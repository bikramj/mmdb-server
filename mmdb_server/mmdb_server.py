#!/usr/bin/env python3
#
# mmdb-server is an open source fast API server to lookup IP addresses for their geographic location.
#
# The server is released under the AGPL version 3 or later.
#
# Copyright (C) 2022-2025 Alexandre Dulaunoy

import configparser
import threading
import time
from ipaddress import collapse_addresses, ip_address
import json
from wsgiref.simple_server import make_server

import falcon
import maxminddb

version = "0.6"
config = configparser.ConfigParser()
config.read('etc/server.conf')
mmdb_file = config['global'].get('mmdb_file')
pubsub = config['global'].getboolean('lookup_pubsub')
port = config['global'].getint('port')
country_file = config['global'].get('country_file')

mmdb_files = mmdb_file.split(",")

with open(country_file) as j:
    country_info = json.load(j)

if pubsub:
    import redis

    rdb = redis.Redis(host='127.0.0.1')

mmdbs = []
for mmdb_file in mmdb_files:
    meta = {}
    meta['reader'] = maxminddb.open_database(mmdb_file, maxminddb.MODE_MEMORY)
    meta['description'] = meta['reader'].metadata().description
    meta['build_db'] = time.strftime(
        '%Y-%m-%d %H:%M:%S', time.localtime(meta['reader'].metadata().build_epoch)
    )
    meta['db_source'] = meta['reader'].metadata().database_type
    meta['nb_nodes'] = meta['reader'].metadata().node_count
    mmdbs.append(meta)


def validIPAddress(IP: str) -> bool:
    try:
        type(ip_address(IP))
        return True
    except ValueError:
        return False


def pubLookup(value: str) -> bool:
    if not pubsub:
        return False
    rdb.publish('mmdb-server::lookup', f'{value}')
    return True


def countryLookup(country: str) -> dict:
    if country != 'None' or country is not None or country != 'Unknown':
        if country in country_info:
            return country_info[country]
        else:
            return {}
    else:
        return {}


def _process_lookup(ip):
    """Helper function to process IP lookup and format response."""
    ret = []
    for mmdb in mmdbs:
        georesult = mmdb['reader'].get(ip) or {}  # Ensure dictionary, prevent NoneType errors
        m = mmdb.copy()
        del m['reader']
        georesult['meta'] = m
        georesult['ip'] = ip

        # Determine country code from old or new format
        country_code = None
        if isinstance(georesult.get('country'), dict):
            country_code = georesult['country'].get('iso_code')
        elif isinstance(georesult.get('country'), str):
            country_code = georesult['country']

        georesult['country_info'] = countryLookup(country_code) if country_code else {}
        ret.append(georesult)
    return ret


class GeoLookup:
    def on_get(self, req, resp, value):
        ua = req.get_header('User-Agent')
        ips = req.access_route
        if not validIPAddress(value):
            resp.status = falcon.HTTP_422
            resp.media = "IPv4 or IPv6 address is in an incorrect format. Dotted decimal for IPv4 or textual representation for IPv6 are required."
            return
        pubLookup(value=f'{value} via {ips} using {ua}')
        resp.media = _process_lookup(value)


class MyGeoLookup:
    def on_get(self, req, resp):
        ips = req.access_route
        resp.media = _process_lookup(ips[0])

class MyRawLookup:
    def on_get(self, req, resp):
        ips = req.access_route
        resp.text = ips[0]
        return
    def on_head(self, req, resp):
        ips = req.access_route
        resp.append_header('X-IP', ips[0])

class CIDRExport:
    """Shared logic for the /cidr endpoints: an index of the loaded databases
    (country -> networks, ASN -> networks) served as collapsed CIDR lists.

    The index is built once in a daemon thread at startup so the hot lookup
    endpoints are never blocked; /cidr requests answer 503 until it is ready.
    The daily database refresh restarts the service, which rebuilds the index.
    """

    index = {'ready': False, 'country': {}, 'asn': {}, 'source': ''}
    collapsed = {}

    @classmethod
    def build_index(cls):
        country = {}
        asn = {}
        source = ''
        for mmdb in mmdbs:
            try:
                for network, record in mmdb['reader']:
                    if not isinstance(record, dict):
                        continue
                    cc = record.get('country')
                    if isinstance(cc, dict):  # MaxMind GeoIP2 format
                        cc = cc.get('iso_code')
                    if cc:
                        country.setdefault(cc, []).append(network)
                    a = record.get('asn')
                    if a is None:  # MaxMind ASN database field name
                        a = record.get('autonomous_system_number')
                    if a is not None:
                        a = str(a)
                        if not a.startswith('AS'):
                            a = 'AS' + a
                        asn.setdefault(a, []).append(network)
            except Exception:
                continue
            if country:
                # first database with country data wins (list ipinfo first)
                source = f"{mmdb['db_source']} (build {mmdb['build_db']})"
                break
        cls.index['country'] = country
        cls.index['asn'] = asn
        cls.index['source'] = source
        cls.index['ready'] = True

    @classmethod
    def cidrs_for(cls, kind, key):
        cached = cls.collapsed.get((kind, key))
        if cached is not None:
            return cached
        networks = cls.index[kind].get(key)
        if not networks:
            return None
        v4 = collapse_addresses(n for n in networks if n.version == 4)
        v6 = collapse_addresses(n for n in networks if n.version == 6)
        cidrs = [str(n) for n in v4] + [str(n) for n in v6]
        cls.collapsed[(kind, key)] = cidrs
        return cidrs

    def respond(self, req, resp, kind, key, label):
        if not self.index['ready']:
            resp.status = falcon.HTTP_503
            resp.append_header('Retry-After', '30')
            resp.media = 'CIDR index is still building, retry shortly.'
            return
        cidrs = self.cidrs_for(kind, key)
        if cidrs is None:
            resp.status = falcon.HTTP_404
            resp.media = f'No networks found for {label}.'
            return
        fmt = req.get_param('format', default='plain').lower()
        header = f"# {label} - {len(cidrs)} ranges - {self.index['source']}"
        if fmt == 'json':
            resp.media = {
                'query': label,
                'count': len(cidrs),
                'source': self.index['source'],
                'cidrs': cidrs,
            }
        elif fmt == 'apache':
            resp.content_type = falcon.MEDIA_TEXT
            resp.text = header + '\n' + '\n'.join(f'Require ip {c}' for c in cidrs) + '\n'
        else:
            # plain: one CIDR per line — directly usable as an HAProxy acl
            # file (src -f <file>); '#' comment lines are allowed there.
            resp.content_type = falcon.MEDIA_TEXT
            resp.text = header + '\n' + '\n'.join(cidrs) + '\n'


class CountryCIDR(CIDRExport):
    def on_get(self, req, resp, country):
        cc = country.strip().upper()
        if len(cc) != 2 or not cc.isalpha():
            resp.status = falcon.HTTP_422
            resp.media = 'Country must be a two-letter ISO code, e.g. CA.'
            return
        self.respond(req, resp, 'country', cc, f'country {cc}')


class ASNCIDR(CIDRExport):
    def on_get(self, req, resp, asn):
        a = asn.strip().upper()
        if a.startswith('AS'):
            a = a[2:]
        if not a.isdigit():
            resp.status = falcon.HTTP_422
            resp.media = 'ASN must be numeric, e.g. AS577 or 577.'
            return
        self.respond(req, resp, 'asn', 'AS' + a, f'AS{a}')


app = falcon.App()

app.add_route('/geolookup/{value}', GeoLookup())
app.add_route('/', MyGeoLookup())
app.add_route('/raw', MyRawLookup())
app.add_route('/cidr/country/{country}', CountryCIDR())
app.add_route('/cidr/asn/{asn}', ASNCIDR())

threading.Thread(target=CIDRExport.build_index, daemon=True).start()


def main():
    with make_server('', port, app) as httpd:
        print(f'Serving on port {port}...')
        httpd.serve_forever()


if __name__ == '__main__':
    main()