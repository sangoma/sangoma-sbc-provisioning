#!/usr/bin/env python2.7

from __future__ import print_function

from contextlib import contextmanager

from attr import attrs, attrib, Factory, asdict

import safe
import toml
import sys
import os

import logging

logging.basicConfig(
    format='%(asctime)-15s [%(levelname)-8s] %(message)s',
    level=logging.DEBUG,
    filename='results.log'
)

logger = logging.getLogger()

class Failure(Exception):
    pass

class ObjectNotFound(Exception):
    pass

########

def random_bytes():
    with open('/dev/urandom', 'rb') as fdes:
        data = fdes.read(4)
        try:
            return data.encode('hex')
        except:
            return data.hex()

########

class ProgressStatus(BaseException):
    def __init__(self, status, *args):
        self.status = status
        self.args = args

class ProgressControl(object):
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.msgs = []

    def tick(self):
        fd = self.kwargs.get('file', sys.stdout)
        print('.', end='', **self.kwargs)
        fd.flush()

    def message(self, *msgs):
        self.msgs.extend(list(msgs))
        self.tick()

    def skip(self, *msgs):
        raise ProgressStatus('SKIPPED', *(self.msgs + list(msgs)))

    def done(self, *msgs):
        raise ProgressStatus('SUCCESS', *(self.msgs + list(msgs)))

def message(*args):
    for arg in args:
        print(' '*11, arg)

@contextmanager
def progress(*args, **kwargs):
    fd = kwargs.get('file', sys.stdout)

    try:
        print('(   ...   )', *args, end='', **kwargs)
        logger.info(*args)

        fd.flush()
        yield ProgressControl(**kwargs)

    except ProgressStatus as e:
        print('\r( {} )'.format(e.status))
        if len(e.args) != 0:
            logger.info('procedure succeeded ({!s})'.format(e.args))
            message(*e.args)
            print()
        raise StopIteration()

    except:
        logger.warning('procedure failed ({!s})'.format(sys.exc_info()[1]).replace('\n', ' - '))
        print('\r( FAILURE )')
        raise

    print('\r( SUCCESS )')

#######

def retrieve_map(o, msg):
    with progress(msg) as p:
        result = dict()
        for name in o.keys():
            p.tick()
            data = o[name].retrieve()
            logger.debug('({}) => {!s}'.format(name, data))
            result[name] = data
        return result

def asdict_filter(o, names):
    return asdict(o, filter=lambda a,_: a.name in names)

def compare_keys(a, b, keys):
    for key in keys:
        if a.get(key) != b.get(key):
            return False

    return True

def normalize_dict(v):
    res = dict()
    for key, val in v.items():
        res[key.replace('__', '/')] = '' if val is None else val
    return res

def search_object_name(base, name):
    for objname, objdata in base.items():
        if objname == name:
            yield (objname, objdata)

    raise ObjectNotFound('object named "{}" not found'.format(name))

def search_object(base, matchfun, errorfun):
    for objname, objdata in base.items():
        if matchfun(objdata):
            yield (objname, objdata)

    raise ObjectNotFound(errorfun())

#######

@attrs(init=False)
class ConfigIP(object):
    proto      = attrib(None)
    interface  = attrib(None)
    address    = attrib(None)
    prefix     = attrib(None)
    hostname   = attrib(None)
    peerdns    = attrib(None)
    persistent = attrib(None)

    def __init__(self, ifname, data):
        try:
            self.proto     = data['type'].replace('4', '-4', 1).replace('6', '-6', 1)
            self.interface = ifname

            if self.proto.startswith('static'):
                self.address, self.prefix = tuple(data['address'].split('/', 1))
                self.hostname = None
            else:
                self.address, self.prefix = None, None
                self.hostname = data['hostname']

            if self.proto.startswith('dhcp'):
                self.peerdns    = data['use_auto_dns']
                self.persistent = data['persistant_dhcp']
            else:
                self.peerdns, self.persistent = None, None

        except KeyError as e:
            raise Failure('option "{}" missing on section "{}"'.format(e, ifname))

        except ValueError as e:
            raise Failure('option "address" missing "/<prefix>" on section "{}"'.format(ifname))

@attrs(init=False)
class ConfigRoute(object):
    name      = attrib(None)
    interface = attrib(None)
    address   = attrib(None)
    prefix    = attrib(None)
    gateway   = attrib(None)

    def __init__(self, ifname, route_name, data):
        try:
            self.name = route_name
            self.interface = ifname
            self.address, self.prefix = tuple(data['addr'].split('/', 1))
            self.gateway = data['via']

        except KeyError as e:
            raise Failure('element "{}" missing on option "route.{}", section "{}"'.format(e, route_name, ifname))

        except ValueError as e:
            raise Failure('"/<prefix>" missing on option "route.{}", section "{}"'.format(route_name, ifname))

@attrs(init=False)
class ConfigNetwork(object):
    global__hostname   = attrib(None)
    global__gatewaydev = attrib(None)
    ipv4__default_gw   = attrib(None)
    ipv6__default_gw   = attrib(None)
    dns__1             = attrib(None)
    dns__2             = attrib(None)
    dns__3             = attrib(None)
    dns__4             = attrib(None)

    def __init__(self, data):
        try:
            self.global__hostname   = data['hostname']
            self.global__gatewaydev = data.get('gw_interface', 'auto')
            self.ipv4__default_gw   = data.get('gw_ipv4', None)
            self.ipv6__default_gw   = data.get('gw_ipv6', None)
            self.dns__1 = data.get('dns1', None)
            self.dns__2 = data.get('dns2', None)
            self.dns__3 = data.get('dns3', None)
            self.dns__4 = data.get('dns4', None)

        except KeyError as e:
            raise Failure('option "{}" missing on section "global"'.format(e))

@attrs(init=False)
class Config(object):
    general = attrib(None)
    ips = attrib(Factory(list))
    routes = attrib(Factory(list))

    def __init__(self, data, ifaces):
        self.general = ConfigNetwork(data['global'])
        logger.debug('General network configuration: {!s}'.format(self.general))

        ips, routes = list(), list()
        for cfgname, cfgdata in data.items():
            logger.info('loading section "{}"...'.format(cfgname))
            if cfgname == 'global':
                continue
            if isinstance(cfgdata, list):
                physname = cfgname if cfgname.find('.') == -1 else cfgname[:cfgname.find('.')]
                logger.debug('adding {} to interfaces list...'.format(physname))
                ifaces.add(physname)

                for ipdata in cfgdata:
                    ips.append(ConfigIP(cfgname, ipdata))

                for ipdata in cfgdata:
                    for routename, routedata in filter((lambda elm: elm[0].startswith('route.')), ipdata.items()):
                        routes.append(ConfigRoute(cfgname, routename[6:], routedata))
            else:
                raise Failure('configuration error: did you forget the double square brackets on "{}"?'.format(cfgdata))

        self.ips = ips
        logger.debug('IP configuration: {!s}'.format(self.ips))
        self.routes = routes
        logger.debug('Route configuration: {!s}'.format(self.routes))

    @classmethod
    def load(cls, ifaces):
        try:
            with open('config.toml') as fdes:
                data = toml.load(fdes)
            return Config(data, ifaces)

        except toml.TomlDecodeError as e:
            raise e

####

IP_FIELDS_MAP = {
    'static': ('with address {address}/{prefix}', ['interface', 'address', 'proto'], ['address', 'prefix', 'interface', 'proto']),
    'dhcp':   ('for {hostname}', ['interface', 'proto'], ['hostname', 'interface', 'peerdns', 'persistent', 'proto']),
    'slaac':  ('for {hostname}', ['interface', 'proto'], ['hostname', 'interface', 'proto']),
}

API_KEY_NAME = 'default'

SAFE_JSON = '/usr/local/sng/cli/libs/product_release/safepy_def.json'

VERSION_FMT = '{major_version}.{minor_version}.{patch_version}'

####


try:
    ifaces, config, api = set(), None, None

    with progress('Loading configuration file...') as p:
        config = Config.load(ifaces)

    with progress("Connecting to REST API...") as p:
        api = safe.api('localhost', port=81, specfile=SAFE_JSON if os.path.exists(SAFE_JSON) else None)

    current_version = None
    minimum_version = { 'major_version': 2, 'minor_version': 3, 'patch_version': 0 } # 2 }

    with progress('Checking minimum required NSC version') as p:
        current_version = api.nsc.version.retrieve()

        succeeded = \
           (int(current_version['major_version']) >  int(minimum_version['major_version'])) or \
           (int(current_version['major_version']) == int(minimum_version['major_version']) and \
            int(current_version['minor_version']) >  int(minimum_version['minor_version'])) or \
           (int(current_version['major_version']) == int(minimum_version['major_version']) and \
            int(current_version['minor_version']) == int(minimum_version['minor_version']) and \
            int(current_version['patch_version']) >= int(minimum_version['patch_version']))

        if succeeded:
            p.done('+ Current version = {0}, minimum version = {1}'\
                .format(VERSION_FMT.format(**current_version), VERSION_FMT.format(**minimum_version)))
        else:
            raise Failure('current version is {0}, minimum required is {1} - please run the UPDATE step before proceeding'\
                .format(VERSION_FMT.format(**current_version), VERSION_FMT.format(**minimum_version)))

    network_ip_map    = retrieve_map(api.network.ip,        'Retrieving IP configuration...')
    network_iface_map = retrieve_map(api.network.interface, 'Retrieving interfaces configuration...')
    network_route_map = retrieve_map(api.network.route,     'Retrieving route configuration...')
    sip_profile_map   = retrieve_map(api.sip.profile,       'Retrieving SIP profile configuration...')

    with progress('Validating interface list...') as p:
        missing_ifaces = [ iface for iface in ifaces if network_iface_map.get(iface) is None ]
        if len(missing_ifaces) != 0:
            raise Failure('system does not have interface(s) "{}" - cannot proceed'.format('", "'.join(missing_ifaces)))

    #####

    # map SIP profiles using IP and port
    sip_ip_port_profiles = dict()

    for sip_name, sip_data in sip_profile_map.items():
        sip_ip_port_profiles.setdefault(sip_data['sip-ip'], dict()).setdefault(sip_data['sip-port'], list()).append(sip_name)

    # map all vlans to their real interface name
    network_vlans_map = dict()

    for ifname, ifdata in network_iface_map.items():
        vlan_id = ifdata.get('id')
        if vlan_id is None:
            continue
        network_vlans_map[ifname] = '{}.{}'.format(ifdata['ifname'], vlan_id)

    # normalize interface names on configuration
    network_ip_vlans_map = dict()

    for ipname, ipdata in network_ip_map.items():
        vlan_iface = network_vlans_map.get(ipdata['interface'])
        if vlan_iface is not None:
            ipdata = dict(ipdata, interface=vlan_iface)
        network_ip_vlans_map[ipname] = ipdata


    loopback_ip, _ = next(search_object(network_ip_map,
        lambda x: x['address'] == '127.0.0.1',
        lambda: 'loopback address not found'))

    with progress('Clearing factory configuration...') as p:
        try:
            factory_net_ip, _ = next(search_object(network_ip_map,
                lambda x: x['address'] == '192.168.168.2',
                lambda: 'factory IP address not found'))

            p.tick()

            try:
                for factory_sip_p, _ in search_object(sip_profile_map,
                    lambda x: x['sip-ip'] == factory_net_ip,
                    lambda: 'factory SIP profile not found'):

                    p.tick()

                    for port_num in range(5060, 5100):
                        if sip_ip_port_profiles.get(loopback_ip, dict()).get(port_num, 0) == 0:
                            api.sip.profile[factory_sip_p].update({'sip-port': port_num, 'sip-ip': loopback_ip })
                            p.message('+ Remapped IP for factory profile "{}"'.format(factory_sip_p))
                            break
                        else:
                            raise Failure('unable to allocate port for SIP profile {} on loopback interface'.format(factory_sip_p))

            except ObjectNotFound as e:
                p.message('+ Skipping SIP profiles changes - {}'.format(e))

            api.network.ip.delete(factory_net_ip)
            del network_ip_map[factory_net_ip]
            p.done('+ Removed factory IP address')

        except ObjectNotFound as e:
            p.skip('+ Skipping - {}'.format(e))

    message('Setting addresses from configuration...')

    for ip_object in config.ips:
        if ip_object.interface.find('.') != -1:
            with progress('Configuring VLAN "{}"..'.format(ip_object.interface)) as p:
                ifname, ifnumber = tuple(ip_object.interface.split('.', 1))
                try:
                    name, _ = next(search_object(network_iface_map,
                        lambda x: x['ifname'] == ifname and x.get('id') == ifnumber,
                        lambda: "not found"))
                    del network_iface_map[name]
                    p.skip('+ VLAN interface {0} already present ({1}), skipping creation..'.format(ip_object.interface, name))
                except ObjectNotFound as e:
                    object_name = 'vlan_{}_{}'.format(ip_object.interface, random_bytes())
                    api.network.interface.create(object_name, dict(ifname=ifname, id=ifnumber))

        object_name = '{}_{}'.format(ip_object.interface, random_bytes())
        debug_info, check_fields, store_fields = None, None, None

        for name, data in IP_FIELDS_MAP.items():
            if ip_object.proto.startswith(name):
                debug_info, check_fields, store_fields = data
                break
        else:
            raise Failure('unknown IP type "{}", cannot proceed'.format(ip_object.proto))


        with progress('Creating IP {0} on {{interface}}'.format(debug_info).format(**asdict(ip_object))) as p:
            try:
                name, _ = next(search_object(network_ip_vlans_map,
                    lambda x: compare_keys(x, asdict(ip_object), check_fields),
                    lambda: "not found"))

                validate_fields = ['prefix', 'hostname']
                validate_changed = False

                for field in validate_fields:
                    value = getattr(ip_object, field, None)
                    if value is not None and value != network_ip_vlans_map[name][field]:
                        p.message('+ Configured "{0}={1}"'.format(field, value))
                        api.network.ip[name][field] = value
                        validate_changed = True

                if not validate_changed:
                    p.message('+ Interface {{interface}} already has a {{proto}} IP {0}'.format(debug_info).format(**asdict(ip_object)))

                del network_ip_map[name]
                p.skip()

            except ObjectNotFound as e:
                postdata = asdict_filter(ip_object, store_fields)
                # DEBUG print("Creating IP {0} with data: {1}".format(object_name, str(postdata)))
                api.network.ip.create(object_name, postdata)

    with progress('Removing previous IP addresses...') as p:
        for ipname, ipdata in network_ip_map.items():
            interface, address = ipdata.get('interface'), ipdata.get('address', '')

            if interface.startswith('lo') or interface.startswith('sngdsp'):
                continue
            if address.startswith('127.'):
                continue

            api.network.ip.delete(ipname)
            p.tick()

    with progress('Removing previous VLAN interfaces...') as p:
        for ifname, ifdata in network_iface_map.items():
            if ifdata.get('id') not in [ None, '' ]:
                api.network.interface.delete(ifname)
                p.tick()

    with progress('Adding routes from configuration...') as p:
        def compare_routes_vlan(route_obj):
            def compare_obj_inner(obj):
                obj = dict(obj, interface=network_vlans_map.get(obj['interface'], obj['interface']))
                return compare_keys(obj, asdict(route_object), ['address', 'prefix', 'interface'])

            return compare_obj_inner

        for route_object in config.routes:
            try:
                name, _ = next(search_object(network_route_map, compare_routes_vlan(route_object), lambda: "not found"))

                validate_fields = ['gateway']
                validate_changed = False

                for field in validate_fields:
                    value = getattr(route_object, field, None)
                    if value is not None and value != network_route_map[name][field]:
                        p.message('+ Setting "{0}={1}" for route {2} (on {3})...'.format(field, value, name, route_object.interface))
                        api.network.route[name][field] = value
                        validate_changed = True

                del network_route_map[name]

                if not validate_changed:
                    p.skip('+ Route already present ({0}) on interface {1}, skipping creation..'.format(name, route_object.interface))

            except ObjectNotFound as e:
                if network_route_map.get(route_object.name):
                    p.message('+ Removed conflicting route with name ({0}) on interface {1}..'.format(\
                        route_object.name, route_object.interface))
                    api.network.route[route_object.name].delete()
                    del network_route_map[route_object.name]

                api.network.route.create(route_object.name, asdict(route_object, filter=(lambda a,_: a.name != 'name')))

    with progress('Removing previous routes..') as p:
        for routename in network_route_map.keys():
            api.network.route.delete(routename)
            p.tick()

    global_options = normalize_dict(asdict(config.general))

    with progress('Configuring new global network settings...') as p:
        api.network.configuration.update(global_options)

    with progress('Applying network changes (may take a while)..') as p:
        api.network.apply()

    if API_KEY_NAME not in api.rest.apikey.keys():

        with progress('Setting up REST API "{}" key...'.format(API_KEY_NAME)) as p:
            api.rest.apikey.create(API_KEY_NAME, {'description': 'Provisioning API key'})

    with open('api.key', 'w') as fdes:
        fdes.write(api.rest.apikey[API_KEY_NAME]['key'])

    print('Configuration procedure finished successfully - network restart is REQUIRED for fully applying the new settings.')

except Exception as e:
    print()
    print('ERROR: {}'.format(e).replace('\n', ' - '), file=sys.stderr)
    logger.critical('configuration failed ({!s})'.format(sys.exc_info()[1]).replace('\n', ' - '))

    import traceback
    traceback.print_tb(sys.exc_info()[2], file=open('failure.log', 'a'))
    sys.exit(1)
