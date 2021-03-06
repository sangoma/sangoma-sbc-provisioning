#!/usr/bin/env python2.7

from __future__ import print_function

from collections import OrderedDict
from contextlib import contextmanager
from functools import wraps

from attr import attrs, attrib, Factory, asdict, fields

import re
import os
import sys
import stat
import select
import logging
import subprocess
import json
import shutil

import threading
import Queue

from argparse import ArgumentParser, RawDescriptionHelpFormatter

import safe
import toml

__version__ = 'git-HEAD'

####

logging.basicConfig(
    format='%(asctime)-15s [%(levelname)-8s] %(message)s',
    level=logging.DEBUG,
    filename='results.log'
)

logger = logging.getLogger()

####

PATCH_TABLE = {
    'token-auth-safe-js.tar.gz':  (2,3,2),
    'sip-profile-status.tar.gz':  (2,3,2),
    'skip-api-rest.tar.gz':       (2,3,2),
}

API_KEY_NAME = 'default'

SAFE_JSON = '/usr/local/sng/cli/libs/product_release/safepy_def.json'

COMMON_PATH = os.path.abspath(os.path.dirname(sys.argv[0]))
ORIGIN_PATH = os.path.dirname(COMMON_PATH)
PARENT_PATH = os.path.dirname(ORIGIN_PATH)

INSTALL_PATH = '/provisioning'

UPDATE_BASE = 'updates'

IP_FIELDS_MAP = {
    'static': ('with address {address}/{prefix}', ['interface', 'address', 'proto'], ['address', 'prefix', 'interface', 'proto']),
    'dhcp':   ('for {hostname}', ['interface', 'proto'], ['hostname', 'interface', 'peerdns', 'persistent', 'proto']),
    'slaac':  ('for {hostname}', ['interface', 'proto'], ['hostname', 'interface', 'proto']),
}

PATCHES_BASE = 'patches'
PATCHES_STATE_FMT = '/var/sng/patch.{}'

####

UPDATE_PATH = \
    os.path.join(INSTALL_PATH, UPDATE_BASE) \
        if ORIGIN_PATH == INSTALL_PATH else PARENT_PATH

CONFIG_PATH = \
    INSTALL_PATH if ORIGIN_PATH == INSTALL_PATH else PARENT_PATH


####

logger.debug('install path: {}'.format(INSTALL_PATH))

logger.debug('origin path: {}'.format(ORIGIN_PATH))
logger.debug('parent path: {}'.format(PARENT_PATH))

logger.debug('config path: {}'.format(CONFIG_PATH))
logger.debug('update path: {}'.format(UPDATE_PATH))

####

class Failure(Exception):
    pass

class Exit(Exception):
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

#######

@attrs
class Version(object):
    major = attrib(None)
    minor = attrib(None)
    patch = attrib(None)

    def __cmp__(self, other):
        res = cmp(self.major, other.major)
        if res == 0:
            res = cmp(self.minor, other.minor)
            if res == 0:
                return cmp(self.patch, other.patch)
            else:
                return res
        else:
            return res

    def __str__(self):
        return '{}.{}.{}'.format(self.major, self.minor, self.patch)

    @classmethod
    def from_update_package(cls, pkg):
        fields = pkg.split('-')
        if len(fields) < 2:
            raise Failure('invalid package name: {}'.format(pkg))

        lst = [ int(e) for e in fields[1].split('.') ]
        if len(lst) != 3:
            raise Failure('invalid version for package "{}": {}'.format(pkg, fields[1]))

        logger.debug('building version from update: {!s}'.format(lst))
        return Version(*lst)

    @classmethod
    def from_api_version(cls, data):
        lst = map(int, [data['major_version'], data['minor_version'], data['patch_version']])
        logger.debug('building version from API: {!s}'.format(lst))
        return Version(*lst)


########

def message(*args, **kwargs):
    char = kwargs.get('char', ' ')
    ends = kwargs.get('end', '\n')
    for arg in args:
        print(char * 3, arg, end=ends)

def confirm_message(*args):
    print()

    for arg in args:
        message('WARNING: {}'.format(arg), char='!')

    message('WARNING: CONTINUE? (y/N)', char='!', end=' ')
    proceed = sys.stdin.readline().strip()
    print()

    if proceed not in ['y', 'Y']:
        message('Skipping, operation cancelled...', '')
        return False

    return True

class ProgressStatus(BaseException):
    def __init__(self, status):
        self.status = status

class ProgressControl(object):
    TICKS = [ '|', '/', '-', '\\' ]

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.ticks = 0
        self.lnbrk = False
        self.queue = Queue.Queue()
        self.ticker = threading.Thread(target=self.timer)
        self.ticker.start()

    def tick(self):
        fd = self.kwargs.get('file', sys.stdout)
        if os.isatty(fd if isinstance(fd, int) else fd.fileno()):
            print(ProgressControl.TICKS[self.ticks], end='\r', **self.kwargs)
            self.ticks = (self.ticks + 1) % len(ProgressControl.TICKS)
            fd.flush()

    def message(self, *msgs):
        message(*msgs)
        self.lnbrk = True
        self.tick()

    def finish(self, status, msgs):
        self.message(*msgs)
        raise ProgressStatus(status)

    def timer(self):
        while True:
            try:
                self.queue.get(True, 3)
                return
            except Queue.Empty:
                self.tick()

    def terminate(self):
        self.queue.put(None)
        self.ticker.join()

    def skip(self, *msgs):
        self.finish('SKIPPED', msgs)

    def fail(self, *msgs):
        self.finish('FAILURE', msgs)

    def done(self, *msgs):
        self.finish('SUCCESS', msgs)

@contextmanager
def progress(*args, **kwargs):
    fd = kwargs.get('file', sys.stdout)
    control = ProgressControl(**kwargs)

    try:
        print(' =>', *args, **kwargs)
        fd.flush()
        logger.info(*args)
        yield control
        logger.info('procedure/DONE')

    except ProgressStatus as e:
        logger.info('procedure/{}'.format(e.status))

    except:
        logger.warning('procedure/exception ({!s})'.format(sys.exc_info()[1]).replace('\n', ' - '))
        print(' ')
        control.terminate()
        raise

    if control.lnbrk:
        print(' ')

    control.terminate()

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
        if str(a.get(key)) != str(b.get(key)):
            return False

    return True

def normalize_dict(v):
    res = dict()
    for key, val in v.items():
        res[key.replace('__', '/')] = '' if val is None else val
    return res

def stringify(v):
    if isinstance(v, bool):
        return 'true' if v else 'false'
    return str(v)

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

def assert_get(table, key, errmsg):
    try:
        return table[key]
    except:
        raise Failure(errmsg)

#######

@attrs(init=False)
class ConfigTrunk(object):
    name       = attrib(None)
    realm      = attrib(None)
    acl        = attrib(None)

    def __init__(self, name, data):
        try:
            self.name = name

            if isinstance(data, basestring):
                self.realm = data
                self.acl = None
            else:
                self.realm = data.get('domain')
                self.acl = data.get('acl')

        except KeyError as e:
            raise Failure('option "{}" missing on section "trunks"'.format(e))

@attrs(init=False)
class ConfigIP(object):
    proto      = attrib(None)
    interface  = attrib(None)
    address    = attrib(None)
    prefix     = attrib(None)
    hostname   = attrib(None)
    peerdns    = attrib(None)
    persistent = attrib(None)
    profiles   = attrib(None)

    def decode_multiple(self, result, data):
        if isinstance(data, basestring):
            result.extend(map(lambda x: dict(name=x), filter(lambda x: len(x)!=0, data.split(','))))

        elif isinstance(data, dict):
            result.append(data)

        elif isinstance(data, list):
            for item in data:
                self.decode_multiple(result, item)

        elif data is not None:
            raise Failure('unknown object type for profile data: {}'.format(data.__class__.__name__))

    def __init__(self, ifname, data, emsconfig):
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

            if data.get('ems', False) and emsconfig is not None:
                emsconfig['ip'] = ifname
                emsconfig['macid'] = ifname

            self.profiles = list()
            self.decode_multiple(self.profiles, data.get('profiles', data.get('profile')))

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
class ConfigEMS(object):
    server = attrib(None)
    ip = attrib(None)
    current = attrib(None)

    macid = attrib(None)
    altmacid = attrib(None)
    mediamacid = attrib(None)

    name = attrib(None)
    description = attrib(None)
    venue = attrib(None)
    hdserial = attrib(None)
    ca = attrib(None)

    def deref_system_ip_address(self):
        if self.ip is None or not self.ip.startswith('(') or not self.ip.endswith(')'):
            return False

        ifname = self.ip.strip('()')
        regex_ifname = re.compile('^[0-9]+[:][ ]+{0}[ ]+inet[ ]([0-9.]+)[/][0-9]+ '.format(ifname))

        proc = subprocess.Popen(['/sbin/ip', '-o', 'addr', 'show'], stdout=subprocess.PIPE)

        for line in proc.stdout:
            m = regex_ifname.match(line)
            if m is None:
                continue
            self.ip = m.group(1)
            proc.terminate()
            proc.wait()
            return True

        else:
            raise Failure('interface {} has a dynamic IP address but no address was found on interface - unable to proceed'.format(ifname))

    def deref_ip_address(self, value, ips, name):
        if value is None or not value.startswith('(') or not value.endswith(')'):
            return value
        ifname = value.strip('()')
        logger.debug('using interface {} for {}'.format(ifname, name))
        has_dynamic = False
        for ip in ips:
            if ip.interface == ifname:
                if ip.proto.startswith('static'):
                    value = ip.address
                    logger.debug('{} is now {}'.format(name, value))
                    return value

                if ip.proto.startswith('dhcp'):
                    has_dynamic = True
        else:
            if not has_dynamic:
                raise Failure('unable to find a static IP address on interface {} to use as {}'.format(ifname, name))

            logger.debug('dynamic IP for {}, skipping dereference until EMS action..'.format(ifname))
            return value

    def deref_mac_address(self, value, name):
        if value is None or not value.startswith('(') or not value.endswith(')'):
            logger.debug('using {} as {}'.format(value, name))
            return value

        ifname = value.strip('()')
        logger.debug('using interface {} for {}'.format(ifname, name))
        try:
            with open('/sys/class/net/{}/address'.format(ifname)) as fdes:
                value = fdes.read().strip()
            logger.debug('{} is now {}'.format(name, value))
            return value
        except Exception as e:
            raise Failure('unable to read MAC address for interface {}: {!s}'.format(ifname, e))

    def __init__(self, data, ips):
        try:
            self.server = data['server']
            self.current = data['current']

            self.ip, self.macid = None, None
            self.altmacid, self.mediamacid = None, None

            if 'ip' in data:
                self.ip = self.deref_ip_address(data['ip'], ips, "source IP")

            for (optname, optdesc) in [
                ('macid',      "MAC address"),
                ('altmacid',   "alternate MAC address"),
                ('mediamacid', "media MAC address")
            ]:
                setattr(self, optname, self.deref_mac_address(data.get(optname), optdesc))

            for optname in [ 'name', 'description', 'venue', 'hdserial', 'ca' ]:
                setattr(self, optname, data.get(optname))

        except KeyError as e:
            raise Failure('option "{}" missing on section "ems"'.format(e))


@attrs(init=False)
class ConfigUser(object):
    username = attrib(None)
    userdata = attrib(Factory(dict))

    FIELDS = [ 'name', 'email', 'access', 'sudoer', 'ssh-enable', 'ssh-publickey' ]

    def __init__(self, name, spec):
        self.username = name

        def password_fields(s, data):
            if s is not None:
                data.update({'secure/password': s, 'secure/verify': s})
            return data

        if isinstance(spec, bool):
            self.userdata = dict(access='true' if spec else 'false')

        elif isinstance(spec, basestring):
            self.userdata = password_fields(spec, {'access': True})

        elif isinstance(spec, dict):
            password = spec.pop('password', None)

            unknown = list()
            for key in spec.keys():
                if key in ConfigUser.FIELDS:
                    continue
                unknown.append(key)

            if len(unknown) != 0:
                raise Failure('unknown fields for user "{}": {!s}'.format(name, ', '.join(unknown)))

            self.userdata = password_fields(password, {
                key.replace('-', '/'): stringify(val) \
                    for key, val in spec.items()
                })

        else:
            raise Failure('unknown value for user "{}" configuration: {!s}'.format(name, spec))


@attrs(init=False)
class ConfigNotifier(object):
    configuration = attrib(Factory(dict))

    FIELDS = [ 'check', 'enable', 'smtp-server', 'smtp-port', 'smtp-user', 'smtp-password' ]

    @classmethod
    def normalize(cls, data):
        def keyformat(key):
            return key if key == 'check' else 'email/{}'.format(key.replace('-', '/'))

        return { keyformat(key): stringify(val) for key, val in data.items() }

    def __init__(self, data):
        unknown = list()
        for key in data.keys():
            if key in ConfigNotifier.FIELDS:
                continue
            unknown.append(key)

        if len(unknown) != 0:
            raise Failure('unknown fields for notifier section: {!s}'.format(', '.join(unknown)))

        self.configuration = ConfigNotifier.normalize(data)


@attrs(init=False)
class ConfigOptions(object):
    max_sessions = attrib(None)
    sessions_sec = attrib(None)
    template = attrib(None)

    def __init__(self, data):
        self.max_sessions = data.get('max-sessions')
        self.sessions_sec = data.get('sessions-per-sec')
        self.template = data.get('template')


@attrs(init=False)
class Config(object):
    ems = attrib(None)
    general = attrib(None)
    ips = attrib(Factory(list))
    routes = attrib(Factory(list))
    users = attrib(Factory(list))
    notifier = attrib(None)
    options = attrib(None)
    trunks = attrib(None)

    def __init__(self, data, ifaces):
        ems_data = dict()
        ips, routes = list(), list()
        for cfgname, cfgdata in data.items():
            logger.info('loading section "{}"...'.format(cfgname))
            if cfgname in [ 'global', 'ems', 'users', 'notifier', 'options', 'trunks' ]:
                continue
            if isinstance(cfgdata, list):
                physname = cfgname if cfgname.find('.') == -1 else cfgname[:cfgname.find('.')]
                logger.debug('adding {} to interfaces list...'.format(physname))
                ifaces.add(physname)

                for ipdata in cfgdata:
                    ips.append(ConfigIP(cfgname, ipdata, ems_data))

                for ipdata in cfgdata:
                    for routename, routedata in filter((lambda elm: elm[0].startswith('route.')), ipdata.items()):
                        routes.append(ConfigRoute(cfgname, routename[6:], routedata))
            else:
                raise Failure('configuration error: did you forget the double square brackets on "{}"?'.format(cfgdata))

        ems_section = data.get('ems')
        if ems_section is not None:
            ems_data.update(ems_section)
            self.ems = ConfigEMS(ems_data, ips)
            logger.debug('EMS configuration: {!s}'.format(self.ems))
        else:
            logger.debug('No EMS section provided')
            self.ems = None

        self.options = ConfigOptions(data.get('options', dict()))
        logger.debug('Options configuration: {!s}'.format(self.options))

        try:
            self.general = ConfigNetwork(data['global'])
            logger.debug('General network configuration: {!s}'.format(self.general))
        except KeyError as e:
            raise Failure('missing section {!s} on configuration'.format(e))

        self.users = list()
        for key, val in data.get('users', dict()).items():
            self.users.append(ConfigUser(key, val))
        logger.debug('Users configuration: {!s}'.format(self.users))

        notifier_section = data.get('notifier')
        if notifier_section is not None:
            self.notifier = ConfigNotifier(notifier_section)
            logger.debug('Notifier configuration: {!s}'.format(self.notifier))
        else:
            logger.debug('No notifier section provided')
            self.notifier = None

        trunks_section = data.get('trunks')
        self.trunks = list()
        if trunks_section is not None:
            for trunk_name, trunk_data in trunks_section.items():
                self.trunks.append(ConfigTrunk(trunk_name, trunk_data))
            logger.debug('Trunks configuration: {!s}'.format(self.trunks))
        else:
            logger.debug('No Trunks section provided')

        self.ips = ips
        logger.debug('IP configuration: {!s}'.format(self.ips))
        self.routes = routes
        logger.debug('Route configuration: {!s}'.format(self.routes))

    @classmethod
    def load(cls, ifaces):
        try:
            filename = os.path.join(CONFIG_PATH, 'config.toml')
            logger.debug('opening config {}...'.format(filename))
            with open(filename) as fdes:
                data = toml.load(fdes)
            return Config(data, ifaces)

        except toml.TomlDecodeError as e:
            raise e


def dump_config(configobj):
    def dump_keys(level, name, obj):
        print ('\n', '  '*level, 'Object "{}"'.format(name))
        level = level+1

        mlen = reduce(max, [ len(e.name) for e in fields(obj.__class__) ])
        objects = []

        for key, val in [ (e.name, getattr(obj, e.name, '')) for e in fields(obj.__class__) ]:
            if isinstance(val, basestring) or val is None:
                print('  '*level, '{{:{0}s}}: {{!s}}'.format(mlen).format(key, val if val is not None else '<none>'))
            else:
                objects.append((key, val))

        for key, val in objects:
            if isinstance(val, list):
                print('\n', ' '*level, 'List "{}"'.format(key))
                level += 1
                for num, elm in zip(xrange(len(val)), val):
                    dump_keys(level, '{}[{}]'.format(key, num), elm)

            elif isinstance(val, dict):
                for elmkey, elmval in val.items():
                    dump_keys(level, '{}[{}]'.format(key, elmkey), val)

            else:
                dump_keys(level, key, val)

    dump_keys(0, "config", configobj)

####


actions = OrderedDict()

def register_action(name, auto=False):
    def apply(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            return fn(*args, **kwargs)
        actions[name] = dict(fun=wrapper, auto=auto)
        return wrapper

    return apply

####

def copy_provision_files(opts):
    configpath = os.path.join(INSTALL_PATH, 'config.toml')

    if ORIGIN_PATH == INSTALL_PATH:
        try: os.chmod(configpath, stat.S_IRUSR|stat.S_IWUSR)
        except: pass
        return

    if os.path.exists(INSTALL_PATH):

        proc = subprocess.Popen(['awk', '-F[\'= ]+', '/^__version__[ \t]+=/ { print $2 }',
                                 os.path.join(INSTALL_PATH, 'common/provision.py')],
                                stdout=subprocess.PIPE)

        version = proc.communicate()[0].strip()
        version = version if len(version) != 0 else '<unknown>'

        if proc.returncode != 0:
            logger.warning('awk returned {}'.format(proc.returncode))

        msgs = [ 'Provisioning files are already installed on "{0}" (version {1})!'.format(INSTALL_PATH, version),
                 'Current provisioning is running on "{0}".'.format(ORIGIN_PATH), '',
                 'Re-running from outside "{0}" will overwrite all the installed files and logs currently there.'.format(INSTALL_PATH) ]

        if not confirm_message(*msgs):
            return

    INSTALL_DEST = INSTALL_PATH + '.new'
    INSTALL_PREV = INSTALL_PATH + '.old'

    def rmtree(path):
        logger.debug('removing "{}" recursively'.format(path))
        shutil.rmtree(path)

    def rename(src, dst):
        logger.debug('renaming {} to {}'.format(src, dst))
        os.rename(src, dst)

    def copy(src, dst):
        logger.debug('copying from {} to {}'.format(src, dst))
        shutil.copy(src, dst)

    with progress('Running provisiong installation...') as p:
        try:
            if os.path.exists(INSTALL_DEST):
                rmtree(INSTALL_DEST)

            shutil.copytree(ORIGIN_PATH, INSTALL_DEST)

            for filename in os.listdir(PARENT_PATH):
                copy_config = filename == 'config.toml'
                copy_update = filename.startswith('nsc-') and filename.endswith('.tgz') and opts.copy_update

                if copy_config or copy_update:
                    copy(os.path.join(PARENT_PATH, filename),
                         os.path.join(INSTALL_DEST, UPDATE_BASE if copy_update else '', filename))

            if os.path.exists(INSTALL_PATH):
                rename(INSTALL_PATH, INSTALL_PREV)

            rename(INSTALL_DEST, INSTALL_PATH)

            if os.path.exists(INSTALL_PREV):
                rmtree(INSTALL_PREV)

        except:
            # revert in case something goes wrong
            if os.path.exists(INSTALL_PREV):
                if os.path.exists(INSTALL_PATH):
                    rmtree(INSTALL_PATH)

                rename(INSTALL_PREV, INSTALL_PATH)

            e = sys.exc_info()[1]
            raise Failure('could not install provisioning files: {!s} [{}]'.format(e, e.__class__.__name__))

        p.done('+ Installed provisioning scripts on {}'.format(INSTALL_PATH))

    try: os.chmod(configpath, stat.S_IRUSR|stat.S_IWUSR)
    except: pass


def check_service(opts, state):
    status = state.api.nsc.service.status().get('status_text', 'UNKNOWN')

    if status != 'STOPPED':
        raise Failure('Cannot proceed - NSC is currently "{}". Please run "service nsc stop" before proceeding.'.format(status))


def check_version(opts, state):
    with progress('Checking for update packages..') as p:
        if not os.path.exists(UPDATE_PATH):
            p.skip('No updates folder ({}), skipping.'.format(UPDATE_PATH))

        pkgs = [ e for e in os.listdir(UPDATE_PATH) if e.startswith('nsc') and e.endswith('.tgz') ]
        pkgs = sorted(pkgs, key=lambda s: map(lambda e: int(e) if e.isdigit() else e, s.split('.')), reverse=True)

        if len(pkgs) == 0:
            p.skip('No valid packages on "updates" folder, skipping.')

        state.update_pkg = pkgs[0]
        p.done('+ Found "{}"!'.format(state.update_pkg))


    current_version = None
    require_version = Version(2,3,3)

    with progress('Checking required NSC version') as p:
        current_version = Version.from_api_version(state.api.nsc.version.retrieve())
        state.current_version = current_version

        if state.update_pkg is not None:
            update_version = Version.from_update_package(state.update_pkg)
            if current_version != require_version:
                if update_version == require_version:
                    state.update_do = True
                    p.done('***** Update will be performed ***** (update = {0}, current = {1})'
                           .format(update_version, current_version))
                else:
                    raise Failure('update version is {0}, required is {1} - cannot proceed'\
                                  .format(update_version, require_version))

        if current_version == require_version:
            p.done('+ OK, version supported, no update required (current = {0}, required = {1})'\
                   .format(current_version, require_version))
        else:
            raise Failure('current version is {0}, required is {1} - cannot proceed'\
                          .format(current_version, require_version))

def setup_api_key(opts, state):
    state.api.rest.configuration.update({'enable': 'true', 'api-key': 'true', 'ip-whitelist': 'false'})
    if API_KEY_NAME not in state.api.rest.apikey.keys():
        with progress('Setting up REST API "{}" key...'.format(API_KEY_NAME)) as p:
            state.api.rest.apikey.create(API_KEY_NAME, {'description': 'Provisioning API key'})
            state.changed = True

    try:
        state.api_key = state.api.rest.apikey[API_KEY_NAME]['key']
    except Exception as e:
        raise Failure('could not retrieve or find REST API key: {!s}'.format(e))

    with open('api.key', 'w') as fdes:
        print(state.api_key, file=fdes)


def apply_patches(opts, state):
    if opts.no_patches:
        message('Skipping patches - disabled at command line.', '')
        return

    if state.update_do:
        message('Skipping patches - update will be performed.', '')
        return

    if not os.path.exists(PATCHES_BASE):
        message('Skipping patches - no files found', '')
        return

    def execute(args, p):
        logger.debug('executing {!s}'.format(args))
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in proc.stdout:
            p.message(line.strip())

        status = proc.wait()
        p.tick()

        if status != 0:
            raise Failure('unable to apply patch ({})'.format(
                'rc={!s}'.format(status) if status > 0 else 'sig={!s}'.format(0-status)))

    with progress('Verifying patches to be applied...') as p:
        for filename in os.listdir(PATCHES_BASE):
            version = PATCH_TABLE.get(filename)
            if version is None:
                logger.debug('patch "{}" not found on internal table, skipping...'.format(filename))
                continue

            version = Version(*version)
            logger.debug('comparing versions: {!s} < {!s}'.format(version, state.current_version))
            if version < state.current_version:
                logger.debug('patch "{}" not needed - last applicable version is {}'.format(filename, version))
                continue

            statefile = PATCHES_STATE_FMT.format(filename)
            if os.path.exists(statefile):
                p.message('+ Patch "{}" already applied'.format(filename))
                continue

            execute([ 'tar', '-C', '/', '-zxf', os.path.abspath(os.path.join(PATCHES_BASE, filename)) ], p)

            logger.debug('touching {}'.format(statefile))
            with open(statefile, 'w') as fdes:
                pass

            p.message('+ Successfully applied patch "{}"!'.format(filename))

        p.message('+ Done!')

####

@register_action('update', auto=True)
def updade_action(opts, state):
    """updates system to required version of NSC"""

    if not state.update_do:
        message('No update required - nothing to do', '')
        return

    def execute(args, errmsg, p):
        logger.debug('executing {!s}'.format(args))
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in proc.stdout:
            p.message(line.strip())

        status = proc.wait()
        p.tick()

        if status != 0:
            raise Failure('{} ({})'.format(errmsg,
                'rc={!s}'.format(status) if status > 0 else 'sig={!s}'.format(0-status)))

    with progress('Checking swap space (preparing for update)') as p:
        SWAP_FILE = '/.swap00'

        if not os.path.exists(SWAP_FILE):

            execute(['dd', 'if=/dev/zero', 'of={}'.format(SWAP_FILE), 'bs=4M', 'count=192'],
                    'swap creation failed', p)

            execute(['mkswap', '-v1', SWAP_FILE],
                    'swap format failed', p)

        if os.system('grep -q "^{}" /proc/swaps 2>/dev/null'.format(SWAP_FILE)) != 0:

            execute(['swapon', SWAP_FILE],
                    'swap activation failed', p)

            p.done('+ Swap space activated successfully')

        else:
            p.skip('+ Swap space already activated')

    with progress('Uploading update package (this may take a few minutes)..'):
        filepath = os.path.join(UPDATE_PATH, state.update_pkg)
        state.api.update.package.upload(filepath)

    with progress('Running update procedure (this may take several minutes)..'):
        state.api.update.package.install()

    with progress('Running post-update procedures...') as p:
        execute(['swapoff', SWAP_FILE],
                'swap de-activation failed', p)

        execute(['rm', '-f', SWAP_FILE],
                'swap deletion failed', p)

    with progress('Updating firmware for DSP devices...'):
        state.api.sngms.fwupdate()

    raise Exit('Update successful! The system now REQUIRES a reboot before proceeding with the provisioning.\n\n' + \
               'Please restart your system and re-run the provisioning scripts installed on "{}".'.format(INSTALL_PATH))


@register_action('config', auto=True)
def config_action(opts, state):
    """configures system using parameters contained on config file"""

    if state.config.notifier is not None:
        with progress('Setting parameters for email notifier...') as p:
            state.api.notifier.configuration.update(state.config.notifier.configuration)

    if len(state.config.users) != 0:
        with progress('Configuring users..') as p:
            for user in state.config.users:
                if user.username in state.api.system.user.keys():
                    p.message('+ Setting parameters for user "{}"..'.format(user.username))
                    state.api.system.user[user.username].update(user.userdata)
                else:
                    p.message('+ Creating user "{}"..'.format(user.username))
                    state.api.system.user.create(user.username, user.userdata)
    else:
        print(' ')

    message('Loading network configuration', char='-')

    network_ip_map    = retrieve_map(state.api.network.ip,        'Retrieving IP configuration...')
    network_iface_map = retrieve_map(state.api.network.interface, 'Retrieving interfaces configuration...')
    network_route_map = retrieve_map(state.api.network.route,     'Retrieving route configuration...')
    sip_profile_map   = retrieve_map(state.api.sip.profile,       'Retrieving SIP profile configuration...')
    sip_trunk_map     = retrieve_map(state.api.sip.trunk,         'Retrieving SIP trunk configuration...')

    with progress('Validating interface list...') as p:
        missing_ifaces = [ iface for iface in state.ifaces if network_iface_map.get(iface) is None ]
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

    with progress('Normalizing services and core configuration..') as p:
        for obj in [ state.api.webconfig, state.api.sshd ]:
            obj.configuration['interface'] = 'all'
            p.tick()

        core_config = dict()
        if state.config.options.max_sessions is not None:
            core_config['max-sessions'] = state.config.options.max_sessions
        if state.config.options.sessions_sec is not None:
            core_config['sessions-per-second'] = state.config.options.sessions_sec

        if len(core_config) != 0:
            state.api.core.configuration.update(core_config)
            p.message('+ Applied new core session limits')

    print(' ')
    message('Setting addresses from configuration', char='-')

    ip_obj_rev_map = dict()

    for ip_object in state.config.ips:
        if ip_object.interface.find('.') != -1:
            with progress('Configuring VLAN "{}"..'.format(ip_object.interface)) as p:
                ifname, ifnumber = tuple(ip_object.interface.split('.', 1))
                try:
                    name, _ = next(search_object(network_iface_map,
                        lambda x: x['ifname'] == ifname and x.get('id') == ifnumber,
                        lambda: "not found"))

                    del network_iface_map[name]

                    try: del network_ip_vlans_map[name]
                    except: pass

                    p.skip('+ VLAN interface {0} already present ({1}), skipping creation..'.format(ip_object.interface, name))
                except ObjectNotFound as e:
                    object_name = ip_object.interface.replace('.', '_') # attempt to maintain a stable interface name
                    state.api.network.interface.create(object_name, dict(ifname=ifname, id=ifnumber))
                    state.changed = True

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

                ip_obj_rev_map[ip_object.address] = name

                validate_fields = ['prefix', 'hostname']
                validate_changed = False

                for field in validate_fields:
                    value = getattr(ip_object, field, None)
                    if value is not None and str(value) != str(network_ip_vlans_map[name][field]):
                        p.message('+ Configuring "{0}={1}"'.format(field, value))
                        state.api.network.ip[name][field] = value
                        validate_changed = True

                if not validate_changed:
                    p.message('+ Interface {{interface}} already has a {{proto}} IP {0}'.format(debug_info).format(**asdict(ip_object)))

                del network_ip_map[name]

                try: del network_ip_vlans_map[name]
                except: pass

                p.skip()

            except ObjectNotFound as e:
                postdata = asdict_filter(ip_object, store_fields)
                # DEBUG print("Creating IP {0} with data: {1}".format(object_name, str(postdata)))
                state.api.network.ip.create(object_name, postdata)
                ip_obj_rev_map[ip_object.address] = object_name
                state.changed = True

    with progress('Remapping and applying new profile configurations...') as p:
        for ip_object in state.config.ips:
            if len(ip_object.profiles) == 0:
                continue

            for sip_data in ip_object.profiles:
                sip_name = sip_data['name']
                sip_media = sip_data.get('media')

                sip_obj_name = None
                for profile_name, profile_data in sip_profile_map.items():
                    if profile_data['display-name'] != sip_name:
                        continue

                    sip_obj_name = profile_name
                    break
                else:
                    raise Failure('unable to find SIP profile {} on configuration'.format(sip_name))

                if sip_media is not None:
                    media_data = {
                        'inbound-media-profile': sip_media, 'outbound-media-profile': sip_media
                    }

                    state.api.sip.profile[profile_name].update(media_data)
                    sip_profile_map[profile_name].update(media_data)

                    p.message('+ Configured media profile to "{}" for profile "{}"'.format(sip_media, sip_name))

                sip_address = sip_profile_map[profile_name]['sip-ip']
                sip_port    = sip_profile_map[profile_name]['sip-port']

                if sip_address == sip_obj_name:
                    p.message('+ Skipping profile "{}", already bound to IP "{}"...'.format(sip_name, ip_object.address))
                    continue

                obj_name = assert_get(ip_obj_rev_map, ip_object.address, "could not find IP {} on reverse map".format(ip_object.address))

                # update profile
                state.api.sip.profile[profile_name].update({'sip-ip': obj_name})
                p.message('+ Bound profile "{}" to IP "{}" ({})'.format(sip_name, ip_object.address, obj_name))

                # update mappings
                sip_profile_map[profile_name]['sip-ip'] = obj_name

                sip_ip_port_profiles[sip_address][sip_port].remove(profile_name)
                sip_ip_port_profiles.setdefault(ip_object.address, dict()).setdefault(sip_port, list()).append(profile_name)

    sip_acl_cleared = set()

    with progress('Applying new trunk configurations...') as p:
        for sip_data in state.config.trunks:
            sip_obj_name = None
            for trunk_name, trunk_data in sip_trunk_map.items():
                if trunk_data['display-name'] != sip_data.name:
                    continue

                sip_obj_name = trunk_name
                break
            else:
                raise Failure('unable to find SIP trunk {} on configuration'.format(sip_data.name))

            if sip_data.realm is not None:
                domain_data = {'realm': sip_data.realm}
                state.api.sip.trunk[trunk_name].update(domain_data)
                sip_trunk_map[trunk_name].update(domain_data)
                p.message('+ Configured domain "{}" for trunk "{}"'.format(sip_data.realm, sip_data.name))

            if None not in [ sip_data.acl, sip_data.realm ]:
                if sip_data.acl not in sip_acl_cleared:

                    if sip_data.acl not in state.api.acl.network_list.keys():
                        raise Failure('ACL named "{}" not found in configuration - cannot proceed'.format(sip_data.acl))

                    for node in state.api.acl.network_list[sip_data.acl].node.keys():
                        state.api.acl.network_list[sip_data.acl].node.delete(node)

                    p.message('+ Performed initial sanitization of ACL "{}"'.format(sip_data.acl))
                    sip_acl_cleared.add(sip_data.acl)

                acl_data = { 'policy': 'allow', 'ip-address': sip_data.realm, 'prefix': 32 }

                state.api.acl.network_list[sip_data.acl].node.create('node_{}'.format(random_bytes()), acl_data)
                p.message('+ ACL "{}" configured to allow "{}" for trunk "{}"'.format(sip_data.acl, sip_data.realm, sip_data.name))
                p.message('')

    with progress('Remapping profiles with IPs to be removed...') as p:
        found = False
        for ip_name, ip_data in network_ip_map.items():
            interface, address = ip_data.get('interface'), ip_data.get('address', '')

            if interface.startswith('lo') or interface.startswith('sngdsp'):
                continue
            if address.startswith('127.'):
                continue

            try:
                for profile_name, _ in search_object(sip_profile_map,
                    lambda x: x['sip-ip'] == ip_name,
                    lambda: 'no matching SIP profile not found'):

                    logger.debug('found profile {} matching IP {}'.format(profile_name, ip_name))
                    p.tick()

                    for port_num in range(5060, 5100):
                        logger.debug('checking port {} on loopback IP {}'.format(port_num, loopback_ip))
                        if sip_ip_port_profiles.get(loopback_ip, dict()).get(port_num, 0) == 0:
                            state.api.sip.profile[profile_name].update({'sip-port': port_num, 'sip-ip': loopback_ip })
                            state.changed, found = True, True
                            p.message('+ Remapped IP for profile "{}"'.format(profile_name))
                            break
                        else:
                            raise Failure('unable to allocate port for SIP profile {} on loopback interface'.format(profile_name))

            except ObjectNotFound as e:
                p.message('+ Skipping IP "{}" - {}'.format(ip_name, e))
                found = True

        if not found:
            p.skip('+ No IPs need to be remapped.')

    with progress('Removing previous IP addresses...') as p:
        for ipname, ipdata in network_ip_map.items():
            interface, address = ipdata.get('interface'), ipdata.get('address', '')

            if interface.startswith('lo') or interface.startswith('sngdsp'):
                continue
            if address.startswith('127.'):
                continue

            state.api.network.ip.delete(ipname)
            state.changed = True
            p.tick()

    with progress('Removing previous VLAN interfaces...') as p:
        for ifname, ifdata in network_iface_map.items():
            if ifdata.get('id') not in [ None, '' ]:
                state.api.network.interface.delete(ifname)
                state.changed = True
                p.tick()

    with progress('Adding routes from configuration...') as p:
        def compare_routes_vlan(route_obj):
            def compare_obj_inner(obj):
                obj = dict(obj, interface=network_vlans_map.get(obj['interface'], obj['interface']))
                return compare_keys(obj, asdict(route_object), ['address', 'prefix', 'interface'])

            return compare_obj_inner

        for route_object in state.config.routes:
            try:
                name, _ = next(search_object(network_route_map, compare_routes_vlan(route_object), lambda: "not found"))

                validate_fields = ['gateway']
                validate_changed = False

                for field in validate_fields:
                    value = getattr(route_object, field, None)
                    if value is not None and str(value) != str(network_route_map[name][field]):
                        p.message('+ Setting "{0}={1}" for route {2} (on {3})...'.format(field, value, name, route_object.interface))
                        state.api.network.route[name][field] = value
                        validate_changed = True

                del network_route_map[name]

                if not validate_changed:
                    p.message('+ Route already present ({0}) on interface {1}, skipping creation..'.format(name, route_object.interface))

            except ObjectNotFound as e:
                if network_route_map.get(route_object.name):
                    p.message('+ Removed conflicting route with name ({0}) on interface {1}..'.format(\
                        route_object.name, route_object.interface))
                    state.api.network.route[route_object.name].delete()
                    state.changed = True
                    del network_route_map[route_object.name]

                state.api.network.route.create(route_object.name, asdict(route_object, filter=(lambda a,_: a.name != 'name')))
                p.message('+ Created route {0} on interface {1}'.format(route_object.name, route_object.interface))
                state.changed = True

    with progress('Removing previous routes..') as p:
        for routename in network_route_map.keys():
            state.api.network.route.delete(routename)
            state.changed = True
            p.tick()

    with progress('Configuring new global network settings...') as p:
        global_request = normalize_dict(asdict(state.config.general))
        global_current = state.api.network.configuration.retrieve()

        for key in (set(global_request.keys()) | set(global_current.keys())):
            if key not in global_request or key not in global_current:
                break
            if global_request[key] != global_current[key]:
                break
        else:
            p.skip('+ No change required on settings.')

        state.api.network.configuration.update(global_request)
        state.changed = True

    global_apply = False
    network_apply = state.changed or opts.force_apply

    with progress('Verifying pending changes to apply..') as p:
        global_apply = state.api.nsc.configuration.status().get('modified') == True

        if global_apply:
            p.done('+ Found non-applied configuration changes.')

        if not global_apply and not network_apply:
            p.skip('+ All settings are up to date.')

    with progress('Applying changes (may take a while)..') as p:
        def apirun(*args):
            def getmethod(o):
                return reduce(lambda o, e: getattr(o, e), args, o)

            try:
                getmethod(state.api)()
            except AttributeError:
                p.message('+ Reloading API interface..')

                try:
                    getmethod(safe.api('localhost', port=81))()
                except AttributeError:
                    raise Failure('unable to retrieve method {!s}() from API - cannot proceed'.format('.'.join(args)))

        if global_apply:
            p.message('+ Running full configuration apply..')
            apirun('nsc','configuration','apply')

        elif network_apply:
            p.message('+ Running network configuration apply..')
            apirun('network','apply')

        else:
            p.skip('+ No changes to apply.')

    with progress('Configuration process finished - restarting network..'):
        if (global_apply or network_apply) and not opts.no_restart:
            state.api.network.restart()
        else:
            if opts.no_restart:
                p.skip('+ Restart disabled via command line.')
            else:
                p.skip('+ No changes to apply, not restarting.')

    print(' ')


@register_action('restore', auto=True)
def restore_action(opts, state):
    """restore configuration from a template"""
    template = state.config.options.template if opts.template is None else opts.template

    if template is None:
        message('No template specified - not performing restore', '')
        return

    if not confirm_message('SYSTEM WILL REBOOT AFTER "RESTORE" IS PERFORMED'):
        return

    with progress('Performing restore from template "{0}"...'.format(template)) as p:
        res = state.api.nsc.archive.upload(template)
        p.message('+ Archive {client_name} uploaded as {file_name}'.format(**res))
        state.api.nsc.archive.restore(res['file_name'], {'backup_exclude_opts': ['network', 'license', 'rest_api'] })
        p.tick()

    print('Restore executed successfully.')
    print('')
    print('Press ENTER to continue and reboot the system.')

    sys.stdin.readline()

    state.api.system.shutdown()
    raise Exit('System will now reboot in 5 seconds.')


@register_action('ems')
def ems_action(opts, state):
    """registers system on configured EMS server"""

    ems_data, ems_lines = '', []

    try:
        if state.config.ems is None:
            message('+ No EMS configuration on config file - nothing to do')
            return

        with progress('Executing EMS provisioning script...') as p:

            if state.config.ems.deref_system_ip_address():
                p.message('+ Using dynamic IP address "{}" as source IP reported for EMS server'.format(state.config.ems.ip))

            # check each argument from config, if present on request-args, if not add it
            cmdargs = [os.path.join(COMMON_PATH, 'server-request') ] + opts.args

            def check_append(param, value, name=None):
                arg, argeq = '--{}'.format(param), '--{}='.format(param)
                if value is not None:
                    if arg not in opts.args and \
                       next((False for e in opts.args if e.startswith(argeq)), True):
                        cmdargs.extend([arg, value])
                    else:
                        p.message('Overriding {} (using command line)'.format(\
                            'option "{}"'.format(param) if name is None else name))

            for param in [ e.name for e in fields(state.config.ems.__class__) ]:
                check_append(param, getattr(state.config.ems, param))

            check_append('key', state.api_key, name='SBC REST API key')

            proc = None
            with open('/dev/null') as fdnil:
                logger.debug('executing {!s}'.format(cmdargs))
                proc = subprocess.Popen(cmdargs, stdin=fdnil, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            fdmap = { proc.stdout.fileno(): proc.stdout,
                      proc.stderr.fileno(): proc.stderr }

            with open('requests.log', 'a') as fdes:
                print('----------', file=fdes)

                while len(fdmap) != 0:
                    rfds = select.select(fdmap.keys(), [], [])[0]
                    for rfd in rfds:
                        fileptr = fdmap[rfd]
                        line = fileptr.readline()

                        if line == '':
                            del fdmap[rfd]
                            continue

                        if fileptr == proc.stderr:
                            ems_lines.append(line)
                            print(line, end='', file=fdes)

                        elif fileptr == proc.stdout:
                            ems_data += line

                        p.tick()

                print('(stdout) ', ems_data, file=fdes)

            status = proc.wait()
            errmsg = 'check logs for more information'

            try:
                resp = json.loads(ems_data)

                if resp['status']:
                    p.done('+ {message} (ID = {id})'.format(**resp))

                errmsg = '{message} ({type} error)'.format(**resp)
                p.message('+ {}'.format(errmsg))

            except ValueError as e:
                logger.warning('no json decoded: {!s}'.format(e))

            raise Failure('server-request failed ({1}) - {0}'.format(errmsg,
                'rc={!s}'.format(status) if status > 0 else 'sig={!s}'.format(0-status)))

    except Failure as e:
        if len(ems_lines) != 0:
            print('\nOutput from \"server-request\" procedure:')
            for line in ems_lines:
                print(' '*4, line)
            print()
        raise


@register_action('factory-reset')
def factory_action(opts, state):
    """performs factory reset and reboots"""

    if not confirm_message('SYSTEM CONFIGURATION WILL BE REPLACED BY FACTORY DEFAULTS',
                           'PLEASE MAKE SURE ANY REQUIRED SETTINGS ARE BACKED UP BEFORE PROCEEDING'):
        return

    with progress('Performing factory reset..') as p:
        state.api.system.reset({'type':'factory', 'reset_options': ['network','license']})


def run_action(name, action, opts, state):
    message('Running "{}" step...'.format(name), char='>')
    action(opts, state)

@register_action('auto')
def auto_actions(opts, state):
    """perform defaults actions"""
    for name, data in actions.items():
        if name == 'auto' or not data['auto']:
            logger.debug('skipping action {} - not automatic'.format(name))
            continue
        run_action(name, data['fun'], opts, state)

####

def main():
    epilog = [ 'available actions:', '' ]

    maxlen = reduce(lambda r, e: max(r, len(e)), actions.keys(), 0)

    for name, data in actions.items():
        epilog.append('  {{0:{0}}}{{1}}{{2}}'.format(maxlen+2).format(name,
            data['fun'].__doc__, ' (auto)' if data['auto'] else ''))

    parser = ArgumentParser(
        usage='configure.sh [action] [options] -- [request-args]',
        epilog='\n'.join(epilog),
        formatter_class=RawDescriptionHelpFormatter)

    parser.add_argument('-v', '--version', action='store_true', default=False, help='show version and exit')

    parser.add_argument('-d', '--dump', action='store_true', default=False, help='dump the configuration data and exit')

    parser.add_argument('-n', '--no-patches', action='store_true', default=False, help='do not apply patches on system (even if required)')

    parser.add_argument('-c', '--copy-update', action='store_true', default=False, help='also copy update package to {}'.format(INSTALL_PATH))

    parser.add_argument('-f', '--force-apply', action='store_true', default=False, help='always apply and restart network (even if not changed)')
    parser.add_argument('-R', '--no-restart', action='store_true', default=False, help='do not restart the network after configuration')

    parser.add_argument('-t', '--template', metavar='FILE', help='use FILE as a template backup package to restore from')

    parser.add_argument('action', nargs='?', default='auto', help='action to perform (default is "auto")')
    parser.add_argument('args', metavar='request-args', nargs='*', help='arguments to the "server-request" script')

    opts = parser.parse_args()

    if opts.version:
        print(__version__)
        return 0

    logger.debug('arguments: {!s}'.format(opts))

    try:
        if opts.action not in actions:
            raise Failure('unknown action: {}'.format(opts.action))

        print('Starting provisioning {}...'.format(__version__))
        print()

        logger.debug('')
        logger.debug('starting provisioning {}...'.format(__version__))

        if opts.no_restart:
            print("NOTE: Network will not be restarted, changes will not be fully applied until restart!")
            print()

        if opts.action != 'auto':
            message('Running single step "{}"...'.format(opts.action), char='>')
            print()

        state = type('State', (object,),
            dict(config=None, api=None, ifaces=set(),
                 update_pkg=None, update_do=False,
                 changed=False, api_key=None,
                 current_version=None))

        with progress('Loading configuration file...') as p:
            state.config = Config.load(state.ifaces)

        copy_provision_files(opts)

        with progress("Connecting to REST API...") as p:
            state.api = safe.api('localhost', port=81, specfile=SAFE_JSON if os.path.exists(SAFE_JSON) else None)

        if opts.dump:
            dump_config(state.config)
            print()
            return 0

        check_service(opts, state)
        check_version(opts, state)
        setup_api_key(opts, state)
        apply_patches(opts, state)

        actions[opts.action]['fun'](opts, state)

        print(' ')
        print('All procedures executed successfully!')
        return 0

    except Exit as e:
        print('\n{!s}'.format(e))
        logger.info('exit requested ({!s})'.format(e).replace('\n', ' - '))
        return 0

    except KeyboardInterrupt:
        print('\nInterrupted (Ctrl+C pressed), exiting!')
        logger.info('Ctrl+C pressed, exiting')
        return 0

    except Exception as e:
        try: sys.stdout.flush()
        except: pass

        excstring = str(e)
        if len(excstring) == 0:
            excstring = 'system/internal error'
        excmsg = '{} ({})'.format(excstring, e.__class__.__name__).replace('\n', '; ')

        print('\nERROR: {}'.format(excmsg), file=sys.stderr)
        logger.critical('configuration failed: {}'.format(excmsg))

        with open('failure.log', 'a') as fdes:
            import traceback
            traceback.print_tb(sys.exc_info()[2], file=fdes)
            print('----------', file=fdes)
        return 1

sys.exit(main())
