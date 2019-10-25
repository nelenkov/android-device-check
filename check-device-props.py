#!/usr/bin/env python

import os
import re
import socket
import struct
import subprocess

SYS_PROP_RE = re.compile(r'^\[(\S+)\]: \[(\S+)\].*')
NETSTAT_RE = re.compile(r'^\S+\s+\S+\s+\S+\s+(\S+)\s+.*')

NET_IF_RE = re.compile(r'^(\S+)\s+Link encap:.*')
IP_ADDR_RE = re.compile(r'^\s+inet addr:(\S+).*')

SERVICE_RE = re.compile(r'\d+\s+(\S+): \[(\S+)\]')

ADB_DEVICES_RE = re.compile(r'^(\S+)\s+(\S+)$')

PRODUCT_PROP = 'ro.product'
FINGERPRINT_PROP = 'ro.build.fingerprint'
FLAVOR_PROP = 'ro.build.flavor'
BUILD_PROP = 'ro.build.product'
TAGS_PROP = 'ro.build.tags'
TYPE_PROP = 'ro.build.type'
FACTORY_MODE_PROP = 'ro.boot.factory_mode'
SECURE_PROP = 'ro.secure'
DEBUGGABLE_PROP = 'ro.debuggable'
QCOM_BT_PROP = 'ro.qualcomm.bluetooth'
USB_CONFIG_PROP = 'sys.usb.config'
USB_STATE_PROP = 'sys.usb.state'
GSM_NW_PROP = 'gsm.network.type'
CRYPTO_STATE_PROP = 'ro.crypto.state'
CRYPTO_PROPS = 'ro.crypto.'
VERITY_MODE_PROP = 'ro.boot.veritymode'

TYPE_USERDEBUG = 'userdebug'
TYPE_ENG = 'eng'
TEST_KEYS = 'test-keys'

SELINUX_ENFORCING = 'Enforcing'
VERITY_ENFORCING = 'enforcing'

ADB_UNAUTHORIZED = 'unauthorized'
ADB_AUTHORIZED = 'device'
ADB_VENDOR_KEYS_ENV = 'ADB_VENDOR_KEYS'

PRIVATE_NETS = (
    ['127.0.0.0', '255.0.0.0'],
    ['192.168.0.0', '255.255.0.0'],
    ['172.16.0.0', '255.240.0.0'],
    ['10.0.0.0', '255.0.0.0']
)

# core services that don't have 'android' in the interface name only
ANDROID_CORE_SERVICES = ('drm.drmManager', 'mount')


def warn(msg, extra=None):
    log('WARN', msg, extra)


def info(msg, extra=None):
    log('INFO', msg, extra)


def err(msg, extra=None):
    log('ERR', msg, extra)


def log(sev, msg, extra):
    print '%s: %s' % (sev, msg)
    if extra is not None:
        print '\t%s' % str(extra)


def print_hr():
    print '-' * 70


def test_name(name):
    print '%s %s %s' % ('*' * 10, name, '*' * 10)


def check_product(sys_props):
    product_props = {}
    for k in sys_props.keys():
        if PRODUCT_PROP in k:
            product_props[k] = sys_props[k]

    info('Product info:')
    for k in product_props.keys():
        info('\t%s=%s' % (k, product_props[k]))


def check_build(sys_props):
    test_name('Build props check')

    build_type = sys_props[TYPE_PROP]
    build_flavor = sys_props[FLAVOR_PROP]

    if TYPE_USERDEBUG in build_type or TYPE_USERDEBUG in build_flavor:
        warn('userdebug build', (build_type, build_flavor))

    if TYPE_ENG in build_type or TYPE_ENG in build_flavor:
        warn('eng build', (build_type, build_flavor))


def check_signing_keys(sys_props):
    test_name('Signing keys check')

    fingerprint = sys_props[FINGERPRINT_PROP]
    build_tags = sys_props[TAGS_PROP]

    if TEST_KEYS in fingerprint or TEST_KEYS in build_tags:
        warn('build is signed with test-keys', (fingerprint, build_tags))


def check_factory_mode(sys_props):
    test_name('Factory mode check')

    if FACTORY_MODE_PROP in sys_props.keys():
        factory_mode = sys_props[FACTORY_MODE_PROP]
        if factory_mode == "1":
            warn("factory mode is on")


def exec_command(cmd, ignore_err=False):
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    res = p.communicate()
    if p.returncode != 0 and not ignore_err:
        err('Error executing [%s]: rc=%d, msg=%s' % (cmd, p.returncode, res[1]))
        if not ignore_err:
            return []

    return res[0].splitlines()


def check_selinux():
    test_name('SELinux check')

    cmd = 'adb shell getenforce'
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    res = p.communicate()
    if p.returncode != 0:
        print 'Error: rc=%d, msg=%s' % (p.returncode, res[1])

    selinux_mode = res[0].splitlines()[0].strip()
    if selinux_mode != SELINUX_ENFORCING:
        warn('SELinux not in enforcing mode', selinux_mode)


def check_debug(sys_props):
    test_name('Debuggable apps check')

    secure = sys_props[SECURE_PROP]
    debuggable = sys_props[DEBUGGABLE_PROP]

    if secure == '0':
        warn('Build is not secure', '%s=%s' % (SECURE_PROP, secure))

    if debuggable == '1':
        warn('Build is debuggable', '%s=%s' % (DEBUGGABLE_PROP, debuggable))


def check_bt(sys_props):
    test_name('Bluetooth modes check')

    bt_props = {}
    for k in sys_props.keys():
        if QCOM_BT_PROP in k:
            val = sys_props[k]
            if val == 'true':
                bt_props[k] = val

    if len(bt_props.keys()) > 0:
        warn('Bluetooth profiles are on by default', bt_props)


def check_usb(sys_props):
    test_name('USB modes check')

    usb_config = sys_props[USB_CONFIG_PROP].split(',')
    usb_state = sys_props[USB_STATE_PROP].split(',')

    if len(usb_config) > 1 and usb_config[0] != 'adb':
        warn('Multiple USB modes configured.', '%s=%s' % (USB_CONFIG_PROP, usb_config))

    if len(usb_state) > 1 and usb_state[0] != 'adb':
        warn('Multiple USB modes enabled.', '%s=%s' % (USB_STATE_PROP, usb_config))


def check_3g(sys_props):
    test_name('3G/LTE check')

    gsm_props = {}
    if GSM_NW_PROP in sys_props.keys():
        gsm_nw = sys_props[GSM_NW_PROP]
        if gsm_nw != '':
            for k in sys_props.keys():
                if 'gsm.' in k:
                    gsm_props[k] = sys_props[k]

    if gsm_props:
        warn('3G/LET may be enabled', gsm_props)


def is_private_ip(ipaddr):
    f = struct.unpack('!I', socket.inet_pton(socket.AF_INET, ipaddr))[0]
    for net in PRIVATE_NETS:
        mask = struct.unpack('!I', socket.inet_aton(net[1]))[0]
        p = struct.unpack('!I', socket.inet_aton(net[0]))[0]
        if (f & mask) == p:
            return True

    return False


def check_net_ifs():
    test_name('Network interface check')

    cmd = 'adb shell ifconfig'
    lines = exec_command(cmd)

    net_ifs = {}

    current_net_if = None
    for line in lines:
        m = NET_IF_RE.match(line)
        if m is not None:
            current_net_if = m.group(1)
        m = IP_ADDR_RE.match(line)
        if m is not None:
            ip_addr = m.group(1)
            if current_net_if is not None:
                net_ifs[current_net_if] = ip_addr

    for net_if in net_ifs.keys():
        ip = net_ifs[net_if]
        if not is_private_ip(ip):
            warn('Found non-private IP address.', '%s: %s' % (net_if, ip))
        info('Found network interface:', '%s: %s' % (net_if, ip))


def check_port_listen():
    test_name('Listening TCP services check')

    services = []
    cmd = 'adb shell "netstat -na|grep -i tcp|grep -i listen"'
    lines = exec_command(cmd, False)
    for line in lines:
        m = NETSTAT_RE.match(line)
        if m is not None:
            service = m.group(1)
            if '127.0.0.1' not in service:
                services.append(service)

    if services:
        warn('Non local TCP servers found', services)


def check_adb_auth():
    test_name('ADB authentication check')

    if ADB_VENDOR_KEYS_ENV not in os.environ.keys():
        info('no ADB vendor key set')
        return

    vendor_keys = os.environ[ADB_VENDOR_KEYS_ENV]
    if vendor_keys:
        info('%s is set to %s, unsetting' % (ADB_VENDOR_KEYS_ENV, vendor_keys))
        os.environ[ADB_VENDOR_KEYS_ENV] = ''

    try:
        cmd = 'adb kill-server'
        exec_command(cmd, True)
        cmd = 'adb devices'
        lines = exec_command(cmd)
        for line in lines:
            m = ADB_DEVICES_RE.match(line)
            if m is not None:
                device = m.group(1)
                state = m.group(2)
                if state != ADB_UNAUTHORIZED:
                    warn('Device %s does not require ADB private key authentication' % device)
    finally:
        # try to restore env
        info('Restoring %s to %s. Reset manually if not successful.' % (ADB_VENDOR_KEYS_ENV, vendor_keys))
        os.environ[ADB_VENDOR_KEYS_ENV] = vendor_keys
        cmd = 'adb kill-server'
        exec_command(cmd, True)


def check_suid():
    test_name('SUID binaries check')

    cmd = 'adb shell "find /system -xdev \( -perm -4000 -o -perm -2000 \)"'
    lines = exec_command(cmd, True)
    suid_files = []
    for line in lines:
        if 'Permission denied' not in line:
            suid_files.append(line.strip())

    if len(suid_files) > 0:
        warn("SUID binaries found", suid_files)


def check_services():
    test_name('AIDL services check')

    cmd = 'adb shell service list'
    lines = exec_command(cmd)

    services = {}
    for line in lines:
        m = SERVICE_RE.match(line)
        if m is not None:
            services[m.group(1).strip()] = m.group(2).strip()

    custom_services = {}
    for s in services.keys():
        iface = services[s]
        if iface and 'android' not in iface:
            custom_services[s] = iface

    if custom_services:
        warn('Found custom Android services')
        for cs in custom_services.keys():
            if cs not in ANDROID_CORE_SERVICES:
                warn('\t%s: [%s]' % (cs, custom_services[cs]))


def check_fde(sys_props):
    test_name('Disk encryption (FDE) check')

    crypto_props = {}
    if CRYPTO_STATE_PROP in sys_props.keys():
        state = sys_props[CRYPTO_STATE_PROP]
        for k in sys_props.keys():
            if CRYPTO_PROPS in k:
                crypto_props[k] = sys_props[k]
        if state == 'encrypted':
            info('userdata is encrypted', crypto_props)
        else:
            warn('userdata is NOT encrypted', crypto_props)
    else:
        warn('userdata is NOT encrypted')


def check_verity(sys_props):
    test_name('dm-verity check')

    if VERITY_MODE_PROP not in sys_props:
        warn('dm-verity is NOT enabled')
    else:
        verity_mode = sys_props[VERITY_MODE_PROP]
        if verity_mode == VERITY_ENFORCING:
            info('dm-verity is enabled and enforcing')
        else:
            warn('dm-verity is enabled but NOT enforcing', '%s=%s' % (VERITY_MODE_PROP, verity_mode))


def collect_sys_props():
    cmd = 'adb shell getprop'
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    res = p.communicate()
    if p.returncode != 0:
        print 'Error: rc=%d, msg=%s' % (p.returncode, res[1])

    props = {}
    lines = res[0].splitlines()
    for line in lines:
        m = SYS_PROP_RE.match(line)
        if m is not None:
            props[m.group(1).strip()] = m.group(2).strip()

    return props


def main():
    sys_props = collect_sys_props()

    test_name('Starting device OS configuration check')
    check_product(sys_props)
    print_hr()
    check_build(sys_props)
    print_hr()
    check_signing_keys(sys_props)
    print_hr()
    check_factory_mode(sys_props)
    print_hr()
    check_debug(sys_props)
    print_hr()
    check_bt(sys_props)
    print_hr()
    check_usb(sys_props)
    print_hr()
    check_3g(sys_props)
    print_hr()
    check_fde(sys_props)
    print_hr()
    check_verity(sys_props)
    print_hr()

    check_selinux()
    print_hr()
    check_suid()
    print_hr()
    check_port_listen()
    print_hr()
    check_net_ifs()
    print_hr()
    check_services()
    print_hr()
    check_adb_auth()
    print_hr()
    print


if __name__ == '__main__':
    main()
