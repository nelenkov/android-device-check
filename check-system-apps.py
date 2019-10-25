#!/usr/bin/env python

import argparse
import glob
import sys
import os

# needs Androguard 3.2.1
import androguard.core.bytecodes.apk
import androguard.misc

NS_ANDROID_URI = 'http://schemas.android.com/apk/res/android'
NS_ANDROID = '{http://schemas.android.com/apk/res/android}'

ANDROID_SYSTEM_SERVICES = ('android', 'com.android', 'com.android.keychain', 'com.android.systemui',
                           'com.android.settings', 'com.android.providers.settings',
                           'com.android.inputdevices', 'com.android.location.fused')

# media, networkstack, platform, shared, testkey
TEST_CERT_SERIALS = (
    0xF2B98E6123572C4E,
    0xFC6CB0D8A6FDD168,
    0xB3998086D056CFFA,
    0xF2A73396BD38767A,
    0x936EACBE07F201DF
)

CTS_SHIM_PKGS = (
    'com.android.cts.ctsshim',
    'com.android.cts.priv.ctsshim'
)


# from PermissionInfo.java in AOSP
class Permission:
    PROTECTION_NORMAL = 0x0
    PROTECTION_DANGEROUS = 0x1
    PROTECTION_SIGNATURE = 0x2
    PROTECTION_SIGNATURE_OR_SYSTEM = 0x3

    PROTECTION_FLAG_PRIVILEGED = 0x10
    PROTECTION_FLAG_DEVELOPMENT = 0x20
    PROTECTION_FLAG_APPOP = 0x40
    PROTECTION_FLAG_PRE23 = 0x80
    PROTECTION_FLAG_INSTALLER = 0x100
    PROTECTION_FLAG_VERIFIER = 0x200
    PROTECTION_FLAG_PREINSTALLED = 0x400

    PROTECTION_MASK_BASE = 0xf
    PROTECTION_MASK_FLAGS = 0xff0

    PROT_LEVEL_DESC = {
        PROTECTION_NORMAL: 'normal',
        PROTECTION_DANGEROUS: 'dangerous',
        PROTECTION_SIGNATURE: 'signature',
        PROTECTION_SIGNATURE_OR_SYSTEM: 'signatureOrSystem'
    }

    def __init__(self, name, details):
        self.name = name
        self.prot_level = 0
        prot_level_str = details['protectionLevel']
        if prot_level_str is not None and prot_level_str != 'None':
            self.prot_level = int(prot_level_str, 0)
        self.group = details['permissionGroup']
        self.details = details

    @staticmethod
    def prot_level_to_str(prot_level):
        prot_level_strs = []

        prot_level_str = Permission.PROT_LEVEL_DESC.get(prot_level & Permission.PROTECTION_MASK_BASE,
                                                        'invalid')
        prot_level_strs.append(prot_level_str)

        # flags
        if (prot_level & Permission.PROTECTION_FLAG_PRIVILEGED) != 0:
            prot_level_strs.append('|privileged')
        if (prot_level & Permission.PROTECTION_FLAG_DEVELOPMENT) != 0:
            prot_level_strs.append('|development')
        if (prot_level & Permission.PROTECTION_FLAG_APPOP) != 0:
            prot_level_strs.append('|appop')
        if (prot_level & Permission.PROTECTION_FLAG_PRE23) != 0:
            prot_level_strs.append('|pre23')
        if (prot_level & Permission.PROTECTION_FLAG_INSTALLER) != 0:
            prot_level_strs.append('|installer')
        if (prot_level & Permission.PROTECTION_FLAG_VERIFIER) != 0:
            prot_level_strs.append('|verifier')
        if (prot_level & Permission.PROTECTION_FLAG_PREINSTALLED) != 0:
            prot_level_strs.append('|preinstalled')

        return ''.join(prot_level_strs)

    def requires_signature(self):
        return (self.prot_level & Permission.PROTECTION_SIGNATURE) == \
               Permission.PROTECTION_SIGNATURE

    def is_priviliged(self):
        return (self.prot_level & Permission.PROTECTION_FLAG_PRIVILEGED) == \
               Permission.PROTECTION_FLAG_PRIVILEGED

    def print_perm(self, indent=0):
        print '%s %s' % ('' * indent, self.__str__())

    def __str__(self):
        return '%s: [group: %s] [protectionLevel: %s (0x%04X)]' % \
               (self.name, self.group,
                self.prot_level_to_str(self.prot_level),
                self.prot_level)


class Package:

    def __init__(self, package_name, version_name, version_code, filename):
        self.name = package_name
        self.version_code = version_code
        self.version_name = version_name
        self.filename = filename
        self.dang_custom_perms = []
        self.protected_broadcasts = []
        self.is_system = False
        self.is_debuggable = False
        self.is_testkey_signed = False
        self.signer_dns = []
        self.shared_user_id = None
        self._apk = None
        self.flag_reasons = []

    def set_apk(self, apk):
        # Androguard APK
        self._apk = apk

    def check_permissions(self, top_level_pkg):
        dp = self._apk.get_declared_permissions_details()
        if dp:
            for name, details in dp.items():
                perm = Permission(name, details)
                if perm.name.startswith(top_level_pkg) and not perm.requires_signature():
                    self.dang_custom_perms.append(perm)

    def check_prot_broadcasts(self):
        tag = self._apk.get_android_manifest_xml().findall('.//' + 'protected-broadcast')
        if len(tag) > 0:
            for item in tag:
                name = item.get(NS_ANDROID + 'name')
                self.protected_broadcasts.append(name)

    def get_signing_certs(self):
        return self._apk.get_certificates()

    def check_certs(self):
        for c in self.get_signing_certs():
            self.signer_dns.append(c.subject.human_friendly)
            if c.serial_number in TEST_CERT_SERIALS and \
                    self.name not in CTS_SHIM_PKGS:
                self.is_testkey_signed = True

    def should_flag(self, top_level_pkg):
        if self.is_debuggable:
            self.flag_reasons.append('Debuggable package')

        self.check_permissions(top_level_pkg)
        has_dang_perms = len(self.dang_custom_perms) > 0
        if has_dang_perms:
            self.flag_reasons.append('Declares potentially dangerous permissions')

        is_3rd_party_sys_privs = self.is_system and \
                                 self.name not in ANDROID_SYSTEM_SERVICES and \
                                 not self.name.startswith('com.android')
        is_own_pkg = self.name.startswith(top_level_pkg)
        if is_3rd_party_sys_privs and not is_own_pkg:
            self.flag_reasons.append('3rd-party package running with system privileges')

        self.check_certs()
        if self.is_testkey_signed:
            self.flag_reasons.append('Signed with testkey: [%s]' % self.signer_dns)

        self.check_prot_broadcasts()
        if is_own_pkg and not self.is_system and len(self.protected_broadcasts) > 0:
            self.flag_reasons.append('Protected broadcasts in non-system package')

        return len(self.flag_reasons) > 0

    def print_potentially_dangerous_permissions(self):
        for perm in self.dang_custom_perms:
            perm.print_perm()
        print

    def print_apk_summary(self):
        print 'APK file: %s' % self.filename
        print 'Flag reasons: %s' % ', '.join(self.flag_reasons)
        print '=' * 40
        print 'package: %s' % self.name
        print 'versionCode=%s, versionName=%s' % (self.version_code, self.version_name)
        print 'sharedUserId=[%s]' % self.shared_user_id
        print 'debuggable: %s' % self.is_debuggable
        print 'signer cert DNs: %s' % self.signer_dns
        print 'signer cert serial: 0x%X' % self.get_signing_certs()[0].serial_number
        print 'signer cert SHA-256: %s' % self.get_signing_certs()[0].sha256.encode('hex')
        print
        if len(self.dang_custom_perms) > 0:
            print 'Potentially dangerous permissions: '
            self.print_potentially_dangerous_permissions()
        print '-' * 40

    def print_apk_details(self):
        print
        print 'Permissions and components:'
        print '-' * 40
        dp = self._apk.get_declared_permissions_details()
        if dp:
            print 'DECLARED PERMISSIONS:'
            for name, details in dp.items():
                perm = Permission(name, details)
                perm.print_perm()
            print

        rp = self._apk.get_permissions()
        if rp:
            print 'REQUESTED PERMISSIONS:'
            for p in rp:
                print '  [%s]' % p
            print

        main_activity = self._apk.get_main_activity()

        activities = self._apk.get_activities()
        if activities:
            print 'ACTIVITIES: '
            for a in activities:
                filters = self._apk.get_intent_filters('activity', a)
                is_main = a == main_activity
                act = a
                if is_main:
                    act = '** %s **' % a
                print '  %s' % act
                if filters:
                    print '    filters: %s' % filters
            print

        services = self._apk.get_services()
        if services:
            print 'SERVICES: '
            for s in services:
                filters = self._apk.get_intent_filters('service', s)
                print '  %s' % s
                if filters:
                    print '     %s' % filters
            print

        receivers = self._apk.get_receivers()
        if receivers:
            print 'RECEIVERS: '
            for r in receivers:
                filters = self._apk.get_intent_filters("receiver", r)
                print '  %s' % r
                if filters:
                    print '    %s' % filters
        print

        if self._apk.get_providers():
            print 'PROVIDERS: '
            for p in self._apk.get_providers():
                print '  %s' % p
            print

        if len(self.protected_broadcasts) > 0:
            print 'PROTECTED BROADCASTS'
            for pb in self.protected_broadcasts:
                print '  %s' % pb


class Report:
    num_system_apps = None  # type: int

    def __init__(self, top_level_pkg):
        self.top_level_pkg = top_level_pkg
        self.num_system_apps = 0
        self.num_debuggable_apps = 0
        self.issues = {}

    def add_issue(self, package):
        self.issues[package.name] = package

    def print_header(self):
        print 'Found %d system apps, %d debuggable apps, %d potentially problematic APKs' \
              % (self.num_system_apps, self.num_debuggable_apps, len(self.issues))
        print

    def print_summary(self):
        self.print_header()
        for name, pkg in self.issues.items():
            pkg.print_apk_summary()

    def print_details(self):
        self.print_header()
        for name, pkg in self.issues.items():
            pkg.print_apk_summary()
            pkg.print_apk_details()
            print


class ApkChecker:

    def __init__(self):
        pass

    def check_apks(self, apks, top_level_pkg):
        print 'APKs to scan: %d' % len(apks)
        print

        report = Report(top_level_pkg)

        for a in apks:
            apk_path = os.path.abspath(a.strip())
            # print 'path: %s' % apk_path
            apk = androguard.core.bytecodes.apk.APK(apk_path)
            axml = apk.get_android_manifest_xml()

            package_name = apk.package
            shared_user_id = axml.get(NS_ANDROID + 'sharedUserId')
            version_code = axml.get(NS_ANDROID + 'versionCode')
            version_name = axml.get(NS_ANDROID + 'versionName')
            debuggable = self.get_element(axml, 'application', 'debuggable')

            # a, d, dx = androguard.misc.AnalyzeAPK(apk_path)
            # print_apk_summary(apk)

            # if (shared_user_id is not None and 'system' in shared_user_id) or (debuggable is not None):
            apk_filename = os.path.basename(apk_path)
            pkg = Package(package_name, version_code, version_name, apk_filename)
            pkg.set_apk(apk)

            if shared_user_id is not None:
                pkg.shared_user_id = shared_user_id
                if 'android.uid.system' == shared_user_id:
                    report.num_system_apps += 1
                    pkg.is_system = True

            if debuggable is not None and debuggable == 'true':
                pkg.debuggable = True
                report.num_debuggable_apps += 1

            if pkg.should_flag(top_level_pkg):
                report.add_issue(pkg)

        return report

    @staticmethod
    def get_element(xml, tag_name, attribute, **attribute_filter):
        tag = xml.findall('.//' + tag_name)
        if len(tag) == 0:
            return None
        for item in tag:
            skip_this_item = False
            for attr, val in list(attribute_filter.items()):
                attr_val = item.get(NS_ANDROID + attr)
                if attr_val != val:
                    skip_this_item = True
                    break

            if skip_this_item:
                continue

            value = item.get(NS_ANDROID + attribute)

            if value is not None:
                return value
        return None


def main():
    help_msg = 'Checks security configuration of Android device system APKs and outputs report.'
    parser = argparse.ArgumentParser(description=help_msg)
    parser.add_argument('apk_dir', metavar='apk-dir', help='APK directory')
    parser.add_argument('top_level_pkg', metavar='top-level-pkg', help='Top-level package')
    parser.add_argument('--show-apk-details', action='store_true', 
                        required=False, help='Show components in each APK')

    args = parser.parse_args()

    apks = glob.glob('%s/*.apk' % args.apk_dir)

    checker = ApkChecker()
    report = checker.check_apks(apks, args.top_level_pkg)

    if args.show_apk_details:
        report.print_details()
    else:
        report.print_summary()


if __name__ == '__main__':
    main()
