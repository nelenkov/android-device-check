#!/usr/bin/env python

import argparse
import os
import re
import sys
import subprocess

APK_PATH_RE = re.compile(r'^\S+:(\S+)=.*')

def collect_apk_paths(all_apks):
    apks = []
    cmd = 'adb shell pm list packages -f'
    result = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    # filter system, system-priv?
    for line in result.stdout:
        m = APK_PATH_RE.match(line)
        if m is not None:
            path = m.group(1)
            if all_apks:
                apks.append(path)
            else:
                if '/system/app/' in path or '/system/priv-app/' in path:
                    apks.append(path)

    return apks


def download_apks(apk_paths, download_path):
    if not os.path.exists(download_path):
        os.makedirs(download_path)

    for apk in apk_paths:
        print 'Getting %s...' % apk
        cmd = 'adb pull %s %s/%s' % (apk, download_path, os.path.basename(apk))
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result = p.communicate()
        if p.returncode != 0:
            print 'Error: rc=%d, msg=%s' % (p.returncode, result[1])


if __name__ == '__main__':
    help_msg = 'Downloads APKs from device over ADB. Defaults to system APKs only.'
    parser = argparse.ArgumentParser(description=help_msg)
    parser.add_argument('download_dir', metavar='apk-dir', help='APK directory')
    parser.add_argument('--all-apks', action='store_true',
                        required=False, help='Download all APKs (system only unless specified)')

    args = parser.parse_args()

    apk_paths = collect_apk_paths(args.all_apks)
    download_apks(apk_paths, args.download_dir)

