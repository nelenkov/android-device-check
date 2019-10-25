# Android device check

A set of scripts to check Android device security configuration.

##  Device runtime configuration check 

The ```check-device-props.py``` scripts check security configuration based on system properties 
and some basic system commands.

### Requirements

Requires ADB connection. Set ```ANDROID_SERIAL``` and/or ```ADB_VENDOR_KEYS``` if more than one device or 
if ADB authentication is required.

### Major checks:

* build type (userdebug, user)
* signing keys
* SELinux availability and mode
* debugging-related properties
* Bluetooth configuration
* USB/ADB configuration
* 3G/telephony availability
* enabled network interfaces
* listening TCP services
* ADB authentication
* SUID binaries
* AIDL services
* disk encryption (FDE/FBE) availability
* dm-verity availability

### Usage

1. Connect to target device via ADB and run the script:

```bash
./check-device-props.py
```

2. Report is output to stdout, redirect as needed. `WARN` messages mark potential configuration issues.

## System APK check

### Overview

A simple script to check security configuration of system APKs for 
Android-based devices. Mainly targeted towards IoT-style devices, 
probably not that useful for phones/tablets. Not meant to be a 
replacement for CTS or other extensive test suites.

Checks are focused on permissions, code signing and component configuration. 
This script does not attempt to perform static analysis of executable code.

### Assumptions

The following assumptions are made:

* device software is based on AOSP
* vendor components all live under the same top-level package
* system APKs from `system/` and `system-priv/` are accessible 
 (either by downloading from live device or from build output)
 
### Major security checks
 
The following security configuration is tested:

* usage of shared user ID, esp. 'android.uid.system'
* whether 3rd-party (non-AOSP, not under top-level package) are running as 'android.uid.system'
* debuggable applications
* whether custom (not defined in AOSP) permissions are signature-protected
* whether protected broadcasts are used
* whether APKs are signed with widely-known keys/certificates ('testkeys')
* optionally prints all permissions and components declared in the APK (detailed mode)

### Requirements

* Androguard >= 3.2.1
* Python 2.7.x (for now)

### Usage

1. Obtain system APKs to test, usually all APKs under `/system/app` and `/system/priv-app`
 * if you can connect to a live device via ADB, you can use the `download-apks.py` helper script:
 ```bash
  $ ./download-apks.py apks/
 ```
2. Run the `check-system-apps.py` script against the APK directory from 1. 
```bash
   ./check-system-apps.py apks/ com.example.package
```
3. Report is output to stdout, redirect as needed.
4. Optionally, specify the `--show-apk-details` flag to show permissions and components declared in each APK.