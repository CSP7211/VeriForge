[app]
# Title of the application
title = VeriForge Red

# Package name
package.name = veriforge_red

# Package domain (needed for android/ios packaging)
package.domain = org.veriforge

# Source code directory
source.dir = ..

# Application version
version = 1.0.0

# Application requirements — python modules to include
requirements = python3,kivy,pyjnius,cryptography,pillow,sqlite3

# Orientation — portrait only for mobile experience
orientation = portrait

# OS X / iOS specific (ignored for Android)
osx.python_version = 3
osx.kivy_version = 2.1.0

# Android specific
fullscreen = 0
android.api = 33
android.minapi = 21
android.sdk = 33
android.ndk = 25b
android.archs = armeabi-v7a, arm64-v8a
android.permissions = \
    INTERNET, \
    READ_EXTERNAL_STORAGE, \
    WRITE_EXTERNAL_STORAGE, \
    FOREGROUND_SERVICE, \
    WAKE_LOCK, \
    REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, \
    ACCESS_NETWORK_STATE, \
    RECEIVE_BOOT_COMPLETED, \
    VIBRATE, \
    CAMERA, \
    RECORD_AUDIO, \
    ACCESS_FINE_LOCATION, \
    ACCESS_COARSE_LOCATION, \
    READ_PHONE_STATE, \
    READ_CONTACTS, \
    READ_SMS

android.private_storage = True
android.accept_sdk_license = True

# Android app entry point
android.entrypoint = org.kivy.android.PythonActivity
android.apptheme = @android:style/Theme.NoTitleBar

# Service declaration for background monitoring
services = RedMonitor:veriforge_red/mobile/android_service.py:foreground

# Android resources
android.add_src = 
android.gradle_dependencies = 

# Build settings
android.release_artifact = apk
android.debug_artifact = apk

# Sign release builds (set via env vars in CI)
# android.keystore = 
# android.keystore_password = 
# android.keyalias = 
# android.keyalias_password = 

# Presplash (loading screen)
presplash.filename = %(source.dir)s/veriforge_red/build/presplash.png

# Icon
icon.filename = %(source.dir)s/veriforge_red/build/icon.png

# Allow backup
android.allow_backup = False

# ---------------------------------------------------------------------------
# Buildozer options
# ---------------------------------------------------------------------------
[buildozer]
log_level = 2
warn_on_root = 1

# Build directory
build_dir = ./.buildozer

# Bin output directory
bin_dir = ./bin

# Build cache
build_cache_dir = ./.buildozer_cache
