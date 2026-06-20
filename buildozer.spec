[app]

# ---------------------------------------------------------------------------
# VeriForge Red — Buildozer Specification
# ---------------------------------------------------------------------------
# Build command:
#   buildozer android debug deploy run
#   buildozer android release
#   buildozer android clean
#
# Requirements (install first):
#   pip install buildozer cython
#

# App identity
# (str) Title of your application
title = VeriForgeRed

# (str) Package name — must be a valid Java package identifier
package.name = VeriForgeRed

# (str) Package domain (needed for android/ios packaging)
package.domain = com.veriforge

# (str) Source code where the main.py lives
source.dir = .

# (list) Source files to include (let empty to include all the files)
source.include_exts = py,png,jpg,kv,atlas

# (list) List of inclusions using pattern matching
source.include_patterns = assets/*,images/*.png

# (list) Source files to exclude (let empty to not exclude anything)
source.exclude_exts = spec,log,gitignore

# (list) List of exclusions using pattern matching
source.exclude_patterns = __pycache__/*,*.pyc,.git/*,*.egg-info/*

# (str) Application versioning (method 1 — manual)
version = 1.0.0

# (str) Application versioning (method 2 — file)
# version.filename = %(source.dir)s/version.txt

# (list) Application requirements
# python3 is always required.
# kivy       — UI framework
# cryptography — VeriForge SDK dependency
# jinja2     — VeriForge SDK dependency
# openssl    — Required by cryptography
# pyjnius    — Android/Java bridge (auto-included with android)
requirements = python3,kivy==2.2.1,cryptography,jinja2,openssl,requests,pyjnius,android

# (str) Custom source folders for requirements
# Sets custom source for any requirements with recipes
# requirements.source.kivy = ../../kivy

# (list) Garden requirements
# See: https://kivy.org/doc/stable/api-kivy.garden.html
#garden_requirements =

# (str) Presplash of the application
# Loading screen shown while the app initializes
#presplash.filename = %(source.dir)s/assets/presplash.png

# (str) Icon of the application
# Icon must be at least 512x512 for Play Store
#icon.filename = %(source.dir)s/assets/icon.png

# (str) Supported orientation (one of landscape, sensorLandscape,
#       portrait or all)
orientation = portrait

# (list) List of services to declare
# VeriForge background scan service — runs persistent scan in background
services = VeriForgeScan:veriforge-service.py

# (str) Android API to use
#android.api = 33

# (int) Minimum API required. 21 = Android 5.0 (Lollipop)
android.minapi = 21

# (int) Android API to target (latest stable recommended)
android.sdk = 33

# (str) Android NDK version to use
#android.ndk = 25b

# (int) Android NDK API to use (optional)
#android.ndk_api = 21

# (bool) Use --private data storage (True) or --dir public storage (False)
#android.private_storage = True

# (str) Android app entry point (default is ok for Kivy apps)
#android.entrypoint = org.kivy.android.PythonActivity

# (list) Pattern to whitelist for the whole project
#android.whitelist =

# (list) Permissions — REQUIRED for VeriForge to function
# INTERNET              — Dashboard HTTP server, updates
# READ_EXTERNAL_STORAGE — Scan files on device
# WRITE_EXTERNAL_STORAGE — Save scan reports
# FOREGROUND_SERVICE    — Background scanning
# FOREGROUND_SERVICE_DATA_SYNC — Android 14+ foreground service type
# POST_NOTIFICATIONS    — Android 13+ notification permission
#android.permissions = INTERNET,READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE,FOREGROUND_SERVICE,WAKE_LOCK
android.permissions = INTERNET,READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE,FOREGROUND_SERVICE,WAKE_LOCK,POST_NOTIFICATIONS,FOREGROUND_SERVICE_DATA_SYNC,ACCESS_NETWORK_STATE

# (list) Features (adds uses-feature in AndroidManifest.xml)
#android.features = android.hardware.touchscreen

# (str) Android manifest.xml template file
#android.manifest_template = %(source.dir)s/AndroidManifest.tmpl.xml

# (str) Custom AndroidManifest.xml (overrides template)
#android.manifest_xml = %(source.dir)s/AndroidManifest.xml

# (str) Android entry point, default is ok for Kivy-based app
#android.entrypoint = org.kivy.android.PythonActivity

# (list) List of Java .jar files to add to the libs so that pyjnius
# can access their classes. Don't add jars that you do not need.
#android.add_jars = foo.jar,bar.jar,path/to/more/*.jar

# (list) List of Java files to add (so that pyjnius can access their classes)
#android.add_src =

# (list) Android AAR archives to add
#android.add_aars =

# (list) Gradle dependencies to add (currently works only with sdl2_gradle
# bootstrap)
#android.gradle_dependencies =

# (bool) Enable Android auto backup in AndroidManifest.xml
#android.allow_backup = True

# (str) XML file for auto backup rules
#android.backup_rules =

# (str) If you need to insert variables into your AndroidManifest.xml,
# declare them here with the format: name = value
#android.manifest_placeholders = :myVariable=%(sources)s

# (bool) Skip byte compile for .py files in the lib directory
#android.no-byte-compile-python = False

# (str) The format used to package the app for release mode (aab or apk or aar).
# android.release_artifact = aab

# (str) The format used to package the app for debug mode (apk or aar).
# android.debug_artifact = apk

# ---------------------------------------------------------------------------
# Android Archs
# ---------------------------------------------------------------------------
# (list) The Android archs to build for. Choices: armeabi-v7a, arm64-v8a,
# x86, x86_64. Default is unset (all archs).
# In most cases, arm64-v8a is sufficient for modern Android devices.
android.archs = arm64-v8a, armeabi-v7a

# (int) overrides the feature version code used when using android.archs
# android.numeric_version = 10000

# ---------------------------------------------------------------------------
# Icon / Splash Configuration
# ---------------------------------------------------------------------------
# Icon resources for different densities
#android.icon.ldpi  = %(source.dir)s/assets/icon-36.png
#android.icon.mdpi  = %(source.dir)s/assets/icon-48.png
#android.icon.hdpi  = %(source.dir)s/assets/icon-72.png
#android.icon.xhdpi = %(source.dir)s/assets/icon-96.png

# Presplash (loading screen) resources
#android.presplash.ldpi  = %(source.dir)s/assets/presplash-320.png
#android.presplash.mdpi  = %(source.dir)s/assets/presplash-480.png
#android.presplash.hdpi  = %(source.dir)s/assets/presplash-720.png
#android.presplash.xhdpi = %(source.dir)s/assets/presplash-960.png

# (string) Presplash background color (default: #FFFFFF)
#android.presplash_color = #0A0A0F

# ---------------------------------------------------------------------------
# Window / Display
# ---------------------------------------------------------------------------
# (bool) Indicate if the application should be fullscreen or not
fullscreen = 0

# (string) Specific version of the NDK to use
# android.ndk = 25b

# (string) Specific version of the SDK to use
# android.sdk = 33

# ---------------------------------------------------------------------------
# Build Configuration
# ---------------------------------------------------------------------------
# (int) Log level (0 = error only, 1 = info, 2 = debug with full output)
log_level = 1

# (int) Display warning if buildozer is run as root (0 = False, 1 = True)
warn_on_root = 1

# (str) Path to build artifact storage
# build_dir = ./.buildozer

# (str) Path to build output
# bin_dir = ./bin

# ---------------------------------------------------------------------------
# OS Specific
# ---------------------------------------------------------------------------
# (str) Path to build command (for Android NDK)
# android.ndk_path =
# (str) Path to SDK command (for Android SDK)
# android.sdk_path =
# (str) Path to Java JDK
# android.ant_path =

# ---------------------------------------------------------------------------
# iOS specific (not used for Android build)
# ---------------------------------------------------------------------------
# ios.kivy_ios_url = https://github.com/kivy/kivy-ios
# ios.kivy_ios_branch = master
# ios.ios_deploy_url = https://github.com/phonegap/ios-deploy
# ios.ios_deploy_branch = 1.10.0
# ios.codesign.allowed = false
# ios.code_sign_identity = iPhone Developer
# ios.provisioning_profile = /path/to/provisioning/profile

# ---------------------------------------------------------------------------
# Buildozer verbosity
# ---------------------------------------------------------------------------
# (int) Log level (0 = error only, 1 = info, 2 = debug)
# log_level = 1

# (int) Display warning if buildozer is run as root (0 = False, 1 = True)
# warn_on_root = 1

# ---------------------------------------------------------------------------
# Additional Android Options
# ---------------------------------------------------------------------------

# (bool) Copy library instead of making a libpymodules.so
# android.copy_libs = 1

# (str) The Android arch to build for, choices: armeabi-v7a, arm64-v8a, x86, x86_64
# android.arch = armeabi-v7a

# ---------------------------------------------------------------------------
# Build Presets
# ---------------------------------------------------------------------------
[build_presets]
# You can use these with: buildozer android debug @preset_name

# Preset for CI/automated builds
ci = debug,update,android.debug_artifact=apk,android.archs=arm64-v8a

# Preset for release builds
release = release,android.archs=arm64-v8a,android.release_artifact=aab

# Preset for quick local testing
quick = android,debug,android.archs=arm64-v8a,android.no-byte-compile-python=1
