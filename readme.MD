# RootRoot

> Android Security Detection Toolkit — Root, Magisk & Frida detection across multiple JNI registration strategies

## Overview

**RootRoot** is an open-source Android security research tool that demonstrates how mobile applications detect rooted devices, Magisk installations, and Frida instrumentation frameworks. It implements **13 detection checks** across **4 distinct JNI registration strategies**, making it an educational resource for understanding both offensive and defensive mobile security techniques.

The app features a dark terminal-style UI with expandable cards that show real-time scan results, execution timing, and detailed descriptions of each detection method.

## Detection Methods

### ☕ Java Layer (2 checks)

| Check | Technique |
|-------|-----------|
| **Root Package Scan** | Queries `PackageManager.getPackageInfo()` against 48 known root app package signatures (Magisk, SuperSU, KingRoot, Xposed, etc.) |
| **SU Binary Search** | Checks `File.exists()` across 14 directories for `su`, `busybox`, and `magisk` binaries |

### ⚡ Native · Static Registration (4 checks)

Functions are registered via **exported JNI symbols** — visible in the `.so` symbol table via `nm` or `readelf`.

| Check | Technique |
|-------|-----------|
| **Su Binary Check** | `access(path, F_OK)` on 7 known su binary paths |
| **Magisk Mount** | Reads `/proc/mounts` for `magisk` and `/sbin/.magisk` mount points |
| **Frida Process** | Scans `/proc/*/cmdline` for `frida-server` processes |
| **Frida Library** | Reads `/proc/self/maps` for `frida-agent` and `frida-gadget` shared libraries |

```
$ llvm-nm -D libnative_detector.so | grep Java_
T Java_com_android_rootroot_NativeDetector_checkSuExistsStatic
T Java_com_android_rootroot_NativeDetector_checkMagiskMountStatic
T Java_com_android_rootroot_NativeDetector_checkFridaProcessStatic
T Java_com_android_rootroot_NativeDetector_checkFridaLibraryStatic
```

### 🔄 Native · Dynamic Registration (4 checks)

Functions are registered at runtime via `RegisterNatives()` in `JNI_OnLoad`. **No exported symbols** — function names don't appear in the symbol table.

| Check | Technique |
|-------|-----------|
| **Su Binary Check** | Same detection logic as static, registered dynamically |
| **Magisk Mount** | `/proc/mounts` scan via `RegisterNatives` |
| **Frida Process** | `/proc/*/cmdline` scan via `RegisterNatives` |
| **Frida Library** | `/proc/self/maps` scan via `RegisterNatives` |

```
$ llvm-nm -D libnative_detector.so | grep detect
                 (nothing — symbols are hidden)
```

### 🔗 Native · Dlsym / Hidden Library (3 checks)

Detection logic lives in a **separate shared library** (`libhidden_detector.so`) with **obfuscated function names**. The main library resolves them at runtime via `dlsym()`.

| Check | Technique |
|-------|-----------|
| **Su Binary Check** | `dlsym(handle, "x7k9m")` → obfuscated su path check |
| **Magisk Mount** | `dlsym(handle, "p3q8r")` → obfuscated `/proc/mounts` scan |
| **Frida Detection** | `dlsym(handle, "w2e5t")` → obfuscated `/proc/self/maps` scan |

```
$ llvm-nm -D libhidden_detector.so
T x7k9m        ← what does this do? Reverse engineer to find out
T p3q8r
T w2e5t
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    MainActivity.kt                       │
│              (Terminal UI + Scan Engine)                  │
├─────────────────┬───────────────────────────────────────┤
│   Java Layer    │         Native Layer (JNI)             │
│                 │                                        │
│ RootingDetector │  ┌──────────────────────────────────┐  │
│   .java         │  │      libnative_detector.so       │  │
│                 │  │                                    │  │
│ • checkRooting  │  │  Static:  exported JNI symbols    │  │
│   Package()     │  │  Dynamic: RegisterNatives()       │  │
│ • checkSu       │  │  Dlsym:   dlopen + dlsym()  ─────┼──┼──┐
│   Binary()      │  │                                    │  │  │
│                 │  └──────────────────────────────────┘  │  │
│ Constants.java  │                                        │  │
│ • 48 root pkgs  │  ┌──────────────────────────────────┐  │  │
│ • 14 su dirs    │  │    libhidden_detector.so          │◄─┘  │
│ • 3 su bins     │  │    (obfuscated symbols)           │     │
│                 │  │    x7k9m, p3q8r, w2e5t            │     │
│                 │  └──────────────────────────────────┘     │
├─────────────────┴───────────────────────────────────────────┤
│                  NativeDetector.java                         │
│           (JNI bridge — loads both .so files)                │
└─────────────────────────────────────────────────────────────┘
```

## Project Structure

```
app/src/main/
├── java/com/android/rootroot/
│   ├── MainActivity.kt          # Terminal UI + scan orchestration
│   ├── NativeDetector.java      # JNI bridge (loads .so, declares native methods)
│   ├── RootingDetector.java     # Java-layer root detection
│   └── Constants.java           # Known root packages, su paths, binaries
├── cpp/
│   ├── CMakeLists.txt           # Native build config (2 shared libraries)
│   ├── native_detector.cpp      # Static + Dynamic + Dlsym JNI methods
│   └── hidden_detector.cpp      # Obfuscated detection functions
└── res/
    ├── layout/activity_main.xml
    ├── values/colors.xml        # Terminal dark theme colors
    ├── values/themes.xml
    ├── drawable/bg_card.xml
    └── drawable/bg_scan_button.xml
```

## Build & Run

### Prerequisites

- Android Studio (Arctic Fox or later)
- Android NDK (installed via SDK Manager)
- CMake 3.22.1+ (installed via SDK Manager)
- Min SDK: 24 (Android 7.0)
- Target SDK: 36

### Steps

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/RootRoot.git

# Open in Android Studio
# File → Open → select the RootRoot directory

# Sync Gradle
# File → Sync Project with Gradle Files

# Build & Run
# Run → Run 'app' on your device/emulator
```

### Supported ABIs

`armeabi-v7a` · `arm64-v8a` · `x86` · `x86_64`

## Security Research Context

This project exists to help security researchers and penetration testers understand:

**Detection side (Blue Team):**
- How Android apps implement root/Magisk/Frida detection
- Tradeoffs between JNI registration strategies (static vs dynamic vs dlsym)
- Why symbol visibility matters for security-sensitive native code

**Bypass side (Red Team):**
- Where to look when reverse engineering detection logic
- How `Interceptor.attach` vs `Interceptor.replace` work in Frida
- Why static JNI is easy to bypass (symbols are visible) while dlsym requires more effort

### Bypass Difficulty by Method

| Method | Symbol Visibility | Bypass Difficulty | Why |
|--------|-------------------|-------------------|-----|
| Java Layer | Fully visible in JADX | ⭐ Easy | Hook return values or modify Constants |
| Native Static | Exported in `.so` | ⭐⭐ Easy | `nm` reveals function names → direct Frida hooks |
| Native Dynamic | Hidden (no exports) | ⭐⭐⭐ Medium | Must hook `RegisterNatives` or trace `JNI_OnLoad` |
| Native Dlsym | Obfuscated names | ⭐⭐⭐⭐ Hard | Must reverse `libhidden_detector.so` or hook `dlsym()` |

## UI

The app features a dark terminal aesthetic with:

- Monospace typography throughout
- `root@device:~#` prompt-style header
- Expandable cards for each detection category
- Real-time scan animation with staggered results
- Green (PASS) / Red (DETECTED) status indicators with pulse effects
- Execution timing for each individual check
- Summary footer with total scan statistics

![a](https://github.com/user-attachments/assets/f566057d-41d6-43cb-8405-39765bad6985)