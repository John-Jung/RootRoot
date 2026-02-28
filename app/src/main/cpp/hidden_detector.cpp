// hidden_detector.cpp — Pure C I/O (no C++ STL dependency)
// Obfuscated detection logic in a separate shared library

#include <jni.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern "C" {

// Root detection (obfuscated name: x7k9m)
__attribute__((visibility("default")))
jboolean x7k9m() {
    const char* paths[] = {
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/data/local/bin/su",
            "/data/local/xbin/su",
            "/su/bin/su",
            "/magisk/.core/bin/su"
    };

    int count = sizeof(paths) / sizeof(paths[0]);
    for (int i = 0; i < count; i++) {
        if (access(paths[i], F_OK) == 0) {
            return JNI_TRUE;
        }
    }
    return JNI_FALSE;
}

// Magisk detection (obfuscated name: p3q8r)
__attribute__((visibility("default")))
jboolean p3q8r() {
    FILE* f = fopen("/proc/mounts", "r");
    if (!f) return JNI_FALSE;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "magisk") || strstr(line, "/sbin/.magisk")) {
            fclose(f);
            return JNI_TRUE;
        }
    }
    fclose(f);
    return JNI_FALSE;
}

// Frida detection (obfuscated name: w2e5t)
__attribute__((visibility("default")))
jboolean w2e5t() {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return JNI_FALSE;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "frida")) {
            fclose(f);
            return JNI_TRUE;
        }
    }
    fclose(f);
    return JNI_FALSE;
}

}