// native_detector.cpp — Pure C I/O (no C++ STL dependency)
// Package: io.github.johnjung.rootroot

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <dlfcn.h>
#include <ctype.h>
#include <android/log.h>

#define LOG_TAG "RootRoot"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static const char* SU_PATHS[] = {
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/data/local/bin/su",
        "/data/local/xbin/su",
        "/su/bin/su",
        "/magisk/.core/bin/su"
};
static const int SU_PATHS_COUNT = 7;

// ================================================================
//              Static Registration
// ================================================================

extern "C" JNIEXPORT jboolean JNICALL
Java_io_github_johnjung_rootroot_NativeDetector_checkSuExistsStatic(JNIEnv *env, jclass clazz) {
    for (int i = 0; i < SU_PATHS_COUNT; i++) {
        if (access(SU_PATHS[i], F_OK) == 0) return JNI_TRUE;
    }
    return JNI_FALSE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_io_github_johnjung_rootroot_NativeDetector_checkMagiskMountStatic(JNIEnv *env, jclass clazz) {
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

extern "C" JNIEXPORT jboolean JNICALL
Java_io_github_johnjung_rootroot_NativeDetector_checkFridaProcessStatic(JNIEnv *env, jclass clazz) {
    DIR* dir = opendir("/proc");
    if (!dir) return JNI_FALSE;

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR && isdigit(entry->d_name[0])) {
            char path[256];
            snprintf(path, sizeof(path), "/proc/%s/cmdline", entry->d_name);

            FILE* f = fopen(path, "r");
            if (f) {
                char cmd[256];
                memset(cmd, 0, sizeof(cmd));
                fread(cmd, 1, sizeof(cmd) - 1, f);
                fclose(f);

                if (strstr(cmd, "frida") || strstr(cmd, "frida-server")) {
                    closedir(dir);
                    return JNI_TRUE;
                }
            }
        }
    }
    closedir(dir);
    return JNI_FALSE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_io_github_johnjung_rootroot_NativeDetector_checkFridaLibraryStatic(JNIEnv *env, jclass clazz) {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return JNI_FALSE;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "frida") || strstr(line, "frida-agent") || strstr(line, "frida-gadget")) {
            fclose(f);
            return JNI_TRUE;
        }
    }
    fclose(f);
    return JNI_FALSE;
}

// ================================================================
//              Dynamic Registration
// ================================================================

static jboolean detectSu(JNIEnv *env, jclass clazz) {
    for (int i = 0; i < SU_PATHS_COUNT; i++) {
        if (access(SU_PATHS[i], F_OK) == 0) return JNI_TRUE;
    }
    return JNI_FALSE;
}

static jboolean detectMagisk(JNIEnv *env, jclass clazz) {
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

static jboolean detectFridaProc(JNIEnv *env, jclass clazz) {
    DIR* dir = opendir("/proc");
    if (!dir) return JNI_FALSE;

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR && isdigit(entry->d_name[0])) {
            char path[256];
            snprintf(path, sizeof(path), "/proc/%s/cmdline", entry->d_name);

            FILE* f = fopen(path, "r");
            if (f) {
                char cmd[256];
                memset(cmd, 0, sizeof(cmd));
                fread(cmd, 1, sizeof(cmd) - 1, f);
                fclose(f);

                if (strstr(cmd, "frida") || strstr(cmd, "frida-server")) {
                    closedir(dir);
                    return JNI_TRUE;
                }
            }
        }
    }
    closedir(dir);
    return JNI_FALSE;
}

static jboolean detectFridaLib(JNIEnv *env, jclass clazz) {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return JNI_FALSE;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "frida") || strstr(line, "frida-agent") || strstr(line, "frida-gadget")) {
            fclose(f);
            return JNI_TRUE;
        }
    }
    fclose(f);
    return JNI_FALSE;
}

static JNINativeMethod methods[] = {
        {"checkSuExistsDynamic",      "()Z", (void*)detectSu},
        {"checkMagiskMountDynamic",   "()Z", (void*)detectMagisk},
        {"checkFridaProcessDynamic",  "()Z", (void*)detectFridaProc},
        {"checkFridaLibraryDynamic",  "()Z", (void*)detectFridaLib}
};

// ================================================================
//              Dlsym (hidden library)
// ================================================================

static void* g_hiddenHandle = NULL;

static void* getHiddenHandle() {
    if (g_hiddenHandle == NULL) {
        g_hiddenHandle = dlopen("libhidden_detector.so", RTLD_NOLOAD | RTLD_NOW);
        if (!g_hiddenHandle) {
            LOGE("dlopen RTLD_NOLOAD fail: %s", dlerror());
            g_hiddenHandle = dlopen("libhidden_detector.so", RTLD_NOW);
            if (!g_hiddenHandle) {
                LOGE("dlopen fail: %s", dlerror());
            }
        }
    }
    return g_hiddenHandle;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_io_github_johnjung_rootroot_NativeDetector_checkSuExistsDlsym(JNIEnv *env, jclass clazz) {
    LOGD("checkSuExistsDlsym called");
    void* handle = getHiddenHandle();
    if (!handle) return JNI_FALSE;

    typedef jboolean (*CheckFunc)();
    CheckFunc check = (CheckFunc)dlsym(handle, "x7k9m");
    if (!check) { LOGE("dlsym x7k9m fail: %s", dlerror()); return JNI_FALSE; }
    return check();
}

extern "C" JNIEXPORT jboolean JNICALL
Java_io_github_johnjung_rootroot_NativeDetector_checkMagiskMountDlsym(JNIEnv *env, jclass clazz) {
    void* handle = getHiddenHandle();
    if (!handle) return JNI_FALSE;

    typedef jboolean (*CheckFunc)();
    CheckFunc check = (CheckFunc)dlsym(handle, "p3q8r");
    if (!check) { LOGE("dlsym p3q8r fail: %s", dlerror()); return JNI_FALSE; }
    return check();
}

extern "C" JNIEXPORT jboolean JNICALL
Java_io_github_johnjung_rootroot_NativeDetector_checkFridaDlsym(JNIEnv *env, jclass clazz) {
    void* handle = getHiddenHandle();
    if (!handle) return JNI_FALSE;

    typedef jboolean (*CheckFunc)();
    CheckFunc check = (CheckFunc)dlsym(handle, "w2e5t");
    if (!check) { LOGE("dlsym w2e5t fail: %s", dlerror()); return JNI_FALSE; }
    return check();
}

// ================================================================
//              JNI_OnLoad
// ================================================================

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env;
    if (vm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    jclass clazz = env->FindClass("io/github/johnjung/rootroot/NativeDetector");
    if (clazz == NULL) {
        LOGE("FindClass failed");
        return JNI_ERR;
    }

    int count = sizeof(methods) / sizeof(methods[0]);
    if (env->RegisterNatives(clazz, methods, count) < 0) {
        LOGE("RegisterNatives failed");
        return JNI_ERR;
    }

    LOGD("JNI_OnLoad: %d dynamic methods registered", count);
    return JNI_VERSION_1_6;
}