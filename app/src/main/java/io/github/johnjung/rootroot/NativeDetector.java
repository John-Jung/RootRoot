package io.github.johnjung.rootroot;

import android.util.Log;

public class NativeDetector {
    private static final String TAG = "RootRoot";

    static {
        try {
            System.loadLibrary("hidden_detector");
            Log.d(TAG, "hidden_detector loaded");
        } catch (UnsatisfiedLinkError e) {
            Log.e(TAG, "hidden_detector load fail: " + e.getMessage());
        }

        try {
            System.loadLibrary("native_detector");
            Log.d(TAG, "native_detector loaded");
        } catch (UnsatisfiedLinkError e) {
            Log.e(TAG, "native_detector load fail: " + e.getMessage());
        }
    }

    // ========== Static Registration ==========
    public static native boolean checkSuExistsStatic();
    public static native boolean checkMagiskMountStatic();
    public static native boolean checkFridaProcessStatic();
    public static native boolean checkFridaLibraryStatic();

    // ========== Dynamic Registration ==========
    public static native boolean checkSuExistsDynamic();
    public static native boolean checkMagiskMountDynamic();
    public static native boolean checkFridaProcessDynamic();
    public static native boolean checkFridaLibraryDynamic();

    // ========== Dlsym (Hidden Library) ==========
    public static native boolean checkSuExistsDlsym();
    public static native boolean checkMagiskMountDlsym();
    public static native boolean checkFridaDlsym();
}
