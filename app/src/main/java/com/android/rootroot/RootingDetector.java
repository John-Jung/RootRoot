package com.android.rootroot;

import android.content.Context;
import android.content.pm.PackageManager;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;

public class RootingDetector {
    private final Context mContext;

    public RootingDetector(Context context) {
        mContext = context;
    }

    public boolean checkRootingPackage() {
        ArrayList<String> packages = new ArrayList<>(Arrays.asList(Constants.knownRootAppsPackages));
        PackageManager pm = mContext.getPackageManager();

        for (String packageName : packages) {
            try {
                pm.getPackageInfo(packageName, 0);
                return true;
            } catch (PackageManager.NameNotFoundException ignore) {
            }
        }
        return false;
    }

    public boolean checkSuBinary() {
        for (String directory : Constants.knownSuDirectories) {
            for (String filename : Constants.knownSuBinaries) {
                File f = new File(directory, filename);
                if (f.exists()) {
                    return true;
                }
            }
        }
        return false;
    }
}
