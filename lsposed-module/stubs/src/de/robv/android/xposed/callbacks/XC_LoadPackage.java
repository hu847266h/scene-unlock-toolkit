package de.robv.android.xposed.callbacks;

import android.content.pm.ApplicationInfo;

import de.robv.android.xposed.XCallback;

/**
 * Compile-only stub (runtime provided by LSPosed framework).
 */
public abstract class XC_LoadPackage extends XCallback {

    public XC_LoadPackage() {
    }

    @SuppressWarnings("unused")
    public static final class LoadPackageParam extends XCallback.Param {
        public String packageName;
        public String processName;
        public ClassLoader classLoader;
        public ApplicationInfo appInfo;
        public boolean isFirstApplication;
    }
}
