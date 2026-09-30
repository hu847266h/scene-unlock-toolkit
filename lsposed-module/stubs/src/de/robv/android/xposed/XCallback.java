package de.robv.android.xposed;

/**
 * Compile-only stub of the legacy Xposed API (runtime provided by LSPosed framework).
 * NEVER packaged into the module APK (gradle compileOnly).
 */
public abstract class XCallback {

    public XCallback() {
    }

    public XCallback(int priority) {
    }

    public static class Param {
        public Object[] args;

        public Param() {
        }

        public Param(Object[] args) {
            this.args = args;
        }
    }
}
