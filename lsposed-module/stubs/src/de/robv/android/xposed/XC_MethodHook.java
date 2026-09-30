package de.robv.android.xposed;

import java.lang.reflect.Member;

/**
 * Compile-only stub (runtime provided by LSPosed framework).
 */
public abstract class XC_MethodHook extends XCallback {

    public XC_MethodHook() {
    }

    public XC_MethodHook(int priority) {
    }

    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
    }

    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
    }

    @SuppressWarnings("unused")
    public static abstract class MethodHookParam extends XCallback.Param {
        public Member method;
        public Object thisObject;
        public Object[] args;

        private Object result = null;
        private Throwable throwable = null;
        public boolean returnEarly = false;

        public Object getResult() {
            return result;
        }

        public void setResult(Object result) {
            this.result = result;
            this.returnEarly = true;
        }

        public Throwable getThrowable() {
            return throwable;
        }

        public void setThrowable(Throwable throwable) {
            this.throwable = throwable;
            this.returnEarly = true;
        }

        public boolean hasThrowable() {
            return throwable != null;
        }
    }

    /**
     * Runtime signature (LSPosed 2.x): hookMethod returns Unhook, not Object[].
     */
    public static class Unhook {
        public Unhook() {
        }

        public void unhook() {
        }

        public XC_MethodHook getCallback() {
            return null;
        }

        public Member getHookedMethod() {
            return null;
        }
    }
}
