package com.hu.sceneunlock;

import android.content.Context;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Scene工具箱 (com.omarea.vtools) N1 2026.09 Alpha8 (versionCode 920260926)
 * 专业版解锁模块 —— 基于《Scene工具箱 激活防护安全评估报告 v1.0》V1/V9 漏洞链：
 *
 *  L4 守护进程裁决应答无认证(V1)：a.zz.g(String) 将守护进程对 "activate" 消息的
 *     应答字符串原样透传（success@<ts> / expired / invalid / not-you / error），
 *     无签名、无 MAC、无挑战-应答。本模块在该唯一漏斗处统一改写为
 *     success@4102444800000（2100-01-01）。
 *  L2 本地状态机(V9, 从属)：a.vq.a()（授权缓存，toString 的数据源）与
 *     a.b3.b(String)（状态机）/ a.b3.c()（授权档位）一并强制为已激活/永久专业版。
 *  ROOT 功能门禁：a.zz.t() 是全应用 38 处工作模式判定的总闸，守护进程在线
 *     （a.zz.r()==true）时强制返回 "root"（守护进程 exec-shell 不做授权裁决，
 *     见报告 V1 复现链②③）。
 *
 * 不写 SharedPreferences、不拦截 exec-shell/scheduler 等常规消息、不伪造服务端凭证。
 * 使用 legacy Xposed API（de.robv XC_MethodHook 风格）—— 目标设备 LSPosed 2.2.0
 * 运行时注入的 API dex 与官方 api-101 AAR 签名不一致（无 intercept/ProceedJoinPoint），
 * legacy 类集 (de.robv.*) 在 framework.dex 中完整存在，全版本 LSPosed 兼容。
 */
public class MainHook implements IXposedHookLoadPackage {

    private static final String TAG = "SceneUnlock";
    private static final String TARGET_PKG = "com.omarea.vtools";

    /** 2100-01-01 00:00 UTC，Scene 状态机按毫秒标准化后格式化为到期日 */
    private static final long FAR_TS = 4102444800000L;
    private static final String FAR_DATE = "2099-12-31";
    private static final String SUCCESS_STATE = "success@" + FAR_TS;
    private static final String PERPETUAL_TYPE = "perpetual";
    private static final String TYPE_NAME_FALLBACK = "专业版(永久)";

    private static final ConcurrentHashMap<String, Boolean> INSTALLED = new ConcurrentHashMap<>();

    private static volatile String sTypeName = TYPE_NAME_FALLBACK;
    private static volatile boolean sTypeNameResolved = false;

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpp) throws Throwable {
        if (!TARGET_PKG.equals(lpp.packageName)) {
            return;
        }
        XposedBridge.log(TAG + ": entering " + lpp.packageName
                + " process=" + lpp.processName);
        installAll(lpp.classLoader);
        // 主进程才做 daemon 自动补丁（daemon 客户端 a.zz 在主进程）
        if (TARGET_PKG.equals(lpp.processName)) {
            hookAppAttach(lpp.classLoader);
        }
    }

    /** 拿宿主 Context（供 daemon 自动补丁释放 assets 用）。
     *  注意：魔改 LSPosed 的 legacy XposedHelpers 缺 findAndHookMethod 变体，
     *  必须用 findClass + hookMethod 组合。 */
    private static void hookAppAttach(ClassLoader cl) {
        try {
            Class<?> appClz = XposedHelpers.findClass("android.app.Application", cl);
            int hit = 0;
            for (Method m : appClz.getDeclaredMethods()) {
                if (!"attach".equals(m.getName())) {
                    continue;
                }
                Class<?>[] ps = m.getParameterTypes();
                if (ps.length == 1 && Context.class.isAssignableFrom(ps[0])) {
                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            Object ctx = param.args != null && param.args.length > 0
                                    ? param.args[0] : null;
                            if (ctx instanceof Context) {
                                DaemonPatcher.onAttach((Context) ctx);
                            }
                        }
                    });
                    hit++;
                }
            }
            XposedBridge.log(TAG + ": hooked Application.attach x" + hit + " (patcher armed)");
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": hook Application.attach FAILED: " + t
                    + " (verdict hook 仍会兜底触发)");
        }
    }

    private static synchronized void installAll(ClassLoader cl) {
        int before = INSTALLED.size();
        tryHook(cl, "a.zz", "g", new Class[]{String.class}, new DaemonVerdictHook(true));
        tryHook(cl, "a.zz", "t", new Class[0], new WorkingModeHook());
        tryHook(cl, "a.vq", "a", new Class[0], new DaemonVerdictHook(false));
        tryHook(cl, "a.b3", "b", new Class[]{String.class}, new StateModelHook(false));
        tryHook(cl, "a.b3", "c", new Class[0], new StateModelHook(true));
        // ---- 诊断探针：定位守护进程数据通道（请求/响应/TCP/加密）----
        tryHookByName(cl, "a.zz", "M", 3, new DiagHook("REQ"));
        tryHookByName(cl, "a.zz", "w", 2, new DiagHook("RESP"));
        tryHookByName(cl, "a.zz", "v", 2, new DiagHook("TCP"));
        tryHookByName(cl, "a.zz", "j", 1, new DiagHook("ENC"));
        XposedBridge.log(TAG + ": hooks " + INSTALLED.size() + " (+" + (INSTALLED.size() - before) + ")");
    }

    /** 按方法名+参数个数匹配（运行时参数类型如 a.d00 编译期不可见） */
    private static void tryHookByName(ClassLoader cl, String className, String methodName,
                                      int paramCount, XC_MethodHook hook) {
        String key = className + "." + methodName + "/" + paramCount;
        if (INSTALLED.containsKey(key)) {
            return;
        }
        try {
            Class<?> c = XposedHelpers.findClass(className, cl);
            int hit = 0;
            for (Method m : c.getDeclaredMethods()) {
                if (m.getName().equals(methodName) && m.getParameterTypes().length == paramCount) {
                    XposedBridge.hookMethod(m, hook);
                    hit++;
                }
            }
            if (hit > 0) {
                INSTALLED.put(key, Boolean.TRUE);
                XposedBridge.log(TAG + ": hooked " + key + " x" + hit);
            } else {
                XposedBridge.log(TAG + ": hook " + key + " NOT FOUND");
            }
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": hook " + key + " FAILED: " + t);
        }
    }

    private static String trunc(Object o, int max) {
        if (o == null) return "null";
        String s = (o instanceof byte[]) ? ("bytes[" + ((byte[]) o).length + "]")
                : String.valueOf(o);
        s = s.replace('\n', ' ');
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }

    private static final class DiagHook extends XC_MethodHook {
        private final String tag;

        DiagHook(String tag) { this.tag = tag; }

        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Object[] a = param.args;
            StringBuilder sb = new StringBuilder(tag).append(' ');
            if ("REQ".equals(tag)) {
                sb.append("id=").append(trunc(param.getResult(), 24))
                  .append(" action=").append(trunc(a.length > 0 ? a[0] : null, 32))
                  .append(" payload=").append(trunc(a.length > 1 ? a[1] : null, 120));
            } else if ("RESP".equals(tag)) {
                sb.append("id=").append(trunc(a.length > 0 ? a[0] : null, 24))
                  .append(" data=").append(trunc(a.length > 1 ? a[1] : null, 200));
            } else if ("TCP".equals(tag)) {
                sb.append("ok=").append(param.getResult())
                  .append(" cmd=").append(trunc(a.length > 1 ? a[1] : null, 80));
            } else {
                sb.append("in=").append(trunc(a.length > 0 ? a[0] : null, 60))
                  .append(" out=").append(trunc(param.getResult(), 24));
            }
            XposedBridge.log(TAG + ": " + sb);
        }
    }

    private static void tryHook(ClassLoader cl, String className, String methodName,
                                Class<?>[] sig, XC_MethodHook hook) {
        String key = className + "." + methodName;
        if (INSTALLED.containsKey(key)) {
            return;
        }
        try {
            Class<?> c = XposedHelpers.findClass(className, cl);
            Method m = c.getDeclaredMethod(methodName, sig);
            XposedBridge.hookMethod(m, hook);
            INSTALLED.put(key, Boolean.TRUE);
            XposedBridge.log(TAG + ": hooked " + key);
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": hook " + key + " FAILED: " + t);
        }
    }

    // ------------------------------------------------------------------
    // a.zz.g(String)（activate 裁决漏斗）与 a.vq.a()（授权缓存取值点）：
    // 非 "success@" 开头的应答（expired/invalid/not-you/error/null）一律改写
    // ------------------------------------------------------------------
    private static final class DaemonVerdictHook extends XC_MethodHook {
        private final boolean verbose;

        DaemonVerdictHook(boolean verbose) {
            this.verbose = verbose;
        }

        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            if (param.hasThrowable()) {
                // 原方法异常（如守护进程不可达超时）→ 直接给出成功裁决
                param.setThrowable(null);
                param.setResult(SUCCESS_STATE);
                XposedBridge.log(TAG + ": " + param.method.getName()
                        + " original failed -> success verdict");
                return;
            }
            Object r = param.getResult();
            if (r instanceof String) {
                String s = (String) r;
                if (s.startsWith("success@")) {
                    return;
                }
                param.setResult(SUCCESS_STATE);
                if (verbose) {
                    XposedBridge.log(TAG + ": verdict '" + s + "' -> " + SUCCESS_STATE);
                }
                // daemon 未打补丁的信号 → 触发自动重打（60s 冷却）
                DaemonPatcher.onVerdict(s);
            } else if (r == null && param.method instanceof Method
                    && ((Method) param.method).getReturnType() == String.class) {
                param.setResult(SUCCESS_STATE);
                XposedBridge.log(TAG + ": verdict null -> " + SUCCESS_STATE);
            }
        }
    }

    // ------------------------------------------------------------------
    // a.zz.t()：工作模式总闸。仅当守护进程确实可达（a.zz.r()==true）时
    // 强制 "root"，避免守护进程缺席时向 UI 谎报连接状态
    // ------------------------------------------------------------------
    private static final class WorkingModeHook extends XC_MethodHook {
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            try {
                Class<?> zz = param.method.getDeclaringClass();
                Method r = zz.getDeclaredMethod("r");
                r.setAccessible(true);
                Object connected = r.invoke(null);
                if (!Boolean.TRUE.equals(connected)) {
                    return;
                }
                Field l = zz.getDeclaredField("l");
                l.setAccessible(true);
                l.set(null, "root");
                param.setResult("root");
                XposedBridge.log(TAG + ": working mode -> root (daemon online)");
            } catch (Throwable t) {
                XposedBridge.log(TAG + ": WorkingMode error: " + t);
            }
        }
    }

    // ------------------------------------------------------------------
    // a.b3.b(String)（状态机）与 a.b3.c()（授权档位）：ActivatedStateModel
    // 属目标 App 类，模块编译期不可见 → 反射调 setter（字段均为 String/boolean，
    // 已对照反编译源码逐一核实，无类型陷阱）
    // ------------------------------------------------------------------
    private static final class StateModelHook extends XC_MethodHook {
        private final boolean typeMode;

        StateModelHook(boolean typeMode) {
            this.typeMode = typeMode;
        }

        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Object model = param.getResult();
            try {
                if (model == null) {
                    return;
                }
                Class<?> c = model.getClass();
                c.getMethod("setActivated", boolean.class).invoke(model, true);
                if (typeMode) {
                    c.getMethod("setPermanent", boolean.class).invoke(model, true);
                    c.getMethod("setType", String.class).invoke(model, PERPETUAL_TYPE);
                    c.getMethod("setTypeName", String.class)
                            .invoke(model, resolveTypeName(param.thisObject));
                    Object text = c.getMethod("getText").invoke(model);
                    if (!(text instanceof String) || !((String) text).contains(FAR_DATE)) {
                        c.getMethod("setText", String.class)
                                .invoke(model, "有效期至:" + FAR_DATE);
                    }
                } else {
                    String prefix = "";
                    Object[] args = param.args;
                    if (args != null && args.length > 0 && args[0] instanceof String) {
                        prefix = (String) args[0];
                        if (prefix == null) {
                            prefix = "";
                        }
                    }
                    c.getMethod("setText", String.class).invoke(model, prefix + FAR_DATE);
                }
            } catch (Throwable t) {
                XposedBridge.log(TAG + ": StateModel error: " + t);
            }
        }
    }

    /** 从 a.b3 实例字段 a(Context) 解析 R.string.license_perpetual，失败回退硬编码 */
    private static String resolveTypeName(Object b3Instance) {
        if (sTypeNameResolved || b3Instance == null) {
            return sTypeName;
        }
        try {
            Field f = b3Instance.getClass().getDeclaredField("a");
            f.setAccessible(true);
            Context ctx = (Context) f.get(b3Instance);
            Object sid = ctx.getClassLoader()
                    .loadClass("com.omarea.vtools.R$string")
                    .getField("license_perpetual")
                    .get(null);
            sTypeName = ctx.getString((Integer) sid);
        } catch (Throwable t) {
            sTypeName = TYPE_NAME_FALLBACK;
        }
        sTypeNameResolved = true;
        return sTypeName;
    }
}
