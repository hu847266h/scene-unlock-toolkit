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
 * Scene工具箱 (com.omarea.vtools) N1 2026.10 Alpha10 ( hook 表按版本多候选 )：
 *   Alpha10: a.s10.g/t/M/j, a.ns.a, a.a3.b/c
 *   Alpha8 : a.zz.g/t/M/j,  a.vq.a,  a.b3.b/c
 * 专业版解锁模块 —— 基于《Scene工具箱 激活防护安全评估报告 v1.0》V1/V9 漏洞链：
 *
 *  L4 守护进程裁决应答无认证(V1)：s10.g(String) 将守护进程对 "activate" 消息的
 *     应答字符串原样透传（success@<ts> / expired / invalid / not-you / error），
 *     无签名、无 MAC、无挑战-应答。本模块在该唯一漏斗处统一改写为
 *     success@4102444800000（2100-01-01）。
 *  L2 本地状态机(V9, 从属)：ns.a()（授权缓存，toString 的数据源）与
 *     a3.b(String)（状态机）/ a3.c()（授权档位）一并强制为已激活/永久专业版。
 *  ROOT 功能门禁：s10.t() 是全应用 38 处工作模式判定的总闸，守护进程在线
 *     （s10.r()==true）时强制返回 "root"（守护进程 exec-shell 不做授权裁决，
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
        // 多候选 hook 表：每项按顺序尝试，首个命中的类生效（Alpha10 / Alpha8）
        tryAnyHook(cl, new String[][]{{"a.s10", "g"}, {"a.zz", "g"}},
                new Class[]{String.class}, new DaemonVerdictHook(true));
        tryAnyHook(cl, new String[][]{{"a.s10", "t"}, {"a.zz", "t"}},
                new Class[0], new WorkingModeHook());
        tryAnyHook(cl, new String[][]{{"a.ns", "a"}, {"a.vq", "a"}},
                new Class[0], new DaemonVerdictHook(false));
        tryAnyHook(cl, new String[][]{{"a.a3", "b"}, {"a.b3", "b"}},
                new Class[]{String.class}, new StateModelHook(false));
        tryAnyHook(cl, new String[][]{{"a.a3", "c"}, {"a.b3", "c"}},
                new Class[0], new StateModelHook(true));
        // ---- 诊断探针：定位守护进程数据通道（请求/加密，仅打日志）----
        tryAnyHookByName(cl, new String[][]{{"a.s10", "M"}, {"a.zz", "M"}},
                3, new DiagHook("REQ"));
        tryAnyHookByName(cl, new String[][]{{"a.s10", "j"}, {"a.zz", "j"}},
                1, new DiagHook("ENC"));
        // ---- 服务器侧重验弹窗抑制（Alpha10 引入的自动 license 云验证）----
        // p50.a 是 /release-exchange 响应分发器：服务器拒绝（兑换码绑定其他设备等）
        // 时弹"盗版"类对话框。跳过拒绝分支 + 吞异常（防 "Unknown error" toast）。
        tryHookServerDispatch(cl);
        // 兜底：按文案过滤 license 失败类 toast/对话框（覆盖 a3.a/hb/u1 等所有路径）
        tryHookPopupFilter(cl);
        XposedBridge.log(TAG + ": hooks " + INSTALLED.size() + " (+" + (INSTALLED.size() - before) + ")");
    }

    // ------------------------------------------------------------------
    // 服务器响应弹窗抑制。Scene 的发卡服务器（/release-activate2、/release-exchange）
    // 会在设备与激活码绑定不符时返回失败，App 据此弹出盗版提示并中断流程；
    // 这条链路不经过 daemon 裁决漏斗，需在响应分发处单独处理。
    // 真实兑换成功路径（exchanged/activated）原样放行，不影响正常购买流程。
    // ------------------------------------------------------------------
    private static final String EXCHANGE_RESP = "com.omarea.model.ExchangeResponse";
    private static volatile Method sGetExchanged, sGetActivated, sGetFound, sGetNumber, sGetUsed;

    private static void tryHookServerDispatch(ClassLoader cl) {
        // 多候选：Alpha10 为 a.p50，后续版本类名可能漂移
        String[][] candidates = {{"a.p50", "a"}};
        for (String[] c : candidates) {
            try {
                Class<?> dispatch = XposedHelpers.findClass(c[0], cl);
                Class<?> respClz = XposedHelpers.findClass(EXCHANGE_RESP, cl);
                Class<?> f70 = XposedHelpers.findClass("a.f70", cl);
                for (Method m : dispatch.getDeclaredMethods()) {
                    Class<?>[] ps = m.getParameterTypes();
                    if (!"a".equals(m.getName()) || ps.length != 4
                            || !ps[0].getName().equals(c[0])
                            || ps[1] != f70 || ps[2] != String.class || ps[3] != respClz) {
                        continue;
                    }
                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            Object resp = param.args.length > 3 ? param.args[3] : null;
                            if (serverRejected(resp)) {
                                // 服务器拒绝（码未绑定此设备/次数耗尽/未找到）：
                                // 跳过原方法 → 不弹盗版对话框，流程继续走本地裁决
                                param.setResult(null);
                                XposedBridge.log(TAG + ": server-rejected exchange response suppressed");
                            }
                        }

                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            if (param.hasThrowable()) {
                                // 吞掉异常 → 调用方的 catch("Unknown error: ") 不再触发
                                XposedBridge.log(TAG + ": exchange dispatch exception swallowed: "
                                        + param.getThrowable());
                                param.setThrowable(null);
                            }
                        }
                    });
                    INSTALLED.put(c[0] + ".a/4", Boolean.TRUE);
                    XposedBridge.log(TAG + ": hooked " + c[0] + ".a/4 (exchange dispatch)");
                    return;
                }
                XposedBridge.log(TAG + ": hook " + c[0] + ".a/4 NOT FOUND");
            } catch (Throwable t) {
                XposedBridge.log(TAG + ": hook " + c[0] + ".a/4 FAILED: " + t);
            }
        }
    }

    /** 判断兑换响应是否为"服务器拒绝"（模块用户无需关注这些失败弹窗） */
    private static boolean serverRejected(Object resp) {
        if (resp == null) {
            return true;
        }
        try {
            if (sGetExchanged == null) {
                synchronized (MainHook.class) {
                    if (sGetExchanged == null) {
                        Class<?> c = resp.getClass();
                        sGetExchanged = c.getMethod("getExchanged");
                        sGetActivated = c.getMethod("getActivated");
                        sGetFound = c.getMethod("getFound");
                        sGetNumber = c.getMethod("getNumber");
                        sGetUsed = c.getMethod("getUsed");
                    }
                }
            }
            boolean exchanged = (Boolean) sGetExchanged.invoke(resp);
            boolean activated = (Boolean) sGetActivated.invoke(resp);
            if (exchanged || activated) {
                return false; // 真实兑换/绑定成功路径，放行原逻辑
            }
            boolean found = (Boolean) sGetFound.invoke(resp);
            if (!found) {
                return true; // 服务器未找到记录 / 设备不符 → 盗版提示来源
            }
            int number = (Integer) sGetNumber.invoke(resp);
            int used = (Integer) sGetUsed.invoke(resp);
            return number <= used; // 次数耗尽 → 抑制；有效未用 → 放行确认对话框
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": serverRejected reflective fail: " + t);
            return false; // 判定失败时放行，不误伤
        }
    }

    // ------------------------------------------------------------------
    // 弹窗文案过滤兜底层。所有 license 失败类 toast/对话框都经过 js1 的
    // UI 辅助方法；按中英文案精确特征拦截，其余弹窗不受影响。
    // ------------------------------------------------------------------
    private static final String[] POPUP_BLOCKLIST = {
            // 盗版/设备绑定类
            "Unknown error", "奇怪的错误",
            "兑换失败", "兑换次数耗尽", "兑换码使用次数已用完", "Run out of exchanges",
            "你可能输入了无效的兑换码", "invalid exchange code",
            "但激活设备时出现错误", "an error occurred when activating the device",
            // 激活失败类
            "激活失败", "Unable to activate", "Activation failed",
            "激活信息无效", "启动失败", "Startup failed",
            // 过期/试用类
            "试用时间已结束", "trial period has ended",
            "授权已于", "License expired in", "激活已失效", "License Expired",
            "可用积分为0", "available credits for this account is 0",
            "请重新购买", "re-purchase",
            // 同步/网络失败类
            "同步超时", "Synchronize timeout",
            "同步激活状态失败", "Failed to synchronize the activation state",
            "请检查网络是否顺畅，以及Scene是否更新到最近版本",
            "Please check whether the network is available",
    };

    private static boolean popupBlocked(CharSequence text) {
        if (text == null) {
            return false;
        }
        String s = text.toString();
        for (String marker : POPUP_BLOCKLIST) {
            if (s.contains(marker)) {
                return true;
            }
        }
        return false;
    }

    private static void tryHookPopupFilter(ClassLoader cl) {
        try {
            Class<?> js1 = XposedHelpers.findClass("a.js1", cl);
            Class<?> f70 = XposedHelpers.findClass("a.f70", cl);
            int hits = 0;
            for (Method m : js1.getDeclaredMethods()) {
                Class<?>[] ps = m.getParameterTypes();
                boolean isToast = m.getName().equals("X") && ps.length == 2
                        && ps[0] == String.class && ps[1] == int.class;
                boolean isDialog = (m.getName().equals("a") || m.getName().equals("F"))
                        && ps.length == 4 && ps[1] == String.class
                        && (ps[2] == String.class || ps[2] == CharSequence.class)
                        && ps[3] == Runnable.class;
                boolean isDialogZ = m.getName().equals("Z") && ps.length == 6
                        && ps[1] == String.class && ps[2] == String.class
                        && ps[3] == Runnable.class;
                if (!isToast && !isDialog && !isDialogZ) {
                    continue;
                }
                XposedBridge.hookMethod(m, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        // 文案匹配 license 失败类 → 丢弃。license 调用点均不消费返回值，
                        // 非 license 弹窗不会命中这些 app 专属文案，无误伤面。
                        for (Object a : param.args) {
                            if (a instanceof CharSequence && popupBlocked((CharSequence) a)) {
                                XposedBridge.log(TAG + ": popup suppressed: "
                                        + trunc(a, 60));
                                param.setResult(null);
                                return;
                            }
                        }
                    }
                });
                hits++;
            }
            if (hits > 0) {
                INSTALLED.put("a.js1.popupfilter", Boolean.TRUE);
                XposedBridge.log(TAG + ": popup filter hooked x" + hits);
            }
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": popup filter FAILED: " + t);
        }
    }

    /** 类名多候选版 tryHook：按顺序尝试每个 (class, method)，首个成功即止 */
    private static void tryAnyHook(ClassLoader cl, String[][] candidates,
                                   Class<?>[] sig, XC_MethodHook hook) {
        for (String[] c : candidates) {
            if (tryHook(cl, c[0], c[1], sig, hook)) {
                return;
            }
        }
        StringBuilder sb = new StringBuilder("hook [");
        for (int i = 0; i < candidates.length; i++) {
            if (i > 0) sb.append(' ');
            sb.append(candidates[i][0]).append('.').append(candidates[i][1]);
        }
        XposedBridge.log(TAG + ": " + sb.append("] FAILED: no candidate matched").toString());
    }

    /** 类名多候选版 tryHookByName：按名字+参数个数匹配 */
    private static void tryAnyHookByName(ClassLoader cl, String[][] candidates,
                                         int paramCount, XC_MethodHook hook) {
        for (String[] c : candidates) {
            if (tryHookByName(cl, c[0], c[1], paramCount, hook)) {
                return;
            }
        }
    }

    /** 按方法名+参数个数匹配（运行时参数类型如 a.d00 编译期不可见），命中返回 true */
    private static boolean tryHookByName(ClassLoader cl, String className, String methodName,
                                         int paramCount, XC_MethodHook hook) {
        String key = className + "." + methodName + "/" + paramCount;
        if (INSTALLED.containsKey(key)) {
            return true;
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
                return true;
            }
            XposedBridge.log(TAG + ": hook " + key + " NOT FOUND");
            return false;
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": hook " + key + " FAILED: " + t);
            return false;
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

    /** 精确签名 hook，命中返回 true（多候选遍历用） */
    private static boolean tryHook(ClassLoader cl, String className, String methodName,
                                   Class<?>[] sig, XC_MethodHook hook) {
        String key = className + "." + methodName;
        if (INSTALLED.containsKey(key)) {
            return true;
        }
        try {
            Class<?> c = XposedHelpers.findClass(className, cl);
            Method m = c.getDeclaredMethod(methodName, sig);
            XposedBridge.hookMethod(m, hook);
            INSTALLED.put(key, Boolean.TRUE);
            XposedBridge.log(TAG + ": hooked " + key);
            return true;
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": hook " + key + " FAILED: " + t);
            return false;
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
