package com.hu.sceneunlock;

import android.content.Context;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

/**
 * scene-daemon 内存热补丁自动化。
 *
 * 背景：Scene 的本地授权校验在守护进程 scene-daemon 内（UPX 壳，arm64 PIE）。
 * 校验函数共 3 处分支决定 activate 裁决与 exec 类 action 是否返回数据。
 * 本类在宿主（Scene）进程内借助宿主自身已授权的 root 通道（su），对运行中的
 * daemon 做 MAP_SHARED memfd 写补丁 + ptrace 注入刷新 icache：
 *
 *   memfd 0x1e562c  b.le -> nop        (Function A 授权分支放行)
 *   memfd 0x1ee6e4  b.gt -> b          (Function B 强制走 success 路径)
 *   memfd 0x1ee6ec  ADD #0x4b4 -> #0x4ad (expired -> invalid 兜底)
 *
 * 工具链三个文件打进模块 APK assets/scene_patch/：
 *   memfd_patched.bin  已补丁 daemon 代码段全量快照 (0x2AD000, Scene N1 Alpha8)
 *   mempoke2           静态 ptrace 注入器 (arm64, TLS 对齐已修复)
 *   repatch.sh         一键重打脚本 (自动探测 pid/基址, 逐线程注入, 版本 diff 校验)
 *
 * 触发时机：
 *   1. Application.attach 后启动 worker，最多等 60s 直到 daemon 被拉起
 *   2. DaemonVerdictHook 观察到 expired/invalid 裁决时（daemon 换新进程未打补丁）
 * 两次触发共享 60s 冷却与单飞锁，幂等可反复执行。
 */
public final class DaemonPatcher {

    private static final String TAG = "SceneUnlock";
    private static final String ASSET_DIR = "assets/scene_patch/";
    private static final String[] ASSETS = {"repatch.sh", "mempoke2", "memfd_patched.bin"};
    private static final String PATCH_DIR = "/data/local/tmp/scene_patch";
    private static final long COOLDOWN_MS = 60_000L;

    private static final AtomicBoolean sBusy = new AtomicBoolean(false);
    private static volatile long sLastAttempt = 0L;
    private static volatile Context sContext;
    private static volatile String sApkPath;

    private DaemonPatcher() {
    }

    /** Application.attach 时回调（主进程） */
    public static void onAttach(Context ctx) {
        if (sContext == null) {
            sContext = ctx;
            Thread w = new Thread(new Runnable() {
                @Override
                public void run() {
                    // App 启动后数秒内才会拉起 daemon，轮询等待
                    for (int i = 0; i < 30; i++) {
                        if (isDaemonRunning()) {
                            requestPatch("worker: daemon detected");
                            return;
                        }
                        try {
                            Thread.sleep(2000L);
                        } catch (InterruptedException e) {
                            return;
                        }
                    }
                    log("worker: daemon not seen in 60s, idle");
                }
            }, "SceneUnlock-PatchWorker");
            w.setDaemon(true);
            w.start();
        }
    }

    /** DaemonVerdictHook 观察到未打补丁的裁决时回调 */
    public static void onVerdict(String verdict) {
        if ("expired".equals(verdict) || "invalid".equals(verdict) || "not-you".equals(verdict)) {
            requestPatch("verdict=" + verdict);
        }
    }

    public static void requestPatch(String why) {
        if (sBusy.get()) {
            log("patch request ignored (busy): " + why);
            return;
        }
        long now = System.currentTimeMillis();
        if (sLastAttempt != 0 && now - sLastAttempt < COOLDOWN_MS) {
            log("patch request ignored (cooldown): " + why);
            return;
        }
        if (ensureContext() == null) {
            // Context 未就绪不消耗冷却，Application.attach 后 worker 会重试
            log("patch deferred (no context yet): " + why);
            return;
        }
        sLastAttempt = now;
        if (!sBusy.compareAndSet(false, true)) {
            return;
        }
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    patchNow();
                } catch (Throwable t) {
                    log("patch FAILED: " + t);
                } finally {
                    sBusy.set(false);
                }
            }
        }, "SceneUnlock-Patch");
        t.start();
    }

    /** sContext 未就绪时用 ActivityThread.currentApplication() 兜底 */
    private static Context ensureContext() {
        if (sContext != null) {
            return sContext;
        }
        try {
            Object ctx = Class.forName("android.app.ActivityThread")
                    .getMethod("currentApplication").invoke(null);
            if (ctx instanceof Context) {
                sContext = (Context) ctx;
                log("context resolved via ActivityThread");
            }
        } catch (Throwable t) {
            log("context fallback failed: " + t);
        }
        return sContext;
    }

    private static void patchNow() throws Exception {
        Context ctx = ensureContext();
        if (ctx == null) {
            log("patch aborted: no context");
            return;
        }
        if (!isDaemonRunning()) {
            log("patch: daemon not running, skip");
            return;
        }
        File cache = extractAssets(ctx);
        if (cache == null) {
            log("patch: asset extraction failed");
            return;
        }
        String cmd = "mkdir -p " + PATCH_DIR
                + " && cp -f " + cache.getAbsolutePath() + "/* " + PATCH_DIR + "/"
                + " && chmod 700 " + PATCH_DIR + "/mempoke2"
                + " && sh " + PATCH_DIR + "/repatch.sh 2>&1";
        String out = execSu(cmd, 60);
        log("repatch output:\n" + (out == null ? "(no output)" : out.trim()));
    }

    /** 从模块 APK 释放 assets/scene_patch/* 到宿主 cacheDir/sp/ */
    private static File extractAssets(Context ctx) throws Exception {
        String apk = findModuleApk();
        if (apk == null) {
            log("extract: module apk path not found");
            return null;
        }
        File outDir = new File(ctx.getCacheDir(), "sp");
        outDir.mkdirs();
        ZipInputStream zin = new ZipInputStream(new FileInputStream(apk));
        try {
            int count = 0;
            ZipEntry e;
            byte[] buf = new byte[65536];
            while ((e = zin.getNextEntry()) != null) {
                String name = e.getName();
                if (!name.startsWith(ASSET_DIR) || e.isDirectory()) {
                    continue;
                }
                String base = name.substring(ASSET_DIR.length());
                if (base.contains("/")) {
                    continue;
                }
                File fo = new File(outDir, base);
                OutputStream os = new FileOutputStream(fo);
                try {
                    int n;
                    while ((n = zin.read(buf)) > 0) {
                        os.write(buf, 0, n);
                    }
                } finally {
                    os.close();
                }
                count++;
            }
            log("extracted " + count + " patch files from " + apk);
            return count == ASSETS.length ? outDir : null;
        } finally {
            zin.close();
        }
    }

    /** 模块 APK 路径：优先 PackageManager.sourceDir（系统公开 API，最可靠），
     *  失败再退回 DexPathList 反射（LSPosed 内存加载模块 dex 时会失败） */
    private static String findModuleApk() {
        if (sApkPath != null) {
            return sApkPath;
        }
        Context ctx = ensureContext();
        if (ctx != null) {
            try {
                Object info = ctx.getPackageManager()
                        .getApplicationInfo("com.hu.sceneunlock", 0);
                String src = (String) info.getClass().getField("sourceDir").get(info);
                if (src != null && src.endsWith(".apk")) {
                    sApkPath = src;
                    log("module apk via PM: " + src);
                    return src;
                }
            } catch (Throwable t) {
                log("PM lookup failed: " + t);
            }
        }
        try {
            Object pathList = XposedHelpers.getObjectField(
                    MainHook.class.getClassLoader(), "pathList");
            Object[] elements = (Object[]) XposedHelpers.getObjectField(pathList, "dexElements");
            for (Object e : elements) {
                try {
                    Object dex = XposedHelpers.getObjectField(e, "dexFile");
                    if (dex != null) {
                        String f = XposedHelpers.getStringField(dex, "mFileName");
                        if (f != null && f.endsWith(".apk")) {
                            sApkPath = f;
                            return f;
                        }
                    }
                } catch (Throwable ignored) {
                }
                try {
                    Object p = XposedHelpers.getObjectField(e, "path");
                    if (p instanceof String && ((String) p).endsWith(".apk")) {
                        sApkPath = (String) p;
                        return sApkPath;
                    }
                    if (p instanceof File && p.toString().endsWith(".apk")) {
                        sApkPath = p.toString();
                        return sApkPath;
                    }
                } catch (Throwable ignored) {
                }
            }
        } catch (Throwable t) {
            log("findModuleApk: " + t);
        }
        return null;
    }

    private static boolean isDaemonRunning() {
        String out = execSu("pgrep -o scene-daemon", 5);
        return out != null && out.trim().matches("\\d+");
    }

    /** 通过宿主已授权的 su 通道执行命令（KernelSU/Magisk 通用） */
    private static String execSu(String cmd, int timeoutSec) {
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"su", "-c", cmd});
            StringBuilder sb = new StringBuilder();
            InputStream in = p.getInputStream();
            byte[] buf = new byte[4096];
            long deadline = System.currentTimeMillis() + timeoutSec * 1000L;
            while (System.currentTimeMillis() < deadline) {
                while (in.available() > 0) {
                    int n = in.read(buf);
                    if (n < 0) {
                        break;
                    }
                    sb.append(new String(buf, 0, n));
                }
                try {
                    int rc = p.exitValue();
                    // 收尾再读一次
                    while (in.available() > 0) {
                        int n = in.read(buf);
                        if (n < 0) {
                            break;
                        }
                        sb.append(new String(buf, 0, n));
                    }
                    log("su rc=" + rc);
                    return sb.toString();
                } catch (IllegalThreadStateException notYet) {
                    Thread.sleep(200L);
                }
            }
            p.destroy();
            log("su timeout after " + timeoutSec + "s");
            return sb.length() > 0 ? sb.toString() : null;
        } catch (Throwable t) {
            log("execSu failed: " + t);
            return null;
        }
    }

    private static void log(String s) {
        XposedBridge.log(TAG + ": [patcher] " + s);
    }
}
