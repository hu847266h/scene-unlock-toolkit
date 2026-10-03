# Scene Unlock Toolkit

针对 **Scene（com.omarea.vtools，N1 2026.09 Alpha8 / 2026.10 Alpha10）** 本地会员激活链路的逆向研究工具包：一个 LSPosed 模块（改写激活裁决 + 自动化 daemon 内存热补丁）+ 一套 ptrace 注入工具链。适配魔改版 LSPosed 2.2.0（legacy 桥接）、MIUI + KernelSU 真机环境。

> **装好即用？** 完整安装/激活/排障说明见 **[使用教程 USAGE.md](USAGE.md)**；模块下载见 [Releases](https://github.com/hu847266h/scene-unlock-toolkit/releases/latest)。

> 模块 hook 表按「Alpha10 优先、Alpha8 兜底」多候选尝试，两个版本通用；daemon 补丁偏移与版本一一对应（Alpha8 / Alpha10 两套见下表），其他版本需按「偏移速查表」一节的方法重新定位。

## 背景

Scene 的会员激活不走纯客户端判定，而是四层链路：

```
ActivityStartSplash（选择运行方式）
        │  跳转被状态机拦截
        ▼
C0060b3  状态机（激活状态决定能否进主页）
        │  读取激活状态
        ▼
C0978zz  daemon 客户端（TCP 127.0.0.1:14754）
        │  activate / exec-shell / get-kernel-prop …
        ▼
scene-daemon  守护进程（UPX 壳，本地授权校验）
```

关键事实（实测）：

- daemon 由 App 通过 `files/up.sh` 拉起，运行态由 UPX stub 解到 `memfd:upx` 匿名映射执行，监听 **TCP 127.0.0.1:14754**（不是报告中写的 8788）。
- 授权校验完全本地，无外联。`activate` 返回 `expired` 时，所有 exec 类 action（`exec-shell` / `dumpsys` / `get-kernel-props` 等）一律返回空 —— 这就是「进了主页但全空」的直接原因。
- 魔改 LSPosed 2.2.0 **不注入 libxposed API 101 的 dex**，且 legacy 桥接的 `XposedBridge.hookMethod` 返回 `Unhook` 而非 `Object[]`。

因此解锁需要同时做两件事：**App 侧改写裁决**（LSP 模块）+ **daemon 侧打通数据通道**（内存热补丁）。二者缺一不可。

## 方案一：LSP 模块（lsposed-module/）

### 架构

```
app/src/main/java/com/hu/sceneunlock/
  MainHook.java        IXposedHookLoadPackage，5 个功能 hook + 4 个诊断探针
  DaemonPatcher.java   daemon 热补丁自动化（部署 assets → su 执行 repatch.sh）
stubs/                 手写 legacy Xposed 桩（XC_MethodHook / XposedBridge / …）
app/stubs/xposed-stubs.jar   compileOnly 依赖
```

### Hook 表（运行时混淆名，Alpha10 / Alpha8）

MainHook 按 `tryAnyHook` 多候选机制依次尝试，首个命中的类生效（混淆名随版本漂移，g/t/r/l、b/c 等成员名在两版间保持稳定，类名变了）：

| 功能 | Alpha10 | Alpha8 | Hook | 作用 |
|---|---|---|---|---|
| 裁决漏斗 | `a.s10.g(String)` | `a.zz.g(String)` | `DaemonVerdictHook` | 改写 daemon 裁决：`expired/invalid` → `success@4102444800000`（2100-01-01） |
| 工作模式闸 | `a.s10.t()` | `a.zz.t()` | `WorkingModeHook` | daemon 在线（`r()==true`）时强制返回 `root`（静态字段 `l` 两版同名） |
| 授权缓存 | `a.ns.a()` | `a.vq.a()` | `DaemonVerdictHook` | 同上（缓存 toString 的数据源，供状态机读取） |
| 激活状态机 | `a.a3.b(String)` / `c()` | `a.b3.b(String)` / `c()` | `StateModelHook` | 强制 `ActivatedStateModel` 为已激活/永久专业版（setter 未混淆，两版一致） |
| 诊断探针 | `a.s10.M/3`、`j/1` | `a.zz.M/3`、`j/1` | `DiagHook` | REQ / ENC 请求与加密日志，仅诊断用 |

### 踩坑记录（魔改 LSPosed 2.2.0 + MIUI）

1. **API 101 不可用**：魔改版不注入 API 101 dex，`implement IXposedHookLoadPackage`（legacy）才能被加载。`AndroidManifest` 的 `xposedminversion` 必须写 legacy 值。
2. **`hookMethod` 签名**：legacy 桩必须 `public static Unhook hookMethod(Member, XC_MethodHook)`；返回 `Object[]` 会静默失败。且缺 `findAndHookMethod` 变体 → 用 `findClass + getDeclaredMethod + hookMethod` 组合。
3. **首屏点击不跳转**：根因是模块写日志到 `files/` 时 `EACCES`（目录属主不对）。修复：`su -c "chown -R 10449:10449 /data/user/0/com.omarea.vtools/files"`。
4. **daemon 起不来**：`files/up.sh` 需要 toolkit 在 PATH 且 busybox 有 applet 符号链接（`sh install_busybox.sh`）。

## 方案二：scene-daemon 内存热补丁（daemon-patch/）

### 为什么不做文件级补丁

- UPX magic 被魔改（尾部自定义段表标记），`upx -d` 拒绝解壳。
- 手工 dump + 重建 ELF 的路线失败：运行态 dump 混入已初始化的脏全局/指针，重建出的 ELF（无论是否打补丁）启动即 100% CPU 死循环、不监听端口。
- `/proc/pid/mem` 写入被 MIUI 内核 anti-debug 拦截（`EIO`，`setenforce 0` 也无效，无 yama，dmesg 无 AVC）。
- `map_files/` 对 MAP_SHARED memfd 写入**可写**，但只更新内存，**icache 不同步**（回读是新字节、执行还是旧指令）—— 对照实验（改字符串引用 `#0x4b4→#0x4ad`）确认了这一点。

最终方案：**map_files 写补丁字节 + ptrace 注入执行 icache 失效指令**（`dc cvau` / `ic ivau` / `dsb ish`），由内核路径保证一致性。

### 补丁点（memfd 内偏移 = vaddr − 0x2CA000）

| 偏移 | vaddr | 原始字节 | 补丁字节 | 含义 |
|---|---|---|---|---|
**N1 Alpha8**（memfd text 0x2AD000 = 2805760 B，memfd 偏移 = vaddr − 0x2CA000）：

| memfd 偏移 | vaddr | 原始字节 | 补丁字节 | 含义 |
|---|---|---|---|---|
| `0x1e562c` | `0x4af62c` | `ad030054` (`b.le`) | `1f2003d5` (`nop`) | Function A：校验剩余时长 ≤0 跳 expired，放行让 success 路径接管 |
| `0x1ee6e4` | `0x4b86e4` | `ec000054` (`b.gt`) | `07000014` (`b +28`) | Function B：强制走 success 分支 |
| `0x1ee6ec` | `0x4b86ec` | `00d01291` (`add x0,x0,#0x4b4`) | `00b41291` (`#0x4ad`) | expired 字符串引用 → invalid（对照实验遗留，兼作兜底） |
| `0x2acf00` | `0x576f00` | 全零（3KB 空白区） | 48B shellcode | icache 失效 stub，`mov x4, xzr; b .` 为完成标志 |

**N1 Alpha10**（memfd text 0x2B9000 = 2854912 B；daemon 有 stub + text 两个 memfd 映射，repatch v4 自动选最大 r-xs 段；SITE3 免除——模块侧改写裁决后字符串兜底无意义）：

| memfd 偏移 | 原始字节 | 补丁字节 | 含义 |
|---|---|---|---|
| `0x1e554c` | `ad030054` (`b.le`) | `1f2003d5` (`nop`) | Function A：同上，`bl 0x1e3a10`（有效期解析）后 `cmp x0,#0; b.le` 跳失败路径 |
| `0x1e3b40` | `ac000054` (`b.gt +20`) | `05000014` (`b +20`) | Function B：强制走 success 返回（解析出的时间戳，`success@<ts>`） |
| `0x2b8938` | 全零（1736B 空白区） | 48B shellcode | icache 失效 stub，同 Alpha8 |

裁决字符串 vaddr：`invalid=0xc04ad`、`expired=0xc04b4`、`not-you=0xc04bb`、`success@=0xc0fc0`（LOAD1 rodata）。

icache shellcode（keystone 汇编，x0..x3 为待刷新地址）：

```asm
dc cvau, x0 ; ic ivau, x0
dc cvau, x1 ; ic ivau, x1
dc cvau, x2 ; ic ivau, x2
dc cvau, x3 ; ic ivau, x3
dsb ish
isb
mov x4, xzr
b .
```

### mempoke2（ptrace 注入器）

`PTRACE_ATTACH` → `GETREGSET(NT_PRSTATUS)` 保存现场 → `SETREGS` 把 PC 指到 shellcode、x0..x3 传刷新地址 → `PTRACE_CONT` → 轮询 `x4==0` → 恢复现场 → `PTRACE_DETACH` + `SIGCONT`。

- 新版会**逐线程尝试**：主线程可能阻塞在 syscall（PC 改了也不会执行），优先挑 PC 已落在代码段内的空闲线程。
- NDK 25 静态编译产物的 `PT_TLS p_align=8` 会被 MIUI bionic loader 拒载（`library ... has invalid TLS segment`）—— 二进制补丁把 `p_align` 改成 64 即可（见仓库内说明）。

### repatch.sh

一键重打：自动探测 daemon pid 与 memfd 基址 → 基线 diff 校验（>400 字节差异视为 Scene 更新了 daemon，中止防写坏）→ 全量覆写补丁快照 → 逐线程 ptrace 注入刷新 icache → `SIGCONT` 恢复 → 检查 14754。

## 自动化：DaemonPatcher

模块内置自动化，正常使用**无需手动敲命令**：

- 触发 ①：宿主 `Application.attach` 后启动 worker，最多等 60s 到 daemon 被拉起；
- 触发 ②：`DaemonVerdictHook` 观察到 `expired/invalid`（说明 daemon 换了新进程没补丁）；
- 两次触发共享 60s 冷却 + 单飞锁，幂等；工具三件套从 APK `assets/scene_patch/` 释放到 `/data/local/tmp/scene_patch/` 后经 `su` 执行。

## 使用

```bash
# 0) 前置：KernelSU/root、LSPosed（魔改 2.2.0 legacy 可用）、无线调试或 USB
# 1) 修复 files 目录属主（首屏 EACCES 时）
adb shell "su -c 'chown -R 10449:10449 /data/user/0/com.omarea.vtools/files'"
# 2) 构建 APK（stubs 先编 jar，或直接 assemble）
./gradlew :app:assembleRelease
# 3) 安装并在 LSPosed 勾选模块 + 作用域 com.omarea.vtools，重启系统界面
adb install -r app/build/outputs/apk/release/app-release.apk
# 4) 打开 Scene → 激活流程自动完成；daemon 重启后模块会自动重打补丁

# 手动重打（模块自动化异常时的兜底）
adb shell "su -c 'sh /data/local/tmp/scene_patch/repatch.sh'"
```

## 偏移速查表（换版本重新定位的方法）

1. `ps -A | grep scene-daemon` 找 pid，`SIGSTOP` 后 `cat /proc/pid/map_files/<memfd区间> > dump.bin` 拿干净 text（Alpha8 为 0x2AD000、Alpha10 为 0x2B9000，延迟 ≤60ms 防止调度写脏页）。**注意 Alpha10 起 daemon 有 stub（8KB）+ text（2.9MB）两个 r-xs memfd 映射，必须选最大的那段**。
2. 在 dump 里 `find "expired\x00"` 等裁决字符串 → 得到 vaddr（全 dump 坐标 − LOAD 偏移）。
3. 扫描 text 段 ADRP+ADD 对引用这些字符串的代码（参考仓库外脚本，或用 capstone 反汇编函数边界）。
4. 用 capstone 读出裁决分支（`cmp x0,#0` + `b.le/b.gt`）与 `add x0,x0,#imm` 字符串引用，即可填出上表 4 个偏移。
5. memfd 偏移 = vaddr − 0x2CA000（LOAD2 的 vaddr/文件差，从 program header 算）。

## 已知限制

- daemon 每次重启（App 冷启、重启手机）补丁失效，模块自动化会重打；若自动化失败用手动命令兜底。
- Scene 更新 daemon 二进制后偏移漂移，repatch 的基线 diff 会拒绝执行，需按速查表重新定位。
- 裁决显示 `success@-1` 属预期（Function A 的返回值未伪造时间戳，由模块侧改写为 2100-01-01）。

## 目录结构

```
lsposed-module/     LSP 模块源码（含 legacy Xposed 桩、内嵌补丁资产）
daemon-patch/       mempoke2.c（ptrace 注入器源码）+ repatch.sh + 构建说明
LICENSE             MIT
```

## License

MIT
