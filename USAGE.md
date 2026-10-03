# SceneUnlockLSP 使用教程

> Scene 工具箱（com.omarea.vtools）专业版解锁模块 —— 安装即用，激活全自动。

## 目录

- [支持版本](#支持版本)
- [环境要求](#环境要求)
- [安装步骤](#安装步骤)
- [激活流程（自动）](#激活流程自动)
- [验证是否成功](#验证是否成功)
- [升级 Scene 之后必须做的一件事](#升级-scene-之后必须做的一件事)
- [常见问题排查](#常见问题排查)
- [手动兜底操作](#手动兜底操作)
- [卸载](#卸载)
- [工作原理（一图流）](#工作原理一图流)

---

## 支持版本

| Scene 版本 | 支持情况 | 说明 |
|---|---|---|
| N1 2026.10 Alpha10 | ✅ 原生支持 | hook 表 + daemon 补丁偏移均适配 |
| N1 2026.09 Alpha8 | ✅ 兼容支持 | 多候选 hook 表自动回退到旧类名 |
| 其他版本 | ⚠️ 未适配 | 见[常见问题排查](#常见问题排查)第 6/7 条 |

## 环境要求

1. **已 root 的安卓真机**：KernelSU 或 Magisk 均可（模块通过宿主 App 自身的 `su` 通道执行补丁脚本，与 root 方案无关）
2. **LSPosed 已安装并激活**：魔改版 2.2.0（legacy 桥接）与官方版均可——模块使用 legacy Xposed API（`IXposedHookLoadPackage`），兼容性最好
3. **Scene 工具箱已安装**：即本模块的作用域目标 `com.omarea.vtools`

## 安装步骤

### 1. 下载模块

从 [GitHub Releases](https://github.com/hu847266h/scene-unlock-toolkit/releases/latest) 下载 `SceneUnlockLSP-vX.Y.apk`。

校验（可选）：

```bash
certutil -hashfile SceneUnlockLSP-v1.4-alpha10.apk SHA256
# 对照 Release 页说明中的 SHA256 值
```

### 2. 安装

正常安装 APK（未知来源按系统提示放行即可）。

### 3. 在 LSPosed 中启用

1. 打开 **LSPosed 管理器 → 模块**
2. 找到 **SceneUnlockLSP**，打开开关
3. 进入模块**作用域**，勾选 **Scene工具箱（com.omarea.vtools）**
4. 如管理器提示"需要重启系统界面"，照做即可

### 4. 完成

无需任何配置。模块没有界面，所有激活逻辑在 Scene 进程内自动完成。

## 激活流程（自动）

打开 Scene 的那一刻，以下链条全自动执行，无需手动干预：

```
打开 Scene
   │
   ├─① LSPosed 注入模块 → 7 个 hook 挂载
   │     裁决改写：expired/invalid → success@4102444800000（2100-01-01）
   │     工作模式强制 root（daemon 在线时）
   │
   ├─② DaemonPatcher 启动（Application.attach 触发）
   │     从模块 APK 释放三件套到 /data/local/tmp/scene_patch/
   │     （memfd_patched.bin + mempoke2 + repatch.sh）
   │
   ├─③ 等 daemon 被 Scene 拉起（最多等 60s）
   │     执行 repatch.sh：
   │       找 daemon 进程 → 定位 memfd 代码段 → 基线校验
   │       → 写入补丁字节 → ptrace 注入刷新 icache
   │
   └─④ 激活通过 → 进入主页，数据全部实时渲染
```

- 两次触发共享 **60s 冷却**，幂等可反复执行，不会重复打补丁
- daemon 每次重启（App 冷启、重启手机）补丁会失效，模块检测到未补丁裁决会**自动重打**

## 验证是否成功

| 检查点 | 预期表现 |
|---|---|
| Scene「用户」页 | 黄色徽标 **专业版（永久）**，**有效期至 2099-12-31** |
| Scene「概览」页 | 内存 / 交换 / GPU / CPU / 电池全部真实数据（非空白或 0） |
| 「调节」页功能 | 可正常进入，无功能门禁拦截 |

## 升级 Scene 之后必须做的一件事

**每次升级（重装）Scene 后，先强停一次再打开：**

```bash
adb shell am force-stop com.omarea.vtools
# 然后正常点开 Scene
```

原因：LSPosed 只在**新 fork 的进程**里注入。升级后系统可能会恢复/保活旧进程，旧进程不会被注入，就会卡在激活页。冷启动一次即可恢复，模块配置无需任何改动。

> 重启手机同理：开机后第一次打开 Scene 前若已存在残留进程，强停一次即可。

## 常见问题排查

**1. Scene 首屏"选择运行方式"点击无反应 / 闪退**

模块写日志到 `files/` 目录时属主不对（常见于全新安装）。修复：

```bash
adb shell "su -c 'chown -R $(stat -c %u:%g /data/user/0/com.omarea.vtools) /data/user/0/com.omarea.vtools/files'"
```

**2. logcat 里完全没有 `SceneUnlock` 日志**

模块没被注入。依次检查：

```bash
# ① 确认作用域勾选
# LSPosed 管理器 → 模块 → SceneUnlockLSP → 作用域含 com.omarea.vtools

# ② 强停 Scene 再冷启动（90% 的情况到这一步就好了）
adb shell am force-stop com.omarea.vtools

# ③ 看注入日志
adb shell "logcat -c; am start -n com.omarea.vtools/.activities.ActivityStartSplash; sleep 8; logcat -d | grep -a SceneUnlock"
```

**3. 日志出现 `hook a.s10.g FAILED: NoSuchMethodException` 之类**

Scene 又更新了、混淆类名漂移。模块会自动尝试所有已知候选名（Alpha10/Alpha8），全部失败才报错。此时需要为新版本重定位类名，见仓库 README「Hook 表」一节的锚点方法（搜 `success@` / `14754` / `setActivated`）。

**4. 日志出现 `[patcher] memfd size unexpected` 或 `baseline check` 报 abort**

Scene 更新了 daemon 二进制，旧偏移被基线保护正确拒绝（**这是保护机制，不是故障**）。需按 README「偏移速查表」重新定位补丁点。在重定位完成前，可临时手动跳过：不做 daemon 补丁时模块仍会改写激活裁决（能进主页），但 exec 类数据（CPU/内存监测等）会为空。

**5. `14754 not listening` 提示**

daemon 空闲态本来就不监听，**属正常现象**。打开 Scene 唤醒即可，无需处理。

**6. 主页进去了但卡片全空**

daemon 未打补丁（exec 类 action 返回空）。看 `[patcher] repatch output:` 日志定位失败原因；或手动兜底（见下节）。

**7. 提示需要激活码 / 卡激活页**

基本就是第 2 条（模块未注入）。强停冷启动。

## 手动兜底操作

模块自动化异常时，可手动执行补丁（工具三件套已在 `/data/local/tmp/scene_patch/`）：

```bash
# 确认 daemon 在跑
adb shell "su -c 'ps -A | grep scene-daemon'"

# 手动重打补丁
adb shell "su -c 'sh /data/local/tmp/scene_patch/repatch.sh'"
# 预期输出：[+] patch applied (icache flushed)

# 补丁后强停并冷启动 Scene
adb shell am force-stop com.omarea.vtools
adb shell am start -n com.omarea.vtools/.activities.ActivityStartSplash
```

诊断日志一键抓取：

```bash
adb shell "logcat -d | grep -aE 'SceneUnlock' | tail -50"
```

关键字段：`hooks 7 (+7)`（hook 全装）、`working mode -> root`（模式闸生效）、
`REQ id=success@... action=activate`（裁决已过）、`[patcher] repatch output: ... patch applied`（daemon 已补丁）。

## 卸载

1. LSPosed 管理器中关闭并卸载本模块
2. 强停 Scene（daemon 重启后内存补丁自然失效）
3. 可选清理：`adb shell "su -c 'rm -rf /data/local/tmp/scene_patch'"`

模块不写入任何 Scene 配置、不修改 Scene APK 与数据，卸载即完全还原。

## 工作原理（一图流）

```
┌─────────────────────────── Scene App 进程 ───────────────────────────┐
│                                                                      │
│  a.s10.g(String) ◄── hook：裁决漏斗改写（expired → success@2100）     │
│  a.s10.t()       ◄── hook：工作模式强制 root                          │
│  a.ns.a()        ◄── hook：授权缓存同步改写                           │
│  a.a3.b()/c()    ◄── hook：状态机强制 已激活/永久专业版                │
│                                                                      │
│  DaemonPatcher ── su ──► repatch.sh ──► mempoke2 (ptrace)            │
└──────────────────────────────────┬───────────────────────────────────┘
                                   │ TCP 127.0.0.1:14754
                    ┌──────────────▼──────────────┐
                    │       scene-daemon           │
                    │  内存热补丁（3 处授权分支）   │
                    │  → activate 返回 success     │
                    │  → exec 类 action 返回数据   │
                    └─────────────────────────────┘
```

模块只改写本机内存中的裁决结果，**不伪造服务端凭证、不修改 Scene APK、不写激活配置**——
因此升级 Scene 或重启设备后一切可自愈。详细逆向报告见 [README](README.md)。
