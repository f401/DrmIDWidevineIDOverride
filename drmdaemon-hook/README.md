# drmdaemon-hook — 按应用改写 Widevine `deviceUniqueId`

Zygisk Next 模块。在 **vendor DRM HAL 进程**内 hook Widevine 的
`WVDrmPlugin::getPropertyByteArray`，让 `MediaDrm.getPropertyByteArray("deviceUniqueId")`
按调用方应用返回你配置的 **32 字节**值；配置修改**约 0.3 秒生效，无需重启服务或设备**。

实测环境：OnePlus 7T Pro / Android 12 / `android.hardware.drm@1.3-service.widevine`
（`libwvhidl.so` BuildId `06df5cf3292b46599094d2565e44b2f2`），Zygisk Next + KernelSU。

> 完整调试复盘（5 个 bug 的证据链、两份 tombstone 的反汇编定位）见
> [`docs/POSTMORTEM-investigation-log.md`](../../docs/POSTMORTEM-investigation-log.md)。

---

## 1. 原理

### 1.1 为什么挂在 vendor HAL 上

```
App: MediaDrm.getPropertyByteArray("deviceUniqueId")   ← PROPERTY_DEVICE_UNIQUE_ID
  → framework   DrmHal::getPropertyByteArray / getPropertyByteArrayInternal
  → Binder/HIDL IDrmPlugin::getPropertyByteArray
  → vendor      WVDrmPlugin::getPropertyByteArray()      ← libwvhidl.so，我们 hook 这里
```

`AMediaDrm_getPropertyByteArray`（NDK）是**应用进程内**的 API，注入 daemon 时无法 hook 它；
而在 vendor HAL 的返回值产生点替换，Java 与 native 两条路径会拿到同一份被改写的字节。

### 1.2 配置怎么进得去：Zygisk Next companion

HAL 进程的 SELinux 域是 `vendor_hal_drm_widevine`，**读不了 `/data`**
（目标目录带 MLS 类别 `c512,c768`，补 `allow` 也过不了）。所以不在 HAL 里做文件 I/O：

```
zygiskd (root)
  └── fork 出的 companion 进程（root，与模块同一个 .so）
        ├── 读 /data/adb/modules/drmdaemon-hook/config/targets.conf
        ├── inotify(文件+目录) + 300ms 内容哈希轮询      ← 变更检测（双保险）
        └── unix socket（长度前缀帧）────────────► HAL 进程
                                                     └── 换掉 hidl_vec<uint8_t>
```

- 注入侧线程 `api.connectCompanion()` 拿 fd，循环收表；**断线自动重连**。
- 规则是在 `getPropertyByteArray` **被调用时**查表的，而且记录了**所有** plugin 实例的包名
  ⇒ 新增规则对已经创建好的 `WVDrmPlugin` 立刻生效。
- companion 由 `zn_modules.txt` 的 `companion` 关键字声明（见 §3.1）。

### 1.3 hook 了哪些地址（libwvhidl.so）

| 符号 | 作用 | 注意 |
| --- | --- | --- |
| `WVDrmPlugin::C1` | 完整对象构造 | **由 `WVDrmFactory::createPlugin()` 调用**（全库唯一调用点），`x2` = 应用包名 |
| `WVDrmPlugin::C2` | 基类子对象构造 | **带隐藏 VTT 参数**（x1），`bool` 在 `w5` |
| `WVDrmPlugin::D2` | 基类子对象析构 | **带隐藏 VTT 参数**（x1）；`D1`/`D0`/各 thunk 都汇入 D2 |
| `getPropertyByteArray` | 返回值改写点 | 返回非平凡类型 `Return<void>` ⇒ **隐藏返回指针 x8** |

C++ 里 hook 方法必须按 ABI 处理三类隐藏项，否则就是「少传一个寄存器 → 野指针 → SIGSEGV」：

| 隐藏项 | 何时出现 | 不处理的后果 |
| --- | --- | --- |
| 间接返回指针 **x8** | 返回非平凡类型（`Return<void>`） | 被调用者往垃圾地址写返回对象 |
| **VTT 参数** | 类**有虚基类**时的 `C2`/`D2` | `ldr x8,[x1]` → `[0-24]`，fault `0xffffffffffffffe8` |
| **this 调整 thunk** | 多继承 / 虚基类 | 影响该挂哪个地址（我们选汇流点 D2）|

---

## 2. 构建

```bash
ANDROID_NDK=/path/to/android-ndk ./build.sh
```

脚本会编译 `src/main/cpp/hook.cpp`、保留未 strip 的副本（用于 `llvm-addr2line` 符号化），
并把 strip 后的产物装到 `template/lib/libdrmdaemon-hook.so`，最后做自检。

关键的链接参数（**不是可有可无**）：

| 参数 | 为什么必需 |
| --- | --- |
| `-static-libstdc++` | 目标进程没有 `libc++_shared.so`；产物若 NEEDED 它，Zygisk Next 的 dlopen 会**静默失败**（日志一行都没有）|
| `-Wl,-Bsymbolic-functions` + `-Wl,--exclude-libs,ALL` | 否则随包的静态 libc++ 成员以 **WEAK 导出**，库内调用全走 PLT；而 companion 进程（`zn-companion64`）不给这些 GOT 槽加 load bias，会跳到**链接期地址**崩溃 |
| `-Wl,-z,now` | 加载期完成重定位，不留惰性解析桩 |

自检应输出：

```text
arch OK / NEEDED: libdl.so liblog.so libm.so libc.so / BIND_NOW OK
export zn_module OK / zn_companion_module OK / zygisk_companion_entry OK
intra-lib PLT 0 (OK)
```

---

## 3. 安装

依赖：**支持 companion 的 Zygisk Next**（本模块用到 `ZygiskNextCompanionModule` /
`zn_companion_module`）、KernelSU 或 Magisk；目标 ROM 的 Widevine service 需在
`post-fs-data` 之后启动（标准 `class hal` 满足）。

1. 把 `template/` 打成 zip（`META-INF/`、`module.prop`、`lib/`、`webroot/`、`config/`、
   `post-fs-data.sh`、`zn_modules.txt`、`sepolicy.rule`、`action.sh` 都放在 zip 根）。
2. 从 KernelSU/Magisk 管理器安装，**重启**（`zn_modules.txt` 只在启动早期读一次）。
3. 在模块详情页点 **WebUI**（或执行模块的 Action）。

### 3.1 `zn_modules.txt`（关键）

```text
path=/odm/bin/hw/android.hardware.drm@1.3-service.widevine companion lib/libdrmdaemon-hook.so
path=/vendor/bin/hw/android.hardware.drm@1.3-service.widevine companion lib/libdrmdaemon-hook.so
name=android.hardware.drm@1.3-service.widevine companion lib/libdrmdaemon-hook.so
```

- `companion` 必须位于 target 与库路径**之间**（最后一个 token 必须是库路径）。
- 缺少 `companion`：模块仍会注入，但 `connectCompanion()` 失败 ⇒ 规则读不到（日志会明确报出来）。
- 声明了 `companion` 但库里没有 companion 入口：ZN 会**丢弃整条声明**（表现为完全不注入）。

### 3.2 `sepolicy.rule`

```text
allow vendor_hal_drm_widevine self:process execmem;
```

只需这一条（inline hook 需要可执行内存）。**不需要**任何 `/data` 文件权限 —— 读文件由
companion（root）负责。其它 ROM 若域不同，按 audit log 里的 `scontext` 改名。

---

## 4. 配置

文件：`/data/adb/modules/drmdaemon-hook/config/targets.conf`

```text
# v1|包名|deviceUniqueId|hex32|64 位十六进制(32 字节)
v1|com.example.player|deviceUniqueId|hex32|0000000000000000000000000000000000000000000000000000000000000000
```

- 第二列必须是 **HAL 实际看到的键**：看日志里 `WVDrmPlugin … created package=<X>`，
  把 `<X>` 原样填进去（本实现中它就是调用方应用包名，来自 `DrmHal::makeDrmPlugin` →
  `factory->createPlugin(uuid, appPackageName, …)`）。
- 第五列必须恰好 64 个十六进制字符；非法行会被忽略并打日志。
- WebUI 支持增删改、原始文本编辑、查看注入日志。**保存后约 0.3 秒生效**。

---

## 5. 验证

```bash
adb logcat -c && adb reboot
adb logcat -b all -d | grep drmdaemon-hook
```

期望（完整链路）：

```text
onModuleLoaded pid=.. boot_ms=..
companion client thread started (self=0x..)
HAL hooks ctor(C1)=installed ctor(C2)=installed dtor=installed getPropertyByteArray=installed
module ready: companion client started, N rule(s) loaded so far
companion loaded                                     ← 来自 companion 进程
companion connected fd=..                            ← HAL 侧
companion: client connected fd=..
companion: pushed 2xx bytes (hash=....) to fd=..     ← 首次下发
rules updated from companion: 1 rule(s) [com.example.player]
```

改一行配置后 0.3 秒内应再出现 **一条 hash 变化的 `pushed`** + `rules updated`；
真正查询时出现：

```text
replacement deviceUniqueId plugin=0x.. size=32 hex=<你配置的 64 位 hex>
```

---

## 6. 排错

| 症状 | 原因 | 处理 |
| --- | --- | --- |
| 日志里连 `onModuleLoaded` 都没有 | 模块没被注入 | 查 .so 能否 dlopen（NEEDED 不能有 `libc++_shared.so`）、`.dynsym` 是否有 `zn_module`/`zn_companion_module`、`zn_modules.txt` 里 `companion` 的位置、ZN 是否支持 companion |
| `HAL hooks … =failed` | 目标域没有 `execmem` | 按 audit log 的 `scontext` 改 `sepolicy.rule` |
| `loaded 0 rule(s)` / `no rule for package=X` | 规则键不对（或规则没下发） | 用 `created package=` 的值当第二列 |
| `connectCompanion failed (attempt N)` | 声明缺 `companion`，或库未导出 companion 入口 | 见 §3.1 |
| `companion: pushed` 只出现一次，改配置无反应 | 旧版本的 inotify 阻塞 bug（1.1.0 已修） | 升级到 1.1.0 |
| 首次能生效，之后某次查询变回原值 | 应用自身缓存了 ID / 绑定账号 | 清应用数据或重启该应用 |
| 播放时崩在 `libwvhidl.so` 内部 | `std::function` 回调跨 libc++ 边界的已知假设（§7） | 反馈并附 tombstone |

---

## 7. 限制与已知假设

- 只覆盖 **arm64** 的 widevine service；`/system/bin/drmserver`（32 位）与本模块无关。
- **不注入目标应用**（Java/NDK 两条路径都从 HAL 取值，所以无必要）。
- 只改 `deviceUniqueId`，不影响安全等级、license 校验。
- 已知假设：`getPropertyByteArray` 的 `std::function` 回调必须跨 libc++ 边界按值传递
  （DrmHal 侧是平台 libc++ `std::__1`，模块是 NDK libc++ `std::__ndk1`；布局一致时可用）。
  若将来在播放路径崩在 `libwvhidl.so` 内部，优先怀疑这里。
- companion 机制依赖 Zygisk Next 的实现（非 AOSP 标准），升级 ZN 后建议回归一次。

---

## 8. 目录结构与许可

```text
drmdaemon-hook/
├── build.sh                 构建 + 自检
├── src/main/cpp/hook.cpp    全部实现（注入侧 + companion 侧，单个 .so）
├── template/                模块打包模板（安装进 /data/adb/modules/drmdaemon-hook/）
│   ├── module.prop / zn_modules.txt / sepolicy.rule / post-fs-data.sh / action.sh
│   ├── config/targets.conf  默认规则
│   ├── lib/                 构建产物（由 build.sh 生成）
│   └── webroot/             KernelSU WebUI / MMRL / WebUI X
├── artifacts/               验证留痕
├── CHANGELOG.md
└── .gitignore
```

- 本仓库自写部分建议以 MIT 或 Apache-2.0 发布（自行选择并补 `LICENSE`）。
- **发布前请阅读 [`docs/RELEASE-CHECKLIST.md`](../../docs/RELEASE-CHECKLIST.md)**：
  其中列出了不应随仓库发布的第三方/专有文件（vendor 二进制、ZN 相关代码与二进制、
  设备 tombstone 等）。
- `src/main/cpp/zygisk_next_api.h` 来自 Zygisk Next 官方模块样例，仅供本模块按接口约定使用；
  Zygisk Next 自 v4-0.9.2 起为专有许可（禁止修改/再分发/提取），请按其条款处理。
