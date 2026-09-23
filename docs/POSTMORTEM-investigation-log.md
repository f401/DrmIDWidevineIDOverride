# 调试复盘：Widevine `deviceUniqueId` 改写（证据链）

> 本文是开发过程的原始复盘，按时间顺序记录每一次失败的现象、tombstone 定位、
> 反汇编证据与最终修复。面向「想了解为什么这么写」的读者；
> 想直接安装使用请看 [`drmdaemon-hook/README.md`](../drmdaemon-hook/README.md)，
> 想看版本级的结论看 [`drmdaemon-hook/CHANGELOG.md`](../drmdaemon-hook/CHANGELOG.md)，
> 4 次崩溃的原始 tombstone 与对照表见 [`tombstones/README.md`](tombstones/README.md)。

# DRM daemon `deviceUniqueId` hook (Zygisk Next)

## AOSP Android 12 chain verification

AOSP Android 12 source was fetched from `frameworks/av` and saved under `aosp-src/` for inspection. The relevant source is `aosp-src/DrmHal.cpp`:

```cpp
constexpr char kPropertyDeviceUniqueId[] = "deviceUniqueId";

status_t DrmHal::getPropertyByteArray(String8 const &name,
                                       Vector<uint8_t> &value) const {
    Mutex::Autolock autoLock(mLock);
    return getPropertyByteArrayInternal(name, value);
}

status_t DrmHal::getPropertyByteArrayInternal(String8 const &name,
                                               Vector<uint8_t> &value) const {
    Return<void> hResult = mPlugin->getPropertyByteArray(
        toHidlString(name), [&](Status status, const hidl_vec<uint8_t>& hValue) {
            if (status == Status::OK) value = toVector(hValue);
        });
    if (name == kPropertyDeviceUniqueId) {
        mMetrics.mGetDeviceUniqueIdCounter.Increment(err);
    }
    return err;
}
```

This verifies the actual chain:

```text
MediaDrm.getPropertyByteArray("deviceUniqueId")
  -> framework DrmHal::getPropertyByteArray
  -> DrmHal::getPropertyByteArrayInternal
  -> HIDL IDrmPlugin::getPropertyByteArray
  -> vendor Widevine implementation
```

`PROPERTY_DEVICE_UNIQUE_ID` is the MediaDrm API constant name. The actual key sent through HIDL is the literal **`deviceUniqueId`**. The returned value is a byte vector (`hidl_vec<uint8_t>` / `Vector<uint8_t>`), not a string and not a system property.

The module hooks the vendor `WVDrmPlugin::getPropertyByteArray` implementation in `libwvhidl.so` and replaces the HIDL callback vector only when the incoming key is exactly `deviceUniqueId`.

## Injected processes

`process.txt` identifies:

```text
/system/bin/drmserver
/vendor/bin/hw/android.hardware.drm@1.3-service.clearkey
/odm/bin/hw/android.hardware.drm@1.3-service.widevine
```

`template/zn_modules.txt` targets these processes. The hook is daemon-side; target applications are not injected.

## Local ELF evidence

```text
readelf -h drmserver
  Class: ELF32
  Machine: ARM

readelf -r drmserver | grep property_get_int64
0000cb7c R_ARM_JUMP_SLOT property_get_int64
```

That relocation is unrelated to the MediaDrm byte-array path and is not hooked. The supplied `libdrmframework*.so` files expose legacy `DrmEngineBase` symbols but do not contain the HIDL `deviceUniqueId` implementation. The actual implementation is in the vendor Widevine HIDL/plugin library loaded by `drmserver`; the module resolves the `getPropertyByteArray` ABI at runtime instead of using a guessed offset.

## `hidl_string` 参数确认

`WVDrmPlugin::getPropertyByteArray` 的第一个参数确实是：

```cpp
const android::hardware::hidl_string& name
```

AOSP Android 12 `HidlSupport.h` 定义了：

```cpp
struct hidl_string {
    details::hidl_pointer<const char> mBuffer;
    uint32_t mSize;  // NOT including the terminating '\\0'
    bool mOwnsBuffer;
};
```

因此 Hook 不使用 `strlen`、`strcmp` 或任何 NUL 终止假设，而是按长度进行匹配：

```cpp
name.buffer != nullptr &&
name.size == sizeof("deviceUniqueId") - 1 &&
memcmp(name.buffer, "deviceUniqueId", sizeof("deviceUniqueId") - 1) == 0
```

这可以正确处理没有尾部 `\0` 的 HIDL 字符串。`HidlString` 的本地布局对应 AOSP 的 8 字节 `hidl_pointer`、`uint32_t` 长度、`bool` 所有权标志和 3 字节填充。

## Configuration

The HAL returns a byte array. The module uses a strict fixed-width 32-byte representation to prevent accidental ASCII/UTF-8 IDs:

```text
v1|package-or-uid|deviceUniqueId|hex32|64-hex-characters
```

Example:

```text
v1|com.example.player|deviceUniqueId|hex32|0000000000000000000000000000000000000000000000000000000000000000
```

字段说明：`v1` 为格式版本；第二列是包名或 UID；第三列固定为实际 HIDL key `deviceUniqueId`；第四列固定为 `hex32`；第五列必须是恰好 64 个十六进制字符（32 字节）。大小写均可，解析后按原始二进制字节写入 `hidl_vec<uint8_t>`；长度错误或含非十六进制字符的行会被拒绝并记录日志。

配置文件路径：`/data/adb/modules/drmdaemon-hook/config/targets.conf`。注意该文件**不由 HAL 进程读取**，而是由 Zygisk Next companion 进程（root daemon 的子进程）读取后经 unix socket 下发，详见下文「配置下发：Zygisk Next companion」。

## 配置下发：Zygisk Next companion（解决 loaded 0 rule(s) 与免重启）

### 故障现象

设备日志出现：

```text
drmdaemon-hook: loaded 0 deviceUniqueId rule(s)
```

并伴随：

```text
avc: denied { search } for name="data" dev="dm-35"
  scontext=u:r:vendor_hal_drm_widevine:s0
  tcontext=u:object_r:system_data_file:s0:c512,c768 tclass=dir permissive=0
```

原因有两个，都属于设计问题而不是配置问题：

1. **域写错了。** 模块原本的 `sepolicy.rule` 写的是 AOSP 的 `hal_drm`，但设备实际域是 `vendor_hal_drm_widevine`。因此 `execmem` 从未放行，inline hook 也没装成功。
2. **HAL 进程本来就无法读取 /data。** 要 `search` 的目录是 `system_data_file:s0:c512,c768`，带 MLS 类别；`s0` 的 subject 不支配 `c512,c768`，所以即使补上 `allow ... system_data_file:dir search` 仍会被 MLS 约束拒绝。`std::ifstream` 以 `EACCES` 失败，规则数自然是 0。

### 修复：让 root 侧去读文件

不要给 DRM HAL 开放 `/data`（那等于把整个数据分区交给它），而是使用 Zygisk Next 的 **companion** 机制：

```text
zygiskd（root daemon）
  └── fork 出的 companion 进程（同域、root 权限）
        ├── 读 /data/adb/modules/drmdaemon-hook/config/targets.conf   ← 允许
        ├── 解析成规则表
        └── unix socket ─────────────►  HAL 进程（vendor_hal_drm_widevine）
                                         └── 应用规则，改写 hidl_vec<uint8_t>
```

要点：

- companion 与模块是**同一个 .so**：文件同时导出 `zn_module`（注入 HAL）与 `zn_companion_module`（在 companion 进程里执行），后者由 `zn_modules.txt` 的 `companion` 关键字声明：

  ```text
  path=/odm/bin/hw/android.hardware.drm@1.3-service.widevine companion lib/libdrmdaemon-hook.so
  ```

  （`companion` 可出现在 target 与库路径之间的任意位置，`path=` 与 `name=` 均支持。缺少该关键字时 `connectCompanion` 失败，会回退为 HAL 进程直接读文件并打印 EACCES。）
- 注入侧在 `onModuleLoaded` 之后由后台线程调用 `api.connectCompanion(handle)` 取得 fd 并循环收表，**断线自动重连**。
- companion 侧在 `onModuleConnected(fd)` 中为每个连接启动一个线程，用 **inotify + 内容哈希**监视配置文件（外加 1s 兜底轮询），**内容一变就立刻推送一张新表**。
- 因此修改配置后**不需要重启 Widevine 服务，也不需要重启设备**：WebUI 保存后约 1 秒内新规则生效。由于规则是在 `getPropertyByteArray` 调用时才查表，连已经创建好的 `WVDrmPlugin` 实例也会用上新规则。

### 协议

长度前缀的文本帧，两端共用同一套 `v1|...` 解析器：

```c
struct { uint32_t magic;   // 'DRM1' = 0x314d5244
         uint32_t length; } header;
char text[length];         // targets.conf 原文
```

companion 无法读取文件时会主动发送一个 `length == 0` 的帧，HAL 侧打印：

```text
drmdaemon-hook: companion sent an empty table (config file unreadable?)
```

### 崩溃修复：`&text[0]` 写坏了字符串对象（2026-09-18）

现象：Widevine HAL 启动即崩（`Process uptime: 0s`），tombstone 栈为

```text
#00 __memchr_aarch64+40                        (libc.so)
#01 std::__constexpr_memchr / __str_find       libdrmdaemon-hook.so
#02 parseConfigText                            libdrmdaemon-hook.so
#03 applyConfigText                            libdrmdaemon-hook.so
#04 companionThread                            libdrmdaemon-hook.so
signal 11 (SEGV_MAPERR), fault addr 0x7665647c646960   ← "`id|dev"，是个 ASCII 值
x0 = "uid|devi"   x1 = 0xa ('\n')   x2 = "kage-or-"    ← 字段里全是配置文件内容
```

根因是 `recvConfig()` 里的一处指针语义错误：

```cpp
static bool recvConfig(int fd, std::string *text) {
  ...
  text->resize(header.length);
  return header.length == 0 || readFull(fd, &text[0], header.length);  // ✗
}
```

`text` 是 `std::string*`，所以 `text[0]` 是**字符串对象本身**（不是字符），`&text[0]` 就等于**对象地址**。于是 `readFull()` 把整段配置文本写到了栈上的 `std::string` 对象上（并继续越界写穿调用者栈帧），对象的 `{cap,size,data}` 三个字段变成文件内容；随后 `find()` 用这些字段当指针和长度去 `memchr`，直接 SEGV。反汇编可证：

```asm
6e758: ldr  x0, [sp, #16]      ; text (std::string*)
6e764: bl   basic_string::resize
6e780: ldr  x1, [sp, #16]      ; ✗ 传的是对象指针，而不是 text->data()
6e78c: bl   readFull
```

修复：`readFull(fd, text->data(), header.length)`。

顺带确认了两件事：

- **companion 链路本身是通的**：能崩在 `parseConfigText` 说明 companion 已经把配置文本成功下发到 HAL 进程（否则根本走不到解析）。
- **不要跨 STL 边界按类型读对象**：`libwvhidl.so` 用的是平台 libc++（`std::__1`，其 PLT 里是 `_ZNSt3__112basic_string...`），本模块用的是 NDK/device libcxx（`std::__ndk1`）。两者布局恰好一致，但不能依赖它。因此构造函数的 `appPackageName` 参数改为**不透明指针 + 手工按 libc++ 布局解码**（`decodeLibcxxString()`，含长度合理性检查），避免同类野指针。

仍属已知假设的一点：`getPropertyByteArray` 的回调是 `std::function`，它**必须**跨这个边界按值传递（原始项目也是这么做的）。两边的 libc++ `std::function` 布局一致时可用；若将来在 DRM 播放路径上崩在 `libwvhidl.so` 内部，优先怀疑这里。

### 崩溃修复二：companion 进程里的库内 PLT 未重定位（2026-09-18 01:00）

第二份 tombstone 的进程不再是 HAL，而是 companion：

```text
Cmdline: zn-companion64 drmdaemon-hook:libdrmdaemon-hook.so      uid: 0     ← companion 跑起来了
signal 11 (SEGV_MAPERR), fault addr 0xe7800        pst: ...60000000
pc = 0x00000000000e7800  <unknown>                 ← 取指失败（不是数据访问）
x17 = 0x00000000000e7800                            ← PLT 桩里 ldr x17 拿到的值
x7 = "00000000"  x13 = "characte"  x8 = x9 = FNV 哈希(配置)   ← 正在处理 targets.conf
#04 __thread_proxy → #02/#03 std::thread 构造 → #01 lib 内某函数 → #00 0xe7800
```

`0xe7800` 正是本模块 `.plt` 里的一根桩：

```text
00000000000e7800 <_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE9push_backEc@plt>:
  adrp x16, ...   ; ldr x17, [x16, #3344]   ; add x16, ...   ; br x17
```

即 **`std::__ndk1::basic_string<char>::push_back(char)`** —— 我们自己静态链接进来的 libc++ 成员函数。触发路径：companion 侧 `readConfigFile()` 里的

```cpp
text->assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
```

`istreambuf_iterator` 是输入迭代器，libc++ 会逐字符 `push_back()` 追加。

**根因**：这个符号由本库自身定义、但以 **WEAK GLOBAL** 导出，因此库内调用也必须走 PLT + 动态重定位。HAL 进程里由 bionic 的 `dlopen` 加载，重定位+load bias 正确；而 companion 是 Zygisk Next 自己的 `zn-companion64` 进程，**我们库内 weak 符号的 PLT 槽没有加上 load bias**（GOT 里是链接期地址 `0xe7800`，`br x17` 直接跳到未映射的低地址 → 取指 SEGV）。官方样例在 companion 里只调用**外部**函数（`read`、`__android_log_print`），从不触发库内 weak 符号的 PLT，所以样例不会暴露这个问题。

**修复（写入 CMakeLists.txt）**：让模块自包含，库内引用不再经过 PLT/GOT：

```cmake
target_link_options(drmdaemon-hook PRIVATE
  -Wl,-Bsymbolic-functions   # 库内调用直接绑定，235 个库内 PLT 桩全部消失
  -Wl,--exclude-libs,ALL     # 不导出随包的静态 libc++ 符号
  -Wl,-z,now                 # 剩余（libc/liblog）槽在加载期解析，不用惰性解析桩
  -Wl,-z,relro)
```

量化对照（修复前的本库）：动态符号里 libc++ 相关 **1249 个**（其中 WEAK 427 个）；PLT 桩共 **418 个**，其中 **235 个指向库内 libc++ 符号**。修复后 `readelf --dyn-syms -W libdrmdaemon-hook.so | grep -c '_ZNSt6__ndk1'` 应大幅下降，且 `.plt` 中不应再出现 `St6__ndk1` 桩。

顺带确认：这份 dump 说明 **companion 已经真的被拉起并执行我们的代码**（`uid: 0`、cmdline 带模块库名）。也解释了更早「加了 companion 反而完全不注入 / 删掉后没有 companion 进程」的阶段——那时 `connectCompanion` 还没成功，HAL 退回了直读 `targets.conf`（所以第一次崩在 HAL 的 `parseConfigText`）。既然 companion 已可用，之前为直读文件加的 `/data` SELinux 放行规则可以撤掉。

### 崩溃修复三：返回值的隐藏返回指针 x8（2026-09-18 01:15）

第三份 tombstone 终于落在「真实查询」路径上，也说明前两步都通了（companion 已下发规则、hook 已被调用）：

```text
Cmdline: /odm/bin/hw/android.hardware.drm@1.3-service.widevine   tid == pid（主线程）
signal 11 (SEGV_MAPERR), fault addr 0x71f9bf2074    x19 = 0x71f9bf2054（= fault - 0x20）
#00 /odm/lib64/libwvhidl.so  WVDrmPlugin::getPropertyByteArray(...)+1732   pc=0x180da8
#01 /data/adb/modules/drmdaemon-hook/lib/libdrmdaemon-hook.so              ← 我们的 hook
#02 android.hardware.drm@1.0.so  BnHwDrmPlugin::_hidl_getPropertyByteArray
#03 ... BnHwDrmPlugin::onTransact → BHwBinder::transact → IPCThreadState
```

崩溃指令（libwvhidl.so 与设备同一 BuildId `06df5cf3…`）：

```asm
180da8: strb wzr, [x19, #32]      ; ✗ 往野指针 x19 零初始化 33 字节
180dac: stp  q0, q0, [x19]
```

`x19` 在整个函数里**只被赋值一次**，就在序言：

```asm
180708: mov x19, x8              ; x8 是入参
18070c: ldr x8, [x26, #40]       ; x8 随即被栈保护覆盖 → 证明前面用的是入参 x8
180710: mov x21, x0              ; this
180714: mov x0, x1               ; &hidl_string
180718: mov x20, x2              ; &callback
```

在 AAPCS64 里 `x8` 是**间接返回指针（indirect result / sret）**。这个方法的真实签名是 HIDL 生成代码：

```cpp
// IDrmPlugin::getPropertyByteArray(name, cb) generates (Status, vec<uint8_t>)
Return<void> WVDrmPlugin::getPropertyByteArray(const hidl_string&,
                                               getPropertyByteArray_cb);
```

`Return<void>` 是**非平凡类型**，所以由**调用者**分配返回对象、把地址放进 x8，被调用者往那里写。

**而我们的 hook（以及最初版本的代码）把返回类型声明成了 `void`：**

```cpp
using GetProperty = void (*)(void *, const HidlString &, Callback);   // ✗
```

于是我们调用 original 时 **x8 是垃圾**（dump 里就是 `0x71f9bf2054`，我们代码里残留的指针），libwvhidl 便把这个 `Return<void>` 零初始化写到野地址 → `SEGV_MAPERR` ✓ 与 tombstone 完全吻合。

这是**原始项目代码里就存在的 ABI 错误**，之前从没暴露，只是因为从未走到「一次真实查询」：先前的崩溃分别发生在启动解析（companion 未通）与 companion 加载（PLT 未重定位）阶段。

**修复**（`hook.cpp`）：给 hook 一个「布局无关、不可拷贝」的返回类型，并让所有路径都是 `return original_get_property(...)`：

```cpp
struct ReturnVoid {
  ReturnVoid() = delete;
  ReturnVoid(const ReturnVoid &) = delete;
  ReturnVoid(ReturnVoid &&) = delete;
  ~ReturnVoid() {}   // 用户提供的析构 → 非平凡 → 走 x8 间接返回
};
using GetProperty = ReturnVoid (*)(void *, const HidlString &, Callback);
```

C++17 对「返回同类型 prvalue」保证**复制消除**，所以调用者的 x8 会被原样转发给 original：不产生临时对象，也**不需要知道 `Return<void>` 的布局或大小**。故意删除拷贝构造，是为了让将来若有人引入临时对象时**编译失败**，而不是静默地把调用者的返回槽写越界。

> 反面做法（很多模块会踩）：自己定义一个「大小猜出来的 `Return<void>` 结构体」按值返回 —— 一旦真实对象比猜的更大，就会写溢出调用者的返回槽。这里用转发彻底回避了尺寸问题。

### 崩溃修复四：析构函数的 VTT 参数（2026-09-18 01:31）

第四份 tombstone 落在**析构路径**（`delete plugin` → `RefBase::decStrong` → 虚基类 thunk → `~WVDrmPlugin`）：

```text
signal 11 (SEGV_MAPERR), fault addr 0xffffffffffffffe8      x8 = 0
#00 libwvhidl.so  WVDrmPlugin::~WVDrmPlugin()+28            pc = 0x1780b4
#01 /data/adb/modules/drmdaemon-hook/lib/libdrmdaemon-hook.so   ← 我们的 hook_dtor
#02 libwvhidl.so  virtual thunk to WVDrmPlugin::~WVDrmPlugin()+36
#03 libutils.so   RefBase::decStrong → BnHwBase::~BnHwBase → BnHwDrmPlugin::~BnHwDrmPlugin
```

崩溃指令与序言（同一 BuildId `06df5cf3…`）：

```asm
178098 <~WVDrmPlugin() D2>:
  1780a4: ldr  x8, [x1]        ; ← x1 是第二个参数
  1780ac: str  x8, [x0]        ; 把它写进对象的 vptr
  1780b0: ldr  x9, [x1, #104]
  1780b4: ldur x8, [x8, #-24]  ; ✗ 崩溃（x8 = [x1] = 0 → 读 -24）
```
而所有 D2 的调用者都在调用前**主动设置 x1**：

```asm
1785c0 <~WVDrmPlugin() D1>:
  1785c0: adrp x1, ... ; ldr x1, [x1, #688]   ; x1 = 指向 vtable 的指针（VTT）
  1785cc: bl   D2@plt
```
D0、`_ZThn8_/_ZThn16_`、`_ZTv0_n24_` 各 thunk 也都是同样写法。

**根因**：`WVDrmPlugin` 继承 `V1_2::IDrmPlugin`，**类里有虚基类**。按 Itanium C++ ABI，基类子对象析构函数 `D2` 额外接收一个 **VTT 指针**，放在 `this` 之后（x1）。我们的 `hook_dtor` 只声明了 `(void *self)`：

```cpp
using PluginDtor = void (*)(void *);          // ✗ 丢掉 x1
static void hook_dtor(void *self) { ...; original_dtor(self); }
```

于是 D2 拿 `[x1]`（垃圾，恰好为 0）当 vtable，再读 `[0-24]` → `fault addr = 0xffffffffffffffe8`、`x8 = 0` ✓ 与 tombstone 逐项吻合。

**同一轮还查出 C2 也带 VTT**（同类隐患，尚未触发但迟早会）：

```asm
177ce8 <WVDrmPlugin::C2(...)>:
  177cfc: ldr  x8, [x1, #32]     ; 从 x1 取基类 vtable
  177d00: and  w11, w5, #0x1     ; ← bool 在 w5（不是 w4）
  177d1c: mov  x21, x4           ; crypto 在 x4
  177d20: mov  x20, x3           ; &
  177d2c: mov  x22, x2           ; &
```
即 **C2 的 ABI 是 `(this, VTT, sp<WvCDM> const&, std::string const&, WVGenericCryptoInterface*, bool)`**——VTT 插在 `this` 后面，所有形参整体右移一格、bool 落到 w5。而 **C1 没有 VTT**（唯一调用点 `WVDrmFactory::createPlugin` 0xa89c4 只设置 x0…x3 与 w4，其中 x2 就是那个 `std::string` 临时对象），所以此前记录的 `package`（x2）其实一直是对的。

**修复**（`hook.cpp`）：

```cpp
using PluginCtor     = void (*)(void *, const void *, const void *, void *, bool);              // C1（无 VTT）
using PluginCtorBase = void (*)(void *, const void *, const void *, const void *, void *, bool); // C2（含 VTT）
using PluginDtor     = void (*)(void *, void *);                                                // D2（含 VTT）
```
`hook_dtor(self, vtt)` 与 `hook_ctor_base(self, vtt, …)` 都原样转发 VTT。若 D2 缺失而回退到 D1 也无妨——D1 只接收 `this`，自己会设置 x1。

> 经验总结：inline hook C++ 函数时，除形参外还要按 ABI 处理三类隐藏项 —— **间接返回指针（x8，见修复三）**、**VTT 参数（虚基类的构造/析构）**、**this 调整 thunk**。这三处现在都按二进制实测对齐了。

### 修复五：companion 只推送一次就静默（2026-09-18，配置不生效）

现象：`companion connected` / `companion: pushed …` 都出现过（开机首次下发成功），但之后**任何配置修改都不再推送**，hook 也一直用旧表。

根因是 `serveClient()` 的监视循环里一个自伤 bug：

```cpp
int ifd = inotify_init1(IN_CLOEXEC);              // ✗ 阻塞 fd
...
if (poll(&pfd, 1, 300) > 0) {
  char events[4096];
  while (read(ifd, events, sizeof(events)) > 0) { }   // ✗ 第二次 read 永久阻塞
}
```

`poll` 报可读 → 第一次 `read` 取走事件 → **第二次 `read` 在无新事件时永久阻塞**（inotify fd 是阻塞的）。循环就此卡死：既不再被 inotify 唤醒，**也再不会执行同一迭代后面的 300ms 内容哈希兜底轮询**。

> 讽刺的是，为了「更灵敏」而给文件本身加 `IN_MODIFY|IN_CLOSE_WRITE|IN_ATTRIB` 监视（WebUI 保存 = 截断写 + chmod），恰好让「事件触发 → drain → 卡死」变成必然路径。这也解释了为什么症状是「初次下发成功，之后全静默」。

修复：

```cpp
int ifd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);   // 关键
...
for (int i = 0; i < 64; ++i) {                       // 有界 drain
  const ssize_t n = read(ifd, events, sizeof(events));
  if (n > 0) continue;
  if (n < 0 && errno == EINTR) continue;
  break;                                             // EAGAIN：排空即退出
}
```

**经验**：在 inotify/事件 fd 上永远不要写 `while (read(fd, …) > 0) {}` 来"排空"——要么 `IN_NONBLOCK` + 遇到 `EAGAIN` 退出，要么只 `read` 一次。这个 bug 会让整个循环连同兜底轮询一起死掉，表现和「连接正常但没反应」一模一样。

### 涉及文件

| 文件 | 改动 |
| --- | --- |
| `src/main/cpp/hook.cpp` | 新增 `zn_companion_module`（`onCompanionLoaded` / `onModuleConnected`）、companion 客户端线程、inotify 推送；删除属性/直读路径 |
| `src/main/cpp/CMakeLists.txt` | 链接 `pthread`（每个连接一个线程） |
| `template/zn_modules.txt` | 三行均添加 `companion` 关键字 |
| `template/sepolicy.rule` | 域改为 `vendor_hal_drm_widevine`；**不再需要**任何 `/data` 文件权限 |
| `template/post-fs-data.sh` | 仅保证配置文件存在 |
| `template/webroot/app.js` | 保存时只写文件（companion 自动下发），不再写任何系统属性 |

### 验证

```bash
# 1) hook 是否装好（域写对后应全部 installed）
adb logcat -b all -d | grep -E 'HAL hooks|loaded [0-9]+ rule'
# 2) companion 是否连上并下发
adb logcat -b all -d | grep -E 'companion'
# 期望：
#   drmdaemon-hook: companion loaded
#   drmdaemon-hook: companion connected fd=..
#   drmdaemon-hook: companion: client connected fd=..
#   drmdaemon-hook: companion: pushed 123 bytes of config to fd=..
#   drmdaemon-hook: rules updated from companion: 1 rule(s)
# 3) 免重启：改一条规则后，1 秒内应再次看到 pushed / rules updated
vi /data/adb/modules/drmdaemon-hook/config/targets.conf
# 4) 触发一次查询以观察替换日志
adb logcat -b all -d | grep 'replacement deviceUniqueId'
```

> 现在仅在命中规则时打印替换后的值，**不再打印原始 `deviceUniqueId`**（那是敏感设备标识，旧实现会把它写进 logcat）。

## 为什么最终改为直接 Hook Widevine HAL

AOSP `DrmHal::getPropertyByteArray` 确实是 Java/native 共用的 framework 边界，但 workspace 已提供实际 vendor 实现 `libwvhidl.so`，因此模块现在进一步下移到 HAL 层。这样替换发生在 `WVDrmPlugin::getPropertyByteArray` 的 HIDL callback，`drmserver` 不会再把原值复制给 framework，所有上层调用都收到同一份替换后的字节。

`libwvhidl.so` 由 `android.hardware.drm@1.3-service.widevine` 加载；当前注入目标仍是 daemon/service，不是目标应用。

## `AMediaDrm_*` 边界确认

AOSP Android 12 的 NDK 源码已保存为：

```text
aosp-src/NdkMediaDrm.cpp
aosp-src/NdkMediaDrm.h
```

源码明确显示：

```cpp
media_status_t AMediaDrm_getPropertyByteArray(
        AMediaDrm *mObj,
        const char *propertyName,
        AMediaDrmByteArray *propertyValue) {
    status_t status = mObj->mDrm->getPropertyByteArray(
            String8(propertyName), mObj->mPropertyByteArray);
    if (status == OK) {
        propertyValue->ptr = mObj->mPropertyByteArray.array();
        propertyValue->length = mObj->mPropertyByteArray.size();
    }
}
```

头文件也确认：

```cpp
#define PROPERTY_DEVICE_UNIQUE_ID "deviceUniqueId"
```

所以 `AMediaDrm_getPropertyByteArray` 是**应用进程中的 NDK API**，由 `libmediandk.so` 导出。它调用应用进程内的 `mObj->mDrm`，随后通过 Binder/HIDL 访问 DRM 服务。`drmserver`/Widevine HAL 不会调用 `AMediaDrm_*`；因此把 Zygisk 模块注入 daemon 后，不能在 daemon 内 Hook `AMediaDrm_getPropertyByteArray`。

边界关系是：

```text
应用进程 libmediandk.so
  AMediaDrm_getPropertyByteArray
        ↓
应用进程内的 MediaDrm/DrmHal client
        ↓ Binder/HIDL
/system/bin/drmserver 或 vendor DRM service
        ↓
Widevine plugin
```

在“不注入目标应用”的约束下，当前模块直接 Hook Widevine service 进程中 `libwvhidl.so` 的 `WVDrmPlugin::getPropertyByteArray`；Java/native 两条 NDK/Java API 最终都共享这个 HIDL 返回值。若 Hook `AMediaDrm_*`，必须注入调用它的应用进程，和当前 daemon-only 设计冲突。

要确认 vendor 侧最终实现，需要从运行设备提取实际加载库，而不是只看 service stub：

```bash
adb shell su -c 'cat /proc/$(pidof android.hardware.drm@1.3-service.widevine)/maps'
adb shell su -c 'cat /proc/$(pidof drmserver)/maps'
```

重点提供 maps 中出现的 DRM/Widevine `.so`，以及：

```bash
readelf -d <library>.so
readelf -Ws <library>.so
objdump -d <library>.so
```

当前 workspace 的 `android.hardware.drm@1.3-service.widevine` 仅是 HIDL 服务 stub，不能证明 vendor plugin 的具体函数位置。

## `libwvhidl.so` 已验证：HAL 层直接 Hook

workspace 现已包含：

```text
libwvhidl.so (ELF64 AArch64, 2,641,400 bytes)
```

动态符号表直接导出 Widevine HAL 实现：

```text
_ZN5wvdrm8hardware3drm4V1_28widevine11WVDrmPlugin20getPropertyByteArrayERKN7android8hardware11hidl_stringENSt3__18functionIFvNS6_3drm4V1_06StatusERKNS6_8hidl_vecIhEEEEE
  address: 0x1806e4
  size: 1856

_ZN5wvdrm8hardware3drm4V1_28widevine11WVDrmPluginC1ERKN7android2spIN5wvcdm25WvContentDecryptionModuleEEERKNSt3__112basic_stringIcNSC_11char_traitsIcEENSC_9allocatorIcEEEEPNS_24WVGenericCryptoInterfaceEb
  address: 0x177f6c
  size: 300
```

`objdump -d libwvhidl.so --start-address=0x1806e4` 进一步确认：

```text
0x180720: 调用 hidl_string::c_str
0x1807b0..0x1808b8: 比较请求属性名
0x180900: 调用 WVDrmPlugin::CdmIdentifierBuilder::getDeviceUniqueId
0x180d4c: 调用 HIDL callback 返回 hidl_vec<uint8_t>
```

这证明真正的返回值边界就是 Widevine HAL 的：

```text
WVDrmPlugin::getPropertyByteArray(hidl_string, callback)
```

## `getPropertyByteArray` 参数的 ELF/c++filt 证据

`readelf -Ws libwvhidl.so` 导出的完整符号为：

```text
_ZN5wvdrm8hardware3drm4V1_28widevine11WVDrmPlugin20getPropertyByteArrayERKN7android8hardware11hidl_stringENSt3__18functionIFvNS6_3drm4V1_06StatusERKNS6_8hidl_vecIhEEEEE
```

使用 `c++filt` 还原后：

```text
wvdrm::hardware::drm::V1_2::widevine::WVDrmPlugin::getPropertyByteArray(
    android::hardware::hidl_string const&,
    std::__1::function<void(
        android::hardware::drm::V1_0::Status,
        android::hardware::hidl_vec<unsigned char> const&)>)
```

因此 C++ ABI 参数是：

```text
隐含 this  : WVDrmPlugin*       (AArch64 x0)
第一个显式参数: hidl_string const& (AArch64 x1)
第二个显式参数: std::function callback (AArch64 x2)
```

模块中的函数指针与该签名对应：

```cpp
using Callback = std::function<void(int32_t, const HidlBytes&)>;
using GetProperty = void (*)(void*, const HidlString&, Callback);
```

`hidl_string` 的 `mSize` 不包含 NUL 终止字节，Hook 使用 `size + memcmp` 匹配 `deviceUniqueId`，从不调用 `strlen`/`strcmp`。callback 的第二个参数是 `hidl_vec<uint8_t> const&`，模块只替换其 buffer、size、owns 三个 ABI 字段。

反汇编中 `0x180720` 调用 `hidl_string::c_str` 读取请求内容，`0x180900` 路径调用 `CdmIdentifierBuilder::getDeviceUniqueId`，`0x180d7c` 至 `0x180d8c` 将结果通过 callback 返回；这与上述参数顺序一致。

当请求 `deviceUniqueId` 且该包名命中规则时，日志只输出替换值（小写十六进制）；原始值不再打印，避免把真实设备标识写进 logcat：

```text
drmdaemon-hook: replacement deviceUniqueId plugin=... size=32 hex=...
```

当前 `hook.cpp` 已改为直接注入 `libwvhidl.so` 并 Hook 该导出函数，共四个地址：构造函数 `C1`（+ `C2` 作兼容）、析构函数 `D2`（+ `D1` 作兜底）、`getPropertyByteArray`。

> **C1/C2/D0/D1/D2 是 Itanium C++ ABI 的构造/析构变体**（`C1` 完整对象构造、`C2` 基类子对象构造、`D1` 完整对象析构、`D2` 基类子对象析构、`D0` 删除析构）。必须在实际被调用的变体上挂钩，否则 Hook 一次都不会触发。本库中的实测结论：
> - 构造函数只被 `WVDrmFactory::createPlugin()` 调用，且调用的是 **`C1`**（`bl WVDrmPluginC1Ev@plt`）；`C2` 在本库中**没有任何 PLT 入口**，即无人从外部调用。所以只 Hook `C2` 是错的，必须 Hook `C1`（`C2` 一并 Hook 以兼容其它 ROM 的编译结果）。
> - 析构：`D1`、`D0` 以及 `_ZThn8_`/`_ZThn16_` 非虚 thunk **全部 `bl` 到 `D2`**，因此 Hook `D2` 即可覆盖「直接析构 / `delete` / 通过多继承子对象析构」所有路径（`D1` 仅作兜底）。

构造时**记录每个 plugin 实例的 `appPackageName`**（不只记录已配置的包名，这样之后新增规则对已存在的实例同样生效），析构时清除映射。请求键为 `deviceUniqueId` 且该包名命中规则时，才包装 HIDL callback，将返回的 `hidl_vec<uint8_t>` 替换为配置字节。

这样替换发生在 vendor HAL 返回值产生的位置，`drmserver`、native `AMediaDrm_getPropertyByteArray` 和 Java `MediaDrm` 都会收到同一份修改后的 HIDL 返回值，不会出现 native/Java 两条路径不一致。

### 反汇编关键证据

```text
readelf -Ws libwvhidl.so | grep WVDrmPlugin20getPropertyByteArray
00000000001806e4 1856 FUNC GLOBAL ... WVDrmPlugin::getPropertyByteArray(...)

objdump -d libwvhidl.so --start-address=0x180900
180900: add x0, x21, #0x98
180914: bl  ... WVDrmPlugin::CdmIdentifierBuilder::getDeviceUniqueId(...)
```

当前模块的 `template/zn_modules.txt` 已包含 `android.hardware.drm@1.3-service.widevine`，因此该 HAL 代码会在正确的 vendor service 进程中加载。



## WebUI

模块现在包含 `template/webroot/`，兼容 KernelSU WebUI、KSU WebUI Standalone、MMRL 和 WebUI X：

```text
template/webroot/index.html
template/webroot/app.js
template/webroot/styles.css
template/webroot/config.json
template/webroot/assets/kernelsu.js
template/action.sh
```

WebUI 功能：

- 读取、编辑、添加、删除 `targets.conf` 规则
- 按包名设置 `deviceUniqueId` 的 32 字节返回值
- 保存时通过 `ksu.exec` 写入模块配置（Base64 管道，避免 shell 特殊字符）
- 查看 `drmdaemon-hook` 注入日志
- `action.sh` 自动识别 KSU WebUI Standalone、MMRL 和 WebUI X

在 KernelSU 模块详情页点击 WebUI；或执行模块的 Action 入口。保存只写入 `targets.conf`，由 companion 进程监视并即时下发，无需重启 Widevine service 或设备。

## Zygisk Next 时机（已核对上游实现）

上游 Zygisk Next 示例的作用范围要求目标必须是 init `fork-execve` 产生的动态 ELF 服务，并且启动晚于 `post-fs-data`；其 `onModuleLoaded` 回调在主程序 `main()` 前、依赖库加载后执行。AOSP Android 12 `drmserver.rc` 将 `drmserver` 声明为 init service，并通过 `drm.service.enabled=1/true` 属性触发启动。

当前 Widevine service ELF 通过 `readelf -d` 明确包含 `NEEDED Shared library: [libwvhidl.so]`。因此目标服务的 `onModuleLoaded` 阶段 `libwvhidl.so` 已经加载，符号可解析，且 `WVDrmPlugin` 对象尚未由 `main()` 创建，两个 inline hook 可以及时安装。厂商若在 `post-fs-data` 之前启动服务，Zygisk Next 无法拦截；请直接通过模块日志和 init 的 `ro.boottime.*` 属性验证。

`template/sepolicy.rule` 同步 AOSP `hal_drm` 的 `execmem` 权限。


## 实测注入时序命令

Zygisk Next 上游文档规定：只有 init `fork-execve` 服务、且晚于 `post-fs-data` 启动的动态 ELF 才会被拦截。模块日志中的 `onModuleLoaded` 只要出现，就表示 Zygisk Next 已在其允许的时序内加载模块。

先清空日志并重启：

```bash
adb logcat -c
adb reboot
```

重启后查看模块是否进入 Widevine service：

```bash
adb logcat -b all -d -v threadtime | grep -E 'drmdaemon-hook|android.hardware.drm@1.3-service.widevine'
```

成功注入时应看到类似：

```text
drmdaemon-hook: onModuleLoaded pid=... boot_ms=...
drmdaemon-hook: HAL hooks ctor=installed getPropertyByteArray=installed (...)
```

`onModuleLoaded` 日志出现即表示该进程满足 Zygisk Next 的 service 注入条件；如果没有日志，先检查进程路径、模块是否启用以及服务是否在 `post-fs-data` 前启动。

用 init 设置的服务启动时间属性确认服务实际启动时刻：

```bash
adb shell su -c 'getprop | grep -E "ro.boottime.*(drm|widevine|clearkey|mediadrm)"'
```

再查看当前进程的内核启动时间（相对于 boot，单位毫秒）：

```bash
adb shell su -c '\
pid=$(pidof android.hardware.drm@1.3-service.widevine | awk "{print \$1}"); \
hz=$(getconf CLK_TCK 2>/dev/null || echo 100); \
ticks=$(awk "{print \$22}" /proc/$pid/stat); \
uptime=$(awk "{print \$1}" /proc/uptime); \
awk -v u="$uptime" -v t="$ticks" -v h="$hz" "BEGIN{printf \"pid=%s service_start_boot_ms=%.0f\\n\", "$pid", (u-t/h)*1000}"'
```

`ro.boottime.<service>` 是 init 在 `Service::Start()` 时写入的启动时间。若该值早于 `post-fs-data`，Zygisk Next 按设计不会加载模块；若 `onModuleLoaded` 已出现，则说明该次服务启动处于可拦截时序。

## Widevine HAL 的启动阶段

AOSP Android 12 的启动顺序和本 workspace 中的 `android.hardware.drm@1.3-service.clearkey.rc` 可以确认 `class hal` 的标准阶段：

```text
init late-init
  -> late-fs
  -> post-fs-data
  -> early-boot
  -> boot
       class_start hal
```

AOSP `init.rc` 的 `class_start hal` 位于 `on boot` action；`on late-fs` 只启动 `class_start early_hal`。本地 ClearKey rc 也明确写有：

```text
service vendor.drm-clearkey-hal-1-3 ...
    class hal
```

因此，若厂商 Widevine rc 与标准 Android 12 DRM HAL 一样声明 `class hal`，它是在 `boot` action 的 `class_start hal` 启动，而不是 `late-fs` 启动；这个阶段晚于 `post-fs-data`，满足 Zygisk Next 的服务拦截条件。

workspace 没有提供 Widevine 对应的 `.rc` 文件，所以不能仅凭当前文件断言厂商 ROM 的 Widevine service 一定使用 `class hal`。在设备上用 root 直接确认：

```bash
adb shell su -c 'grep -R -n -A22 -B3 "android.hardware.drm@1.3-service.widevine" /odm/etc/init /vendor/etc/init /system/etc/init 2>/dev/null'
```

看到以下内容即可确认：

```text
service ... /odm/bin/hw/android.hardware.drm@1.3-service.widevine
    class hal
```

如果看到 `on property:... start ...`，则还要检查该 property 的设置时刻。服务实际启动时间可用 init 写入的 `ro.boottime.<service-name>` 查看：

```bash
adb shell su -c 'getprop | grep -E "ro.boottime.*(drm|widevine|clearkey|mediadrm)"'
```

AOSP `init/service.cpp` 在 `Service::Start()` 写入 `ro.boottime.<name>`；该值是服务相对 boot 的启动纳秒时间。结合模块日志里的 `boot_ms`：

```bash
adb logcat -b all -d -v threadtime | grep 'drmdaemon-hook: onModuleLoaded'
```

即可确认模块是否在服务启动时被注入。若服务 rc 是 `class hal`，启动阶段结论是 boot；若厂商 rc 自定义为 `early_hal` 或在 `late-fs` action 中启动，则以实际 rc 为准。
