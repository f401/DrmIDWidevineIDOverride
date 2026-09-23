# Changelog

## 1.1.0 — 2026-09-18 (`versionCode 2`)

首个可用版本。相对最初的「HAL 进程直读配置文件」实现，重做了配置下发通道，并修掉 5 个会让进程崩溃或让功能静默失效的问题。

### 修复

1. **SELinux 域写错** — `sepolicy.rule` 用了 AOSP 的 `hal_drm`，而设备实测域是 `vendor_hal_drm_widevine`，`execmem` 从未放行，inline hook 静默失败。
2. **HAL 进程无法读取 `/data`** — 目标目录是 `system_data_file:s0:c512,c768`，`s0` 的 subject 不支配 MLS 类别，`open()` 恒 EACCES ⇒ 规则数永远是 0，且改配置必须重启。改为 **Zygisk Next companion** 下发：root 侧读文件，经 unix socket 推给 HAL，inotify + 300ms 内容哈希轮询实现热更新。
3. **返回值 ABI（x8 隐藏返回指针）** — 被 hook 的 `getPropertyByteArray` 返回非平凡类型 `Return<void>`，AAPCS64 通过隐藏指针 x8 返回；原声明是 `void (*)(...)`，调用 original 时不转发 x8 ⇒ libwvhidl 把返回对象写到野地址 ⇒ SIGSEGV。
4. **析构函数 VTT 参数** — `~WVDrmPlugin()`（D2）在 `this` 之后还有一个隐藏的 VTT 指针（类含虚基类）；原实现只传 `this` ⇒ `ldr x8,[x1]` → `ldur x8,[x8,#-24]` ⇒ SIGSEGV。同时修正 `C2`（基类子对象构造）同样带 VTT、`bool` 落在 `w5`。
5. **companion 只推送一次** — inotify 用阻塞 fd + `while (read(...) > 0)` 排水：第二次 `read` 永久阻塞，循环连同后面的 300ms 兜底轮询一起卡死，配置修改再也不下发。

### 加固

- 构造参数不再跨 STL 按类型读取：手工按 libc++ 布局解码并做长度校验，避免同类野指针。
- 析构只 hook `D2`（`D1`、`D0` 与各 thunk 全部汇入 `D2`），`D1` 仅作兜底。
- 记录**所有** plugin 实例的包名（新增规则对已存在的实例立即生效），析构时清除映射。
- 不再把真实 `deviceUniqueId` 写进日志，只打印替换值。
- 未命中规则时打一次诊断：`no rule for package=<X> (N rule(s) loaded)`。
- companion 客户端线程在最前面启动，`libwvhidl.so` 解析失败也不会导致规则通道静默失效。
- 构建强制 `-static-libstdc++ -Wl,-Bsymbolic-functions -Wl,--exclude-libs,ALL -Wl,-z,now`，`build.sh` 内置自检（NEEDED / 三个导出符号 / 库内 PLT 桩为 0）。
