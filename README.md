# drmid — Widevine `deviceUniqueId` 逆向与改写

一个针对 Android Widevine DRM 的**逆向研究 + Root 模块工程**：让
`MediaDrm.getPropertyByteArray("deviceUniqueId")` 按应用返回自定义的 32 字节值。

## 目录

| 路径 | 内容 |
| --- | --- |
| [`drmdaemon-hook/`](drmdaemon-hook/) | **主交付物**：Zygisk Next 模块（源码、打包模板、WebUI、构建脚本、发布用 README/CHANGELOG） |
| [`docs/POSTMORTEM-investigation-log.md`](docs/POSTMORTEM-investigation-log.md) | 完整调试复盘：调用链推导、5 个 bug 的证据链（readelf / objdump / tombstone / addr2line） |
| [`docs/RELEASE-CHECKLIST.md`](docs/RELEASE-CHECKLIST.md) | **发布前必读**：哪些第三方/专有文件不应随仓库发布 |
| [`docs/tombstones/`](docs/tombstones/) | 4 次崩溃现场（含对照表；注意含设备 fingerprint） |
| [`docs/history/`](docs/history/) | 方案演进中的旧实现 |
| `libwvhidl.so`、`android.hardware.drm@1.3-service.*`、`drmserver`、`libdrmframework*.so` | 分析用的目标 ELF（**厂商/AOSP 二进制，发布时请删除**，见清单） |
| `aosp-src/` | 引用的 AOSP Android 12 源码片段（Apache-2.0，发布时建议裁剪并加 NOTICE） |
| `ZN-AuditPatch/` | 第三方项目克隆（**不要发布**） |

## 快速开始

```bash
# 1) 构建模块（需要 NDK）
ANDROID_NDK=/path/to/android-ndk ./drmdaemon-hook/build.sh

# 2) 阅读安装/配置/排错
less drmdaemon-hook/README.md

# 3) 发布前的取舍
less docs/RELEASE-CHECKLIST.md
```

## 技术要点速览

- **落点**：`libwvhidl.so` 的 `WVDrmPlugin::getPropertyByteArray`（vendor HAL 返回值产生处，
  Java 与 NDK 两条路径共用）。
- **配置通道**：Zygisk Next **companion**（HAL 域读不了 `/data`，由 root 侧 companion 读文件后
  经 unix socket 推送，inotify + 300ms 哈希轮询 ⇒ 改配置约 0.3s 生效，无需重启）。
- **踩过的四类 ABI 陷阱**：隐藏返回指针 `x8`、虚基类的 **VTT 参数**、`this` 调整 thunk、
  以及**跨 libc++ 边界**（平台 `std::__1` vs NDK `std::__ndk1`）与**库内 WEAK 符号的 PLT 重定位**。
  详见 `drmdaemon-hook/README.md` §1.3 与 `docs/POSTMORTEM-investigation-log.md`。
# DrmIDWidevineIDOverride
