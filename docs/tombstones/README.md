# 崩溃现场（4 次）

按发生时间命名，对应 `docs/POSTMORTEM-investigation-log.md` 里各节的分析。

| 文件 | 时间 | 进程 | 崩溃点 | 对应的 bug |
| --- | --- | --- | --- | --- |
| `tombstone-0047-parseConfigText-memchr.txt` | 00:47:15 | widevine HAL | `__memchr_aarch64` ← `parseConfigText` ← `companionThread` | `recvConfig` 里 `&text[0]`（`text` 是 `std::string*`，取到的是**对象地址**）⇒ 把配置文本写穿栈上的字符串对象 |
| `tombstone-0100-companion-plt-nobias.txt` | 01:00:22 | **zn-companion64**（uid 0） | `pc = x17 = fault = 0xe7800`（取指失败） | 库内 WEAK 导出的 libc++ 成员走 PLT，companion 进程未给这些 GOT 槽加 load bias ⇒ 跳到链接期地址 |
| `tombstone-0115-getPropertyByteArray-sret.txt` | 01:15:56 | widevine HAL | `WVDrmPlugin::getPropertyByteArray+1732`，fault `0x71f9bf2074` | 返回值是非平凡类型 `Return<void>`，AAPCS64 用**隐藏指针 x8** 返回；hook 声明为 `void` ⇒ 未转发 x8 |
| `tombstone-0131-dtor-vtt.txt` | 01:31:53 | widevine HAL | `~WVDrmPlugin()+28`，fault `0xffffffffffffffe8`，`x8 = 0` | 析构函数 `D2` 有隐藏的 **VTT 参数**（类含虚基类）；hook 只传了 `this` |

## 来源说明

- `0115` 与 `0131` 是**原始设备文件**（最初分别以 `dump.txt.bak` / `dump.txt` 保存）。
- `0047` 与 `0100` 的原始文件在设备上被后续崩溃**覆盖**了，这两份是**按我们当时抓取的日志全文逐字节复原**的
  （大小与原文件一致：3554 / 3925 字节），内容未做任何修改。

## 注意

这些文件包含设备 `Build fingerprint`、pid、地址与内存内容。若要作为公开仓库的一部分发布，
请先对 `Build fingerprint` 行打码，或整体移除（见 `docs/RELEASE-CHECKLIST.md`）。
