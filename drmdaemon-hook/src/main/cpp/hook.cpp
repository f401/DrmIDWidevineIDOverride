// DRM daemon Widevine `deviceUniqueId` override (Zygisk Next module + companion).
//
// Injected into /odm/bin/hw/android.hardware.drm@1.3-service.widevine
// (Zygisk Next only injects late-started init services). Inside libwvhidl.so:
//
//   * WVDrmPlugin::WVDrmPlugin(...)          -> remembers plugin* -> appPackageName
//   * WVDrmPlugin::~WVDrmPlugin()            -> forgets the mapping again
//   * WVDrmPlugin::getPropertyByteArray(...) -> rewrites the HIDL callback result
//
// Configuration transport: Zygisk Next companion socket
// -----------------------------------------------------
// The injected process runs in the vendor HAL domain
// (scontext=u:r:vendor_hal_drm_widevine:s0) which cannot traverse /data
// (system_data_file with MLS categories c512,c768). Reading
// /data/adb/modules/... from inside the hook therefore fails with EACCES,
// which is why it used to log "loaded 0 deviceUniqueId rule(s)".
//
// Instead of doing the file I/O in the unprivileged HAL process, this library
// also registers a **companion module** (`zn_companion_module`). Zygisk Next
// loads the very same .so into a forked child of its root daemon and calls
// `zn_companion_module.onModuleConnected(fd)` with a unix socket to the
// injected process. The companion reads targets.conf with root privileges and
// streams the rules over the socket, and it watches the file (inotify +
// content hash) to push a new table on every change. That is what makes a
// WebUI save / shell edit take effect without restarting the Widevine service
// or rebooting.
//
// zn_modules.txt must therefore contain the `companion` token:
//   path=/odm/bin/hw/android.hardware.drm@1.3-service.widevine companion lib/libdrmdaemon-hook.so

#include <android/log.h>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <dlfcn.h>
#include <fcntl.h>
#include <fstream>
#include <functional>
#include <iterator>
#include <mutex>
#include <poll.h>
#include <string>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include "zygisk_next_api.h"

#define LOGI(...)                                                              \
  __android_log_print(ANDROID_LOG_INFO, "drmdaemon-hook", __VA_ARGS__)
#define LOGW(...)                                                              \
  __android_log_print(ANDROID_LOG_WARN, "drmdaemon-hook", __VA_ARGS__)
#define LOGE(...)                                                              \
  __android_log_print(ANDROID_LOG_ERROR, "drmdaemon-hook", __VA_ARGS__)

// Layouts are from Android 12 system/libhidl/base/include/hidl/HidlSupport.h.
struct HidlString {
  const char *buffer;
  uint32_t size;
  bool owns;
  uint8_t pad[3];
};
struct HidlBytes {
  uint8_t *buffer;
  uint32_t size;
  bool owns;
  uint8_t pad[3];
};
static_assert(sizeof(HidlString) == 16, "unexpected hidl_string layout");
static_assert(sizeof(HidlBytes) == 16, "unexpected hidl_vec layout");
using Callback = std::function<void(int32_t, const HidlBytes &)>;

// The hooked method really is
//     Return<void> WVDrmPlugin::getPropertyByteArray(const hidl_string&,
//                                                    getPropertyByteArray_cb);
// `Return<void>` is a *non-trivial* type, so AAPCS64 returns it through an
// "indirect result" pointer passed in x8: the caller allocates the object and
// the callee writes into it. libwvhidl does exactly that - `mov x19, x8` in the
// prologue (0x180708) and `strb wzr, [x19, #32]` in the cleanup (0x180da8).
//
// Declaring the hook as returning `void` (as the first revision did) means our
// call to the original passes whatever garbage happens to sit in x8, and the
// vendor writes Return<void> to that wild address -> SEGV_MAPERR. That is
// precisely the 09-18 01:15 tombstone: x19 = 0x71f9bf2054 (a leftover pointer
// from our own code) and the fault at x19 + 0x20.
//
// Fix: give the hook a non-trivially-copyable, layout-less return type and make
// every path a plain `return original_get_property(...)`. C++17 guarantees copy
// elision when returning a prvalue of the same type, so the caller's x8 is
// forwarded to the original verbatim: no temporary is materialised and we never
// need to know Return<void>'s layout or size. Copying is deleted on purpose, so
// a future refactor cannot silently introduce a temporary that would overflow
// the caller's return slot.
struct ReturnVoid {
  ReturnVoid() = delete;
  ReturnVoid(const ReturnVoid &) = delete;
  ReturnVoid(ReturnVoid &&) = delete;
  ~ReturnVoid() {} // user-provided -> non-trivial -> indirect (x8) return
};

using GetProperty = ReturnVoid (*)(void *, const HidlString &, Callback);
// The ctor takes `const std::string&` — modelled as an opaque pointer on
// purpose, see decodeLibcxxString() below.
// ABI notes, all verified against libwvhidl.so (BuildId 06df5cf3…):
//
// C1 - complete object ctor: (this, sp<WvCDM> const&, std::string const&,
//      WVGenericCryptoInterface*, bool). Its only call site is
//      WVDrmFactory::createPlugin() at 0xa89c4: x1=&sp temp, x2=&string temp,
//      x3=static crypto object, w4=bool - no hidden VTT, because a complete
//      object construction knows the most-derived vtable statically.
using PluginCtor = void (*)(void *, const void *, const void *, void *, bool);

// C2 - *base object* ctor of a class WITH virtual bases. The Itanium ABI
//      inserts the VTT pointer right after `this`, so every formal argument
//      shifts one register and the bool moves to w5. Verified in C2's prologue
//      (0x177cfc-0x177d3c): it loads the base vtables from [x1+24..48] and reads
//      the flag from w5. Calling C2 with the C1 signature both mis-reads
//      `package` and drops the VTT, which crashes inside C2.
using PluginCtorBase = void (*)(void *, const void *, const void *,
                                const void *, void *, bool);

// D2 - *base object* dtor, also takes the VTT in x1: D1, D0 and every
//      _ZThn*/_ZTv* thunk load it and set x1 before `bl D2`. Dropping it made D2
//      execute `ldr x8,[x1]` (garbage -> 0) then `ldur x8,[x8,#-24]`, i.e. the
//      09-18 01:31 tombstone: fault addr 0xffffffffffffffe8, x8 = 0.
//      D1 itself takes only `this` (it supplies the VTT for D2), so passing an
//      extra argument when we fall back to D1 is harmless.
using PluginDtor = void (*)(void *, void *);

static ZygiskNextAPI api;
static void *g_self_handle = nullptr;
static GetProperty original_get_property = nullptr;
static PluginCtor original_ctor = nullptr;         // C1: complete object ctor
static PluginCtorBase original_ctor_base = nullptr; // C2: base object ctor (VTT)
static PluginDtor original_dtor = nullptr;          // D2: base object dtor (VTT)

constexpr size_t kDeviceIdBytes = 32;
constexpr size_t kDeviceIdHexChars = kDeviceIdBytes * 2;
using DeviceId = std::array<uint8_t, kDeviceIdBytes>;

// Keep in sync with template/post-fs-data.sh and the module id.
#define DRMDAEMON_CONFIG_PATH                                                  \
  "/data/adb/modules/drmdaemon-hook/config/targets.conf"
#define DRMDAEMON_CONFIG_DIR "/data/adb/modules/drmdaemon-hook/config"
static constexpr char kConfigPath[] = DRMDAEMON_CONFIG_PATH;
static constexpr char kConfigDir[] = DRMDAEMON_CONFIG_DIR;
static constexpr uint32_t kMsgMagic = 0x314d5244u; // 'DRM1'
static constexpr uint32_t kMsgMaxLength = 1u << 20;

// Guards `rules`, `plugin_packages` and `miss_logged`.
static std::mutex g_lock;
static std::unordered_map<std::string, DeviceId> rules;
static std::unordered_map<void *, std::string> plugin_packages;
// Packages we already complained about ("no rule for package=..."), so the
// diagnostic is printed once per config revision instead of per query.
static std::unordered_set<std::string> miss_logged;

static uint64_t bootTimeMs() {
  timespec ts{};
  clock_gettime(CLOCK_BOOTTIME, &ts);
  return static_cast<uint64_t>(ts.tv_sec) * 1000u + ts.tv_nsec / 1000000u;
}

static int hexNibble(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

static bool decodeHex32(const std::string &hex, DeviceId *out) {
  if (!out || hex.size() != kDeviceIdHexChars)
    return false;
  for (size_t i = 0; i < kDeviceIdBytes; ++i) {
    const int hi = hexNibble(hex[i * 2]);
    const int lo = hexNibble(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0)
      return false;
    (*out)[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return true;
}

// v1|package-or-uid|deviceUniqueId|hex32|64-hex-characters
static bool parseRuleLine(const std::string &line, std::string *package,
                          DeviceId *id) {
  if (line.empty() || line[0] == '#')
    return false;
  size_t a = line.find('|');
  size_t b = (a == std::string::npos) ? std::string::npos : line.find('|', a + 1);
  size_t c = (b == std::string::npos) ? std::string::npos : line.find('|', b + 1);
  size_t d = (c == std::string::npos) ? std::string::npos : line.find('|', c + 1);
  if (a == std::string::npos || b == std::string::npos ||
      c == std::string::npos || d == std::string::npos)
    return false;
  if (line.compare(0, a, "v1") != 0)
    return false;
  const std::string pkg = line.substr(a + 1, b - a - 1);
  if (pkg.empty() || line.substr(b + 1, c - b - 1) != "deviceUniqueId" ||
      line.substr(c + 1, d - c - 1) != "hex32")
    return false;
  DeviceId parsed{};
  if (!decodeHex32(line.substr(d + 1), &parsed))
    return false;
  *package = pkg;
  *id = parsed;
  return true;
}

// ---------------------------------------------------------------------------
// config text -> rule table
// ---------------------------------------------------------------------------

static size_t parseConfigText(const std::string &text,
                              std::unordered_map<std::string, DeviceId> *out) {
  size_t loaded = 0;
  size_t bad = 0;
  size_t begin = 0;
  while (begin <= text.size()) {
    size_t end = text.find('\n', begin);
    if (end == std::string::npos)
      end = text.size();
    std::string line = text.substr(begin, end - begin);
    if (!line.empty() && line.back() == '\r')
      line.pop_back();
    std::string pkg;
    DeviceId id{};
    if (parseRuleLine(line, &pkg, &id)) {
      (*out)[pkg] = id;
      ++loaded;
    } else if (!line.empty() && line[0] != '#') {
      ++bad;
    }
    if (end == text.size())
      break;
    begin = end + 1;
  }
  if (bad)
    LOGW("ignored %zu malformed config line(s)", bad);
  return loaded;
}

// Applies a config blob. Returns true when the rule table actually changed.
static bool applyConfigText(const std::string &text, const char *source) {
  std::unordered_map<std::string, DeviceId> next;
  const size_t loaded = parseConfigText(text, &next);
  std::string keys;
  {
    std::lock_guard<std::mutex> guard(g_lock);
    if (next == rules)
      return false;
    rules.swap(next);
    miss_logged.clear(); // re-arm the per-package diagnostics for the new table
    for (const auto &entry : rules) {
      if (!keys.empty())
        keys += ',';
      keys += entry.first;
      if (keys.size() > 256) {
        keys += ",...";
        break;
      }
    }
  }
  LOGI("rules updated from %s: %zu rule(s) [%s]", source, loaded, keys.c_str());
  return true;
}

// Printed once per package and per config revision: tells you the exact package
// name the vendor HAL uses, which is the key that targets.conf must contain.
static void logRuleMissOnce(void *plugin) {
  std::string pkg;
  size_t rule_count = 0;
  bool first_time = false;
  {
    std::lock_guard<std::mutex> guard(g_lock);
    auto it = plugin_packages.find(plugin);
    pkg = (it == plugin_packages.end()) ? std::string("<unknown plugin>")
                                        : it->second;
    first_time = miss_logged.insert(pkg).second;
    rule_count = rules.size();
  }
  if (first_time)
    LOGW("no rule for package=%s (%zu rule(s) loaded); use exactly the value "
         "printed by `created package=`",
         pkg.c_str(), rule_count);
}

// ---------------------------------------------------------------------------
// wire protocol: uint32 magic, uint32 length, length bytes of config text
// ---------------------------------------------------------------------------

static bool writeFull(int fd, const void *data, size_t size) {
  const char *p = static_cast<const char *>(data);
  while (size > 0) {
    // MSG_NOSIGNAL: a dying peer must not kill the process with SIGPIPE.
    const ssize_t n = send(fd, p, size, MSG_NOSIGNAL);
    if (n > 0) {
      p += n;
      size -= static_cast<size_t>(n);
      continue;
    }
    if (n < 0 && (errno == EINTR || errno == EAGAIN))
      continue;
    return false;
  }
  return true;
}

static bool readFull(int fd, void *data, size_t size) {
  char *p = static_cast<char *>(data);
  while (size > 0) {
    const ssize_t n = read(fd, p, size);
    if (n > 0) {
      p += n;
      size -= static_cast<size_t>(n);
      continue;
    }
    if (n < 0 && errno == EINTR)
      continue;
    return false;
  }
  return true;
}

static bool sendConfig(int fd, const std::string &text) {
  struct {
    uint32_t magic;
    uint32_t length;
  } header = {kMsgMagic, static_cast<uint32_t>(text.size())};
  return writeFull(fd, &header, sizeof(header)) &&
         writeFull(fd, text.data(), text.size());
}

static bool recvConfig(int fd, std::string *text) {
  struct {
    uint32_t magic;
    uint32_t length;
  } header{};
  if (!readFull(fd, &header, sizeof(header)))
    return false;
  if (header.magic != kMsgMagic || header.length > kMsgMaxLength) {
    LOGE("bad companion message (magic=%08x length=%u)", header.magic,
         header.length);
    return false;
  }
  text->resize(header.length);
  // NOTE: must be (*text)[0] / data(), NOT &text[0]. `text` is a std::string*,
  // so `&text[0]` is the address of the string *object*: passing that to
  // readFull() writes the config text over the object (and past it, into the
  // caller's stack frame), which then makes find()/substr() dereference string
  // fields holding file bytes -> SIGSEGV inside memchr. That was the crash at
  // parseConfigText() in the 09-18 tombstone.
  return header.length == 0 ||
         readFull(fd, text->data(), header.length);
}

// ---------------------------------------------------------------------------
// companion side (runs inside the Zygisk Next root daemon)
// ---------------------------------------------------------------------------

static bool readConfigFile(std::string *text, uint64_t *hash) {
  errno = 0;
  std::ifstream in(kConfigPath, std::ios::binary);
  if (!in) {
    LOGE("companion: cannot read %s: errno=%d (%s)", kConfigPath, errno,
         strerror(errno));
    return false;
  }
  text->assign(std::istreambuf_iterator<char>(in),
               std::istreambuf_iterator<char>());
  uint64_t h = 1469598103934665603ull; // FNV-1a
  for (unsigned char c : *text) {
    h ^= c;
    h *= 1099511628211ull;
  }
  *hash = h;
  return true;
}

// One thread per connected client: push the table now, then keep pushing
// whenever the file content changes. The socket is owned by this thread.
static void serveClient(int fd) {
  LOGI("companion: client connected fd=%d", fd);

  // IN_NONBLOCK is essential: the drain loop below would otherwise block
  // forever on its second read() once the pending events are consumed, which
  // freezes both the inotify wakeups *and* the content-hash polling further
  // down - config edits would never be pushed again (the "companion connected,
  // pushed once, then silence" symptom).
  int ifd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
  if (ifd >= 0) {
    // Watch the directory for atomic replacements (create+rename)...
    inotify_add_watch(ifd, kConfigDir,
                      IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE | IN_DELETE |
                          IN_ATTRIB);
    // ...and the file itself: IN_MODIFY on a file is NOT reported when only the
    // directory is watched, and the WebUI rewrites the file in place
    // (`base64 -d > targets.conf`), which is a truncate + write.
    inotify_add_watch(ifd, kConfigPath,
                      IN_CLOSE_WRITE | IN_MODIFY | IN_ATTRIB | IN_MOVE_SELF |
                          IN_DELETE_SELF);
  }

  uint64_t sent_hash = 0;
  bool failure_reported = false;
  for (;;) {
    std::string text;
    uint64_t hash = 0;
    if (readConfigFile(&text, &hash)) {
      failure_reported = false;
      if (hash != sent_hash) {
        if (!sendConfig(fd, text)) {
          LOGI("companion: client fd=%d went away", fd);
          break;
        }
        sent_hash = hash;
        LOGI("companion: pushed %zu bytes (hash=%016llx) to fd=%d", text.size(),
             static_cast<unsigned long long>(hash), fd);
        continue; // re-check right away, the file may change again
      }
    } else if (!failure_reported) {
      // Tell the module once instead of leaving it silently at 0 rules.
      failure_reported = true;
      if (!sendConfig(fd, std::string()))
        break;
    }

    // 300ms fallback poll: even if inotify misses an event (or the file is
    // replaced in a way we do not watch), the content hash is re-checked.
    struct pollfd pfd = {ifd, POLLIN, 0};
    if (poll(ifd >= 0 ? &pfd : nullptr, ifd >= 0 ? 1 : 0, 300) > 0 &&
        ifd >= 0) {
      // Drain pending events. The fd is non-blocking, so the first EAGAIN ends
      // the loop instead of blocking the thread forever.
      char events[4096];
      for (int i = 0; i < 64; ++i) {
        const ssize_t n = read(ifd, events, sizeof(events));
        if (n > 0)
          continue;
        if (n < 0 && errno == EINTR)
          continue;
        break; // EAGAIN: drained (or a real error)
      }
    }
  }

  if (ifd >= 0)
    close(ifd);
  close(fd);
}

// ---------------------------------------------------------------------------
// module side (runs inside the Widevine HAL process)
// ---------------------------------------------------------------------------

static void companionThread() {
  LOGI("companion client thread started (self=%p)", g_self_handle);
  bool file_fallback_logged = false;
  unsigned attempts = 0;
  for (;;) {
    ++attempts;
    int fd = g_self_handle ? api.connectCompanion(g_self_handle) : -1;
    if (fd < 0) {
      LOGE("connectCompanion failed (attempt %u): is `companion` present on "
           "your zn_modules.txt line, and does the module library export "
           "zn_companion_module / zygisk_companion_entry?",
           attempts);
      if (!file_fallback_logged) {
        file_fallback_logged = true;
        LOGE("falling back to reading %s from the HAL process, which is "
             "normally denied by SELinux (vendor_hal_drm_widevine)",
             kConfigPath);
      }
      std::string text;
      uint64_t hash = 0;
      if (readConfigFile(&text, &hash))
        applyConfigText(text, "direct file read");
      sleep(5);
      continue;
    }

    LOGI("companion connected fd=%d", fd);
    std::string text;
    while (recvConfig(fd, &text)) {
      if (text.empty()) {
        LOGW("companion sent an empty table (config file unreadable?)");
        continue;
      }
      if (!applyConfigText(text, "companion"))
        LOGI("companion table re-applied, no change (%zu bytes)", text.size());
    }
    close(fd);
    LOGW("companion connection lost, reconnecting");
    sleep(1);
  }
}

// ---------------------------------------------------------------------------
// HAL hooks
// ---------------------------------------------------------------------------

static bool replacementFor(void *plugin, DeviceId *out) {
  std::lock_guard<std::mutex> guard(g_lock);
  auto p = plugin_packages.find(plugin);
  if (p == plugin_packages.end())
    return false;
  auto r = rules.find(p->second);
  if (r == rules.end())
    return false;
  *out = r->second; // copy: `rules` may be swapped by the companion thread
  return true;
}

// Remember *every* package, not only the ones that have a rule yet: a rule
// added later must also apply to plugin objects that already exist. Written to
// be idempotent so both constructor variants can be hooked safely.
static void recordPlugin(void *self, const std::string &package) {
  if (!self || package.empty())
    return;
  bool changed = false;
  {
    std::lock_guard<std::mutex> guard(g_lock);
    auto it = plugin_packages.find(self);
    if (it == plugin_packages.end() || it->second != package) {
      plugin_packages[self] = package;
      changed = true;
    }
  }
  if (changed)
    LOGI("WVDrmPlugin %p created package=%s", self, package.c_str());
}

// libwvhidl.so is built against the platform libc++ (`std::__1`, note the
// `_ZNSt3__112basic_string...` calls in its PLT) while this module is built
// against the NDK/device libcxx (`std::__ndk1`). The two are layout-compatible
// in practice, but never rely on that for an object that crosses the boundary:
// a single mismatch turns a std::string into a wild pointer. So the ctor's
// `appPackageName` argument is received as an opaque pointer and decoded by
// hand using libc++'s documented layout:
//
//   long  form: { uint64 cap; uint64 size; char *data; }
//   short form: byte0 = (size << 1) | 1_is_long, bytes [1, 22] = data
static std::string decodeLibcxxString(const void *object) {
  if (!object)
    return {};
  const auto *p = static_cast<const unsigned char *>(object);
  const bool is_long = (p[0] & 1u) != 0;
  size_t size = 0;
  const char *data = nullptr;
  if (is_long) {
    uint64_t raw_size = 0;
    const char *raw_data = nullptr;
    std::memcpy(&raw_size, p + 8, sizeof(raw_size));
    std::memcpy(&raw_data, p + 16, sizeof(raw_data));
    size = static_cast<size_t>(raw_size);
    data = raw_data;
  } else {
    size = static_cast<size_t>(p[0] >> 1);
    data = reinterpret_cast<const char *>(p + 1);
  }
  // Sanity bound: anything else means we decoded a foreign layout.
  if (!data || size == 0 || size > 512) {
    LOGW("refusing to decode a suspicious package string (size=%zu)", size);
    return {};
  }
  return std::string(data, size);
}

static void hook_ctor(void *self, const void *cdm, const void *package,
                      void *crypto, bool flag) {
  original_ctor(self, cdm, package, crypto, flag);
  recordPlugin(self, decodeLibcxxString(package));
}

static void hook_ctor_base(void *self, const void *vtt, const void *cdm,
                           const void *package, void *crypto, bool flag) {
  original_ctor_base(self, vtt, cdm, package, crypto, flag);
  recordPlugin(self, decodeLibcxxString(package));
}

static void hook_dtor(void *self, void *vtt) {
  {
    // Forget before running the real destructor: avoids stale entries when an
    // address is reused and keeps the map from growing without bound.
    std::lock_guard<std::mutex> guard(g_lock);
    plugin_packages.erase(self);
  }
  original_dtor(self, vtt); // D2 needs its VTT argument
}

// D2 (base object destructor) is the one to hook: in libwvhidl.so the D1
// (complete) and D0 (deleting) destructors plus the _ZThn8_/_ZThn16_
// non-virtual thunks all `bl` into D2, so hooking D2 alone covers every
// destruction path. D1 is kept only as a fallback for other builds.

static bool isDeviceUniqueId(const HidlString &name) {
  // hidl_string carries an explicit byte length. Do not call strlen/strcmp:
  // the HIDL buffer is length-delimited and may not have a trailing NUL.
  constexpr char kKey[] = "deviceUniqueId";
  constexpr size_t kKeyLength = sizeof(kKey) - 1;
  return name.buffer != nullptr && name.size == kKeyLength &&
         std::memcmp(name.buffer, kKey, kKeyLength) == 0;
}

static std::string hexBytes(const uint8_t *data, size_t size) {
  constexpr char kHex[] = "0123456789abcdef";
  if (!data || size == 0)
    return "";
  std::string out;
  out.resize(size * 2);
  for (size_t i = 0; i < size; ++i) {
    out[i * 2] = kHex[data[i] >> 4];
    out[i * 2 + 1] = kHex[data[i] & 0x0f];
  }
  return out;
}

static ReturnVoid hook_get_property(void *plugin, const HidlString &name,
                                    Callback callback) {
  if (!isDeviceUniqueId(name) || !callback) {
    // Forward the caller's return slot (x8) untouched.
    return original_get_property(plugin, name, std::move(callback));
  }

  DeviceId value{};
  const bool has_rule = replacementFor(plugin, &value);
  if (!has_rule)
    logRuleMissOnce(plugin);

  Callback wrapped = [callback = std::move(callback), plugin, has_rule,
                      value](int32_t status, const HidlBytes &original) mutable {
    if (status != 0 || !has_rule) {
      callback(status, original);
      return;
    }
    HidlBytes changed{};
    changed.buffer = const_cast<uint8_t *>(value.data());
    changed.size = static_cast<uint32_t>(value.size());
    changed.owns = false;
    LOGI("replacement deviceUniqueId plugin=%p size=%u hex=%s", plugin,
         changed.size, hexBytes(changed.buffer, changed.size).c_str());
    callback(0, changed);
  };
  return original_get_property(plugin, name, std::move(wrapped));
}

// ---------------------------------------------------------------------------
// entry points
// ---------------------------------------------------------------------------

static void *resolve(ZnSymbolResolver *resolver, const char *name) {
  return api.symbolLookup(resolver, name, false, nullptr);
}

static void onLoaded(void *self_handle, const ZygiskNextAPI *loaded_api) {
  std::memcpy(&api, loaded_api, sizeof(api));
  g_self_handle = self_handle;
  LOGI("onModuleLoaded pid=%d boot_ms=%llu", getpid(),
       static_cast<unsigned long long>(bootTimeMs()));

  // Start the companion client FIRST: it does not depend on libwvhidl.so, and
  // an early return below must not be able to silently disable rule delivery.
  std::thread(companionThread).detach();

  ZnSymbolResolver *resolver = api.newSymbolResolver("libwvhidl.so", nullptr);
  if (!resolver) {
    LOGE("libwvhidl.so not loaded");
    return;
  }

  const char *ctor =
      "_ZN5wvdrm8hardware3drm4V1_"
      "28widevine11WVDrmPluginC1ERKN7android2spIN5wvcdm25WvContentDecryptionMod"
      "uleEEERKNSt3__112basic_stringIcNSC_11char_traitsIcEENSC_"
      "9allocatorIcEEEEPNS_24WVGenericCryptoInterfaceEb";
  // C1 is the one actually used: the only call site in libwvhidl.so is inside
  // WVDrmFactory::createPlugin() (`bl WVDrmPluginC1Ev@plt`), which is exactly
  // the HIDL entry the framework calls with the app package name. C2 has no PLT
  // entry at all in this build, but other ROM builds may route through it, so
  // both are hooked (they never both run for one object, and recordPlugin() is
  // idempotent anyway).
  const char *ctor_base =
      "_ZN5wvdrm8hardware3drm4V1_"
      "28widevine11WVDrmPluginC2ERKN7android2spIN5wvcdm25WvContentDecryptionMod"
      "uleEEERKNSt3__112basic_stringIcNSC_11char_traitsIcEENSC_"
      "9allocatorIcEEEEPNS_24WVGenericCryptoInterfaceEb";
  const char *dtor_base =
      "_ZN5wvdrm8hardware3drm4V1_28widevine11WVDrmPluginD2Ev";
  const char *dtor = "_ZN5wvdrm8hardware3drm4V1_28widevine11WVDrmPluginD1Ev";
  const char *get_property =
      "_ZN5wvdrm8hardware3drm4V1_"
      "28widevine11WVDrmPlugin20getPropertyByteArrayERKN7android8hardware11hidl"
      "_stringENSt3__18functionIFvNS6_3drm4V1_06StatusERKNS6_8hidl_vecIhEEEEE";

  void *ctor_target = resolve(resolver, ctor);
  if (!ctor_target)
    ctor_target = resolve(resolver, ctor_base);
  void *ctor_base_target = resolve(resolver, ctor_base);
  // D2 first (all destructor paths funnel into it), D1 as fallback.
  void *dtor_target = resolve(resolver, dtor_base);
  if (!dtor_target)
    dtor_target = resolve(resolver, dtor);
  void *property_target = resolve(resolver, get_property);

  const bool ctor_ok =
      ctor_target && api.inlineHook(ctor_target, (void *)hook_ctor,
                                    (void **)&original_ctor) == ZN_SUCCESS;
  const bool ctor_base_ok =
      ctor_base_target && ctor_base_target != ctor_target &&
      api.inlineHook(ctor_base_target, (void *)hook_ctor_base,
                     (void **)&original_ctor_base) == ZN_SUCCESS;
  const bool dtor_ok =
      dtor_target && api.inlineHook(dtor_target, (void *)hook_dtor,
                                    (void **)&original_dtor) == ZN_SUCCESS;
  const bool property_ok =
      property_target &&
      api.inlineHook(property_target, (void *)hook_get_property,
                     (void **)&original_get_property) == ZN_SUCCESS;
  LOGI("HAL hooks ctor(C1)=%s ctor(C2)=%s dtor=%s getPropertyByteArray=%s "
       "(C1=%p C2=%p dtor=%p property=%p)",
       ctor_ok ? "installed" : "failed",
       ctor_base_ok ? "installed" : "n/a",
       dtor_ok ? "installed" : "failed",
       property_ok ? "installed" : "failed", ctor_target, ctor_base_target,
       dtor_target, property_target);
  if (!ctor_ok || !property_ok)
    LOGE("hook install failed: check `allow vendor_hal_drm_widevine "
         "self:process execmem;` in sepolicy.rule (the domain is "
         "vendor_hal_drm_widevine on this device)");
  api.freeSymbolResolver(resolver);

  size_t loaded_rules = 0;
  {
    std::lock_guard<std::mutex> guard(g_lock);
    loaded_rules = rules.size();
  }
  LOGI("module ready: companion client started, %zu rule(s) loaded so far",
       loaded_rules);
}

__attribute__((visibility("default"), unused)) struct ZygiskNextModule zn_module = {
    .target_api_version = ZYGISK_NEXT_API_VERSION_1,
    .onModuleLoaded = onLoaded};

// Runs in the Zygisk Next root daemon (a forked child), where reading
// /data/adb/modules/drmdaemon-hook/config/targets.conf is allowed.
static void onCompanionLoaded() { LOGI("companion loaded"); }

static void onModuleConnected(int fd) {
  std::thread(serveClient, fd).detach();
}

// Compatibility shim: Zygisk Next generations before the `zn_companion_module`
// struct API resolved a plain C symbol from the same library instead
// (daemon side: dlopen("/proc/self/fd/<module lib fd>") + dlsym). Defining it
// as well costs nothing and keeps the module working on both API generations.
// If the daemon cannot find any companion entry it answers 0 and the injected
// side logs "companion not valid" / connectCompanion() returns -1.
//
// NOTE: the module is built with -fvisibility=hidden, so this needs an explicit
// default-visibility attribute or dlsym() cannot see it.
extern "C" __attribute__((visibility("default"))) void
zygisk_companion_entry(int fd) {
  onModuleConnected(fd);
}

__attribute__((visibility("default"), unused)) struct ZygiskNextCompanionModule
    zn_companion_module = {
        .target_api_version = ZYGISK_NEXT_API_VERSION_1,
        .onCompanionLoaded = onCompanionLoaded,
        .onModuleConnected = onModuleConnected};
