cmake_minimum_required(VERSION 3.22.1)
project(drmdaemonhook)
add_library(drmdaemon-hook SHARED hook.cpp)
target_compile_features(drmdaemon-hook PRIVATE cxx_std_20)
target_compile_options(drmdaemon-hook PRIVATE -fno-exceptions -fno-rtti -fvisibility=hidden)
target_link_libraries(drmdaemon-hook log dl pthread)

# The Zygisk Next *companion* process (zn-companion64) does not relocate our
# library's intra-library weak-symbol PLT slots correctly: a call such as
# std::__ndk1::basic_string<>::push_back() branches to the PLT stub's *link-time*
# address (e.g. 0xe7800) instead of base+0xe7800 -> SIGSEGV on instruction fetch.
# That is exactly the 09-18 01:00 tombstone from readConfigFile()'s
# text->assign(istreambuf_iterator...).
#
# Binding our own definitions internally removes those PLT stubs entirely, so no
# dynamic relocation is needed for them:
#   -Bsymbolic-functions  internal calls become direct branches (no PLT/GOT)
#   --exclude-libs,ALL    do not export the bundled static libc++ symbols
#   -z now                resolve the remaining (libc/liblog) slots eagerly,
#                         i.e. no lazy resolver stubs in the companion either
target_link_options(drmdaemon-hook PRIVATE
  -Wl,-Bsymbolic-functions
  -Wl,--exclude-libs,ALL
  -Wl,-z,now
  -Wl,-z,relro)
