cmake_minimum_required(VERSION 3.22.1)

project("native_hook")

set(NGHTTP2_SOURCES
    nghttp2/nghttp2_hd.c
    nghttp2/nghttp2_hd_huffman.c
    nghttp2/nghttp2_hd_huffman_data.c
    nghttp2/nghttp2_buf.c
    nghttp2/nghttp2_mem.c
    nghttp2/nghttp2_helper.c
    nghttp2/nghttp2_rcbuf.c
    nghttp2/sfparse.c
)

# v1.34: 主链路弃用 shadowhook（inline hook，Android 16 PAC 设备崩溃），改用 xhook（PLT/GOT hook）
#   xhook 只改 GOT 表项、不改函数指令 → 完全免疫 PAC 指针认证崩溃（OnePlus/OPPO Android 16 已验证）
# v1.67: libflutter.so 静态 BoringSSL keylog 注入必须用 shadowhook_hook_func_addr
#   （按绝对地址 inline hook，仅 hook 低频 ssl_log_secret 一个函数；xhook 对未导出符号无效）
#   shadowhook v2.0.1 预编译 .so 通过 IMPORTED 链接，运行时 dlopen 动态调用
set(XHOOK_SOURCES
    xhook/xhook.c
    xhook/xh_core.c
    xhook/xh_elf.c
    xhook/xh_util.c
    xhook/xh_log.c
    xhook/xh_version.c
)

add_library(
        native_hook
        SHARED
        native_hook.cpp
        conscrypt_hook.cpp
        flutter_keylog.cpp
        http2_parser.cpp
        ${NGHTTP2_SOURCES}
        ${XHOOK_SOURCES}
)

# v1.67: shadowhook 预编译 .so（arm64-v8a / armeabi-v7a）
# 只在 native_hook.cpp 里 dlopen("libshadowhook.so")，无需链接符号；
# 但为确保 .so 被正确打包进 APK，通过 jniLibs 目录（见 build.gradle.kts sourceSets）
add_library(shadowhook SHARED IMPORTED)
set_target_properties(shadowhook PROPERTIES
        IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/libs/${ANDROID_ABI}/libshadowhook.so
)

target_include_directories(native_hook PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/nghttp2
        ${CMAKE_SOURCE_DIR}/xhook
)

set_source_files_properties(${NGHTTP2_SOURCES} PROPERTIES
        COMPILE_FLAGS "-include arpa/inet.h -Wno-unused-parameter -Wno-sign-compare"
)

target_compile_options(native_hook PRIVATE
        -Wno-unused-parameter
        -Wno-sign-compare
)

# xhook 源码是 C，需要 C 编译（默认 .c 即 C）
set_source_files_properties(${XHOOK_SOURCES} PROPERTIES
        COMPILE_FLAGS "-Wno-unused-parameter -Wno-sign-compare -Wno-format"
)

target_link_libraries(
        native_hook
        PRIVATE
        log
)
