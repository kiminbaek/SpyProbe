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

# v1.30.5: shadowhook 2.0.1（修复 Android 15/16 INIT_LINKER=12）+ libshadowhook_nothing.so
#   shadowhook_init 需要 nothing 库同目录存在，缺它返回 12（Issue #113）
add_library(shadowhook SHARED IMPORTED)
set_target_properties(shadowhook PROPERTIES IMPORTED_LOCATION
        ${CMAKE_SOURCE_DIR}/libs/${ANDROID_ABI}/libshadowhook.so)

add_library(shadowhook_nothing SHARED IMPORTED)
set_target_properties(shadowhook_nothing PROPERTIES IMPORTED_LOCATION
        ${CMAKE_SOURCE_DIR}/libs/${ANDROID_ABI}/libshadowhook_nothing.so)

add_library(
        native_hook
        SHARED
        native_hook.cpp
        http2_parser.cpp
        ${NGHTTP2_SOURCES}
)

target_include_directories(native_hook PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/nghttp2
)

set_source_files_properties(${NGHTTP2_SOURCES} PROPERTIES
        COMPILE_FLAGS "-include arpa/inet.h -Wno-unused-parameter -Wno-sign-compare"
)

target_compile_options(native_hook PRIVATE
        -Wno-unused-parameter
        -Wno-sign-compare
)

target_link_libraries(
        native_hook
        PRIVATE
        shadowhook
        shadowhook_nothing
        log
)

