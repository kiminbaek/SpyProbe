#include <jni.h>
#include <string>
#include <cstring>
#include <android/log.h>
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/stat.h>
#include <unwind.h>
#include <iomanip>
#include <sstream>
#include <pthread.h>
#include <cstdio>
#include <time.h>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <atomic>
#include <vector>
#include <cstdlib>
#include "xhook.h"
#include "http2_parser.h"

#define LOG_TAG "SpyProbe-Native"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#define MAX_STACK_DEPTH 12
#define JNI_MAX_BUFFER_MAPPING (2 * 1024 * 1024)

// v1.31.5 P0-3: Flutter 内部网络栈（dart:io 自带 BoringSSL，符号在 libflutter.so）inline hook 风险高，
//   91暗网 正是 Flutter App——默认不 hook libflutter.so，只 hook 系统 SSL 库（libssl/libconscrypt/libttboringssl）。
// v1.66.0: 重新启用——v1.34 已换 xhook（PLT/GOT hook 不改函数指令，PAC 免疫），v1.31.5 关闭时的
//   inline hook+PAC 崩溃根因已治本；用户实测（2026-08-12）91aw Flutter 层业务 API 全漏，重开抓 dart:io 网络栈。
#define ENABLE_FLUTTER_SSL_HOOK 1

static JavaVM *gJvm = nullptr;
static jclass gNativeRequestHookClass = nullptr;
static jmethodID gOnNativeDataMethod    = nullptr;
static jmethodID gOnH2RequestMethod     = nullptr;
static jmethodID gOnH2DataChunkMethod   = nullptr;
static jmethodID gCollectRespBodyMethod = nullptr;
static jmethodID gOnConnClosedMethod    = nullptr;
// v1.30.4: native→Java 日志桥（shadowhook_init / hook 结果写 LogStore，任意线程可调）
static jmethodID gNativeLogMethod       = nullptr;
// v1.38 P0-3: SSL keylog 回调 → Java NativeProbe.nativeKeylog(String)
static jmethodID gNativeKeylogMethod    = nullptr;
// v1.59: TLS 元数据回调 → Java NativeProbe.onTlsMeta(long, String)
static jmethodID gOnTlsMetaMethod       = nullptr;

static pthread_key_t g_thread_key;
thread_local bool g_is_in_hook = false;

// v1.45.3 P0: 前置声明——dladdr 解析 SSL_get_fd（定义在 native_log 之后）
static void resolve_ssl_get_fd_via_dladdr(void* sym);
thread_local JNIEnv* tls_env = nullptr;
static std::atomic<uint8_t> g_fd_cache[65536];
static std::mutex g_cache_mutex;
static std::unordered_map<jlong, std::string> g_stack_cache;
static std::unordered_map<int, std::string> g_socket_info_cache;

typedef ssize_t (*type_send)(int, const void *, size_t, int);
typedef ssize_t (*type_recv)(int, void *, size_t, int);
typedef ssize_t (*type_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
typedef ssize_t (*type_recvfrom)(int, void *, size_t, int, struct sockaddr *, socklen_t *);
// v1.31.5 P0-2: 去掉 libc write/read hook——write/read 是所有文件/管道/eventfd IO 的入口，
//   Flutter 引擎（91暗网）高频调用，inline hook 风险最大；网络 socket 数据走 send/recv/sendto/recvfrom 已覆盖。
typedef int (*type_close)(int);
typedef int (*type_SSL_write)(void *ssl, const void *buf, int num);
typedef int (*type_SSL_read)(void *ssl, void *buf, int num);
typedef void (*type_SSL_free)(void *ssl);
// v1.63 P1-3: SSL_write_ex/SSL_read_ex —— BoringSSL(API 29+)/OpenSSL 1.1.1+ 提供 ex 变体，
//   部分库（Flutter/WebSocket/自定义 TLS）直接调 ex API，此前只 hook SSL_write/SSL_read
//   会绕过 → 漏抓 TLS 明文。签名：返回 1=成功 0=失败，实际字节数写 *written/*readbytes。
typedef int (*type_SSL_write_ex)(void *ssl, const void *buf, size_t num, size_t *written);
typedef int (*type_SSL_read_ex)(void *ssl, void *buf, size_t num, size_t *readbytes);
// v1.39 P0: SSL_get_fd —— SSL 数据回调里拿底层 fd 查 socket 四元组（pcap 用）
typedef int (*type_SSL_get_fd)(const void *ssl);
static type_SSL_get_fd real_SSL_get_fd = nullptr;
// v1.45.6 P0: SSL_set_fd —— OpenSSL/BoringSSL 标准流程 SSL_new→SSL_set_fd(ssl,fd)→SSL_connect
//   必有。直接 hook 记录 ssl→fd 映射，完全绕开 SSL_get_fd 符号解析（跨库/namespace 全免疫）。
typedef int (*type_SSL_set_fd)(void *ssl, int fd);
static type_SSL_set_fd orig_ssl_set_fd = nullptr;
static std::unordered_map<uintptr_t, int> g_ssl_fd_map;
static std::mutex g_ssl_fd_mutex;
// v1.59: TLS 元数据 per-ssl 标记（collect_tls_meta_once 只提取一次；SSL_free 时清除）
// v1.60: + attempts 计数（未成功时尝试上限防每次数据回调都 build）
static std::unordered_set<uintptr_t> g_tls_meta_done;
static std::unordered_map<uintptr_t, int> g_tls_meta_attempts;
static std::mutex g_tls_meta_mutex;
// v1.45.2: native_log 前置声明（callback_kotlin_chunk 在定义前使用）
static void native_log(const char* msg);
// v1.59: collect_tls_meta_once 前置声明（do_ssl_*_common 在定义前使用）
static void collect_tls_meta_once(uintptr_t conn_id, void* orig_sym);
// v1.45.6: get_ssl_fd_from_hook 前置声明（callback_kotlin_chunk 在定义前使用）
static int get_ssl_fd_from_hook(uintptr_t ssl_ptr);

static type_send orig_send;
static type_recv orig_recv;
static type_sendto orig_sendto;
static type_recvfrom orig_recvfrom;
static type_close orig_close;

// v1.25 P0-3: SSL_write/SSL_read/SSL_free 与 NativeCrypto_* 变体各自独立 orig 指针。
// 此前共用一个 orig 指针：第二个 hook（NativeCrypto_*）会覆盖第一个（SSL_*）写入的 orig，
// 且符号缺失时 hook_func 失败不写 orig（保持 nullptr），回调里调 nullptr 会 segfault。
// 现在分开记录 + hook 成功才写 orig + 回调里 orig==nullptr 时安全返回。
struct SslHookEntry {
    const char* lib_name;
    type_SSL_write orig_ssl_write;
    type_SSL_read  orig_ssl_read;
    type_SSL_free  orig_ssl_free;
    // v1.63 P1-3: ex 变体（BoringSSL/OpenSSL 1.1.1+）
    type_SSL_write_ex orig_ssl_write_ex;
    type_SSL_read_ex  orig_ssl_read_ex;
    type_SSL_write orig_native_write;
    type_SSL_read  orig_native_read;
    type_SSL_free  orig_native_free;
};

static SslHookEntry g_ssl_hooks[] = {
    { "libssl.so",             nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr },
    { "libconscrypt_jni.so",   nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr },
    { "libttboringssl.so",     nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr },
    { "libflutter.so",         nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr },
};
static const int SSL_HOOK_COUNT = sizeof(g_ssl_hooks) / sizeof(g_ssl_hooks[0]);

struct ScopedHookGuard {
    ScopedHookGuard() { g_is_in_hook = true; }
    ~ScopedHookGuard() { g_is_in_hook = false; }
};

struct JniLocalRefGuard {
    JNIEnv* env;
    std::vector<jobject> refs;
    JniLocalRefGuard(JNIEnv* e) : env(e) {}
    ~JniLocalRefGuard() {
        for (jobject ref : refs) if (ref) env->DeleteLocalRef(ref);
    }
    template<typename T> T add(T ref) {
        if (ref) refs.push_back((jobject)ref);
        return ref;
    }
};

static void detach_current_thread(void *env) {
    tls_env = nullptr;
    if (gJvm) gJvm->DetachCurrentThread();
}

JNIEnv* get_jni_env() {
    if (tls_env) return tls_env;
    if (!gJvm) return nullptr;
    int envStat = gJvm->GetEnv((void **)&tls_env, JNI_VERSION_1_6);
    if (envStat == JNI_EDETACHED) {
        if (gJvm->AttachCurrentThread(&tls_env, nullptr) == JNI_OK) {
            pthread_setspecific(g_thread_key, tls_env);
        } else {
            tls_env = nullptr;
        }
    }
    return tls_env;
}

bool check_exception(JNIEnv* env) {
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return true;
    }
    return false;
}

struct BacktraceState { void** current; void** end; };
_Unwind_Reason_Code unwind_callback(struct _Unwind_Context* context, void* arg) {
    BacktraceState* state = static_cast<BacktraceState*>(arg);
    uintptr_t pc = _Unwind_GetIP(context);
    if (pc) {
        if (state->current == state->end) return _URC_END_OF_STACK;
        *state->current++ = reinterpret_cast<void*>(pc);
    }
    return _URC_NO_REASON;
}

std::string get_native_stack_internal() {
    void* buffer[MAX_STACK_DEPTH];
    BacktraceState state = {buffer, buffer + MAX_STACK_DEPTH};
    _Unwind_Backtrace(unwind_callback, &state);
    std::stringstream ss;
    ss << "Native Stack:\n";
    for (void** ptr = buffer; ptr < state.current; ++ptr) {
        const void* addr = *ptr;
        Dl_info info;
        if (dladdr(addr, &info) && info.dli_fname) {
            uintptr_t offset = (uintptr_t)addr - (uintptr_t)info.dli_fbase;
            const char* lib_name = strrchr(info.dli_fname, '/');
            lib_name = (lib_name != nullptr) ? lib_name + 1 : info.dli_fname;
            ss << "  #" << (ptr - buffer) << " pc " << std::hex << offset << "  " << lib_name << "\n";
        }
    }
    return ss.str();
}

std::string get_cached_stack(jlong id) {
    std::lock_guard<std::mutex> lock(g_cache_mutex);
    auto it = g_stack_cache.find(id);
    if (it != g_stack_cache.end()) return it->second;
    std::string stack = get_native_stack_internal();
    if (g_stack_cache.size() >= 2048) g_stack_cache.clear();
    g_stack_cache[id] = stack;
    return stack;
}

// v1.39 P0: socket info 从 "ip:port" 升级为 "src_ip:src_port->dst_ip:dst_port"——
//   pcap 导出需要完整四元组（本地+远端），日志展示也更完整。
//   兼容旧逻辑：调用方无需解析，直接展示或交给 PcapWriter 拆解。
static void sockaddr_to_str(struct sockaddr_storage* addr, char* ip_str, size_t ip_len, int* port) {
    *port = 0;
    if (addr->ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)addr;
        *port = ntohs(s->sin_port); inet_ntop(AF_INET, &s->sin_addr, ip_str, ip_len);
    } else if (addr->ss_family == AF_INET6) {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)addr;
        *port = ntohs(s->sin6_port); inet_ntop(AF_INET6, &s->sin6_addr, ip_str, ip_len);
    } else {
        strncpy(ip_str, "unknown", ip_len - 1);
    }
}

static std::string get_cached_socket_info(int fd) {
    if (fd <= 0) return "";
    {
        std::lock_guard<std::mutex> lock(g_cache_mutex);
        auto it = g_socket_info_cache.find(fd);
        if (it != g_socket_info_cache.end()) return it->second;
    }
    struct sockaddr_storage local, remote; socklen_t llen = sizeof(local), rlen = sizeof(remote);
    char lip[INET6_ADDRSTRLEN] = {0}, rip[INET6_ADDRSTRLEN] = {0};
    int lport = 0, rport = 0;
    if (getsockname(fd, (struct sockaddr*)&local, &llen) != 0) return "";
    sockaddr_to_str(&local, lip, sizeof(lip), &lport);
    if (getpeername(fd, (struct sockaddr*)&remote, &rlen) == 0) {
        sockaddr_to_str(&remote, rip, sizeof(rip), &rport);
    } else {
        strncpy(rip, "0.0.0.0", sizeof(rip) - 1);
        rport = 0;
    }
    std::string info = std::string(lip) + ":" + std::to_string(lport)
                     + "->" + std::string(rip) + ":" + std::to_string(rport);
    std::lock_guard<std::mutex> lock(g_cache_mutex);
    g_socket_info_cache[fd] = info;
    return info;
}

bool is_network_fd(int fd) {
    if (fd < 0 || fd >= 65536) return false;
    uint8_t state = g_fd_cache[fd].load(std::memory_order_relaxed);
    if (state != 0) return state == 2;
    struct stat statbuf;
    if (fstat(fd, &statbuf) != 0 || !S_ISSOCK(statbuf.st_mode)) {
        g_fd_cache[fd].store(1, std::memory_order_relaxed); return false;
    }
    struct sockaddr_storage addr; socklen_t len = sizeof(addr);
    if (getsockname(fd, (struct sockaddr*)&addr, &len) == 0 && (addr.ss_family == AF_INET || addr.ss_family == AF_INET6)) {
        g_fd_cache[fd].store(2, std::memory_order_relaxed); return true;
    }
    g_fd_cache[fd].store(1, std::memory_order_relaxed); return false;
}

// v1.51.2: 自家端点识别——回环 IP + 端口 9900-9910（9900=日志推送数据面，9901=控制面 ping）。
// 主进程每 ~500ms ping 目标进程 9901，native hook 会把该往返数据全部记录成
// [TCP <<< >>> 9901] GET /api/ping + [conn closed TCP #N] → 刷屏（用户真机截图实锤）。
static bool is_self_loopback_port(const std::string &ep) {
    if (ep.empty()) return false;
    size_t colon = ep.rfind(':');
    if (colon == std::string::npos) return false;
    std::string ip = ep.substr(0, colon);
    bool loopback = (ip == "127.0.0.1" || ip == "::ffff:127.0.0.1" || ip == "::1" || ip == "[::1]");
    if (!loopback) return false;
    int port = atoi(ep.c_str() + colon + 1);
    return port >= 9900 && port <= 9910;
}
static bool is_self_internal_info(const std::string &info) {
    if (info.empty()) return false;
    size_t arrow = info.find("->");
    std::string local = (arrow != std::string::npos) ? info.substr(0, arrow) : info;
    std::string remote = (arrow != std::string::npos) ? info.substr(arrow + 2) : "";
    return is_self_loopback_port(local) || is_self_loopback_port(remote);
}

// v1.51.2: 只读查询四元组（不写缓存）——close 时 g_socket_info_cache 已被调用方 erase，
//   用 get_cached_socket_info 会把旧 info 写回缓存污染 fd 复用；且 close 后 fd 未真正关闭，
//   getsockname/getpeername 仍可实查。
static std::string peek_socket_info(int fd) {
    if (fd <= 0) return "";
    struct sockaddr_storage local, remote; socklen_t llen = sizeof(local), rlen = sizeof(remote);
    char lip[INET6_ADDRSTRLEN] = {0}, rip[INET6_ADDRSTRLEN] = {0};
    int lport = 0, rport = 0;
    if (getsockname(fd, (struct sockaddr*)&local, &llen) != 0) return "";
    sockaddr_to_str(&local, lip, sizeof(lip), &lport);
    if (getpeername(fd, (struct sockaddr*)&remote, &rlen) == 0) {
        sockaddr_to_str(&remote, rip, sizeof(rip), &rport);
    } else {
        strncpy(rip, "0.0.0.0", sizeof(rip) - 1);
        rport = 0;
    }
    return std::string(lip) + ":" + std::to_string(lport) + "->" + std::string(rip) + ":" + std::to_string(rport);
}

void notify_kotlin_close(jlong id, bool is_ssl) {
    if (gNativeRequestHookClass == nullptr || gOnConnClosedMethod == nullptr) return;
    // v1.51.2: 自家控制面连接关闭不通知 Java（避免 [conn closed TCP #N] 刷屏）
    if (id > 0) {
        int fd = 0;
        if (is_ssl) {
            fd = get_ssl_fd_from_hook((uintptr_t)id);
        } else {
            fd = (int)id;
        }
        if (fd > 0 && is_self_internal_info(peek_socket_info(fd))) return;
    }
    JNIEnv *env = get_jni_env();
    if (!env) return;
    env->CallStaticVoidMethod(gNativeRequestHookClass, gOnConnClosedMethod, id, (jboolean)is_ssl);
    check_exception(env);
}

// v1.42 P2-11: 前向声明（callback_kotlin 分段回调调 chunk 版本）
bool callback_kotlin_chunk(jlong id, bool is_write, const void *buf, size_t len, bool is_ssl);

bool callback_kotlin(jlong id, bool is_write, const void *buf, size_t len, bool is_ssl) {
    if (gNativeRequestHookClass == nullptr || buf == nullptr || len == 0) return false;
    // v1.42 P2-11: 不再整体丢弃 >2MB 的大块数据（SSL_read 一般 ≤16KB 但非 SSL 大读取/HTTP2
    //   可能超限）。改为按 JNI_MAX_BUFFER_MAPPING 分段循环回调，每段独立映射 JNI 缓冲。
    if (len > JNI_MAX_BUFFER_MAPPING) {
        bool anyBlock = false;
        const char *p = static_cast<const char *>(buf);
        size_t off = 0;
        while (off < len) {
            size_t chunk = len - off;
            if (chunk > JNI_MAX_BUFFER_MAPPING) chunk = JNI_MAX_BUFFER_MAPPING;
            if (callback_kotlin_chunk(id, is_write, p + off, chunk, is_ssl)) anyBlock = true;
            off += chunk;
        }
        return anyBlock;
    }
    return callback_kotlin_chunk(id, is_write, buf, len, is_ssl);
}

/** 单段（≤ JNI_MAX_BUFFER_MAPPING）回调 Java：NewDirectByteBuffer 映射 + 调用 NativeProbe.onNativeData */
bool callback_kotlin_chunk(jlong id, bool is_write, const void *buf, size_t len, bool is_ssl) {
    if (gNativeRequestHookClass == nullptr || buf == nullptr || len == 0) return false;
    if (!is_ssl && !is_network_fd((int)id)) return false;

    JNIEnv *env = get_jni_env();
    if (!env) return false;

    JniLocalRefGuard refGuard(env);

    jobject jBuffer = refGuard.add(env->NewDirectByteBuffer((void*)buf, len));
    if (jBuffer == nullptr) return false;
    
    jstring jInfo = nullptr;
    std::string info;
    if (is_ssl) {
        // v1.39 P0: TLS 明文数据带完整 socket 四元组（pcap 需要本地+远端地址端口）。
        //   id = ssl 指针，用 SSL_get_fd 拿底层 fd 再查 getsockname/getpeername 缓存。
        // v1.45.2 兜底: hook_SSL_new 已延迟解析
        // v1.45.6 P0: 优先查 SSL_set_fd 记录的 ssl→fd 映射（标准流程必有，跨库/namespace 全免疫）；
        //   不再直接 dlsym(RTLD_DEFAULT)——那可能拿到系统 BoringSSL 的 SSL_get_fd（跨库垃圾 fd）。
        //   若映射缺失则用 real_SSL_get_fd（已由 hook_SSL_new 同库解析）。
        int fd = get_ssl_fd_from_hook((uintptr_t)id);
        if (fd > 0) info = get_cached_socket_info(fd);
    } else if (id > 0) {
        info = get_cached_socket_info((int)id);
    }
    if (!info.empty()) {
        // v1.51.2: 自家控制面（9900-9910 回环）数据不记录——9901 ping 往返刷屏根治
        if (is_self_internal_info(info)) return false;
        jInfo = refGuard.add(env->NewStringUTF(info.c_str()));
        if (check_exception(env)) jInfo = nullptr;
    }
    
    // v1.39 P1: native SSL 调用栈——TLS 明文数据双向都采样（定位明文来自哪个 so/函数）；
    //   libc 层保持只有 is_write 采样（读方向高频且诊断价值低）。1/10 采样防刷屏。
    jstring jStack = nullptr;
    if (is_write || is_ssl) {
        thread_local int sample_counter = 0;
        if (++sample_counter >= 10) {
            sample_counter = 0;
            std::string stack = get_cached_stack(id);
            if (!stack.empty()) {
                jStack = refGuard.add(env->NewStringUTF(stack.c_str()));
                if (check_exception(env)) jStack = nullptr;
            }
        }
    }

    jboolean shouldBlock = env->CallStaticBooleanMethod(
        gNativeRequestHookClass, gOnNativeDataMethod, id, is_write, jBuffer, jInfo, jStack, is_ssl
    );

    if (check_exception(env)) return false;
    return (bool)shouldBlock;
}

// v1.47 P2-3: H2 DATA 帧单段回调（≤ JNI_MAX_BUFFER_MAPPING）——NewDirectByteBuffer 直接映射段内存，零拷贝
static void callback_kotlin_h2_chunk(JNIEnv* env, uintptr_t conn_id, int stream_id, bool is_request,
                                     const uint8_t* data, size_t len) {
    if (data == nullptr || len == 0) return;
    JniLocalRefGuard refGuard(env);
    jobject jBuffer = refGuard.add(env->NewDirectByteBuffer((void*)data, len));
    if (jBuffer == nullptr) return;
    env->CallStaticVoidMethod(gNativeRequestHookClass, gOnH2DataChunkMethod,
                              (jlong)conn_id, (jint)stream_id, (jboolean)is_request, jBuffer);
    check_exception(env);
}

bool callback_kotlin_h2(uintptr_t conn_id, const H2FeedResult& feed_result) {
    if (gNativeRequestHookClass == nullptr || gOnH2RequestMethod == nullptr || gOnH2DataChunkMethod == nullptr) return false;
    JNIEnv *env = get_jni_env();
    if (!env) return false;
    
    bool should_block = false;
    std::unordered_set<int> newly_blocked_streams;
    
    for (const auto& check : feed_result.early_checks) {
        JniLocalRefGuard refGuard(env);

        std::string req_hdr_str;
        for (const auto& kv : check.req_headers)  { req_hdr_str  += kv.first + "\n" + kv.second + "\n"; }
        
        jstring jMethod = refGuard.add(env->NewStringUTF(check.method.c_str()));
        jstring jPath = refGuard.add(env->NewStringUTF(check.path.c_str()));
        jstring jAuthority = refGuard.add(env->NewStringUTF(check.authority.c_str()));
        jstring jScheme = refGuard.add(env->NewStringUTF(check.scheme.c_str()));
        jstring jReqHdr = refGuard.add(env->NewStringUTF(req_hdr_str.c_str()));
        
        if (check_exception(env)) continue;

        jboolean blocked = env->CallStaticBooleanMethod(
            gNativeRequestHookClass, gOnH2RequestMethod, (jlong)conn_id, (jint)check.stream_id, 
            jMethod, jPath, jAuthority, jScheme, jReqHdr, nullptr, (jint)-1, (jboolean)false
        );

        if (check_exception(env)) blocked = false;
        
        if (blocked) {
            newly_blocked_streams.insert(check.stream_id);
            h2_enqueue_rst_stream(conn_id, check.stream_id, 0x8);
            h2_block_stream(conn_id, check.stream_id);
            should_block = true;
        }
    }

    for (const auto& chunk : feed_result.data_chunks) {
        if (newly_blocked_streams.count(chunk.stream_id)) continue;
        if (chunk.data.size() > JNI_MAX_BUFFER_MAPPING) {
            // v1.47 P2-3: 大 DATA 帧（App 可把 MAX_FRAME_SIZE 设到 16MB）分段回调，不再丢弃。
            //   与 callback_kotlin v1.42 P2-11 分段策略一致；段内 NewDirectByteBuffer 直接映射原内存段，零拷贝
            const uint8_t* p = chunk.data.data();
            size_t off = 0;
            while (off < chunk.data.size()) {
                size_t seg = chunk.data.size() - off;
                if (seg > JNI_MAX_BUFFER_MAPPING) seg = JNI_MAX_BUFFER_MAPPING;
                callback_kotlin_h2_chunk(env, conn_id, chunk.stream_id, chunk.is_request, p + off, seg);
                off += seg;
            }
            continue;
        }
        callback_kotlin_h2_chunk(env, conn_id, chunk.stream_id, chunk.is_request,
                                 chunk.data.data(), chunk.data.size());
    }

    for (const auto& req : feed_result.completed) {
        if (newly_blocked_streams.count(req.stream_id)) continue;
        JniLocalRefGuard refGuard(env);

        std::string req_hdr_str, resp_hdr_str;
        for (const auto& kv : req.req_headers)  { req_hdr_str  += kv.first + "\n" + kv.second + "\n"; }
        for (const auto& kv : req.resp_headers) { resp_hdr_str += kv.first + "\n" + kv.second + "\n"; }
        
        jstring jMethod = refGuard.add(env->NewStringUTF(req.method.c_str()));
        jstring jPath = refGuard.add(env->NewStringUTF(req.path.c_str()));
        jstring jAuthority = refGuard.add(env->NewStringUTF(req.authority.c_str()));
        jstring jScheme = refGuard.add(env->NewStringUTF(req.scheme.c_str()));
        jstring jReqHdr = refGuard.add(env->NewStringUTF(req_hdr_str.c_str()));
        jstring jRespHdr = refGuard.add(env->NewStringUTF(resp_hdr_str.c_str()));
        
        if (check_exception(env)) continue;

        jboolean blocked = env->CallStaticBooleanMethod(
            gNativeRequestHookClass, gOnH2RequestMethod, (jlong)conn_id, (jint)req.stream_id, 
            jMethod, jPath, jAuthority, jScheme, jReqHdr, jRespHdr, (jint)req.status_code, (jboolean)true
        );

        if (check_exception(env)) blocked = false;
        
        if (blocked) {
            h2_enqueue_rst_stream(conn_id, req.stream_id, 0x8);
            should_block = true;
        }
    }

    return should_block;
}

// v1.70.1 P0: Conscrypt JNI hook（flutter_keylog.cpp）的统一明文入口
//   —— 复用 XH SSL hook 相同的 h2 检测 + HTTP 解析：
//      h2 帧 → h2_feed → callback_kotlin_h2（REQ# 结构化）
//      HTTP/1.1 明文 → callback_kotlin（REQ# 结构化）
//   否则 CS hook 直接 callback_kotlin 会把 h2 二进制帧当 HTTP/1.1 解析出乱码。
bool callback_collect_resp_body(); // 定义在下方
extern "C" bool process_conscrypt_plain(jlong id, bool is_write, const void *buf, size_t len) {
    if (buf == nullptr || len == 0) return false;
    uintptr_t conn_id = static_cast<uintptr_t>(id);
    if (is_write) {
        std::shared_ptr<Http2Connection> h2conn = h2_get_or_create(conn_id);
        if (h2conn != nullptr) {
            bool collect = h2conn->h2_checked && h2conn->is_h2 && callback_collect_resp_body();
            auto feed_res = h2_feed(h2conn, static_cast<const uint8_t*>(buf), len, true, collect);
            if (!feed_res.early_checks.empty() || !feed_res.data_chunks.empty() || !feed_res.completed.empty()) {
                callback_kotlin_h2(conn_id, feed_res);
            }
            if (h2conn->is_h2) return false; // h2 已消费
        }
    } else {
        if (h2_is_http2(conn_id)) {
            std::shared_ptr<Http2Connection> h2conn = h2_get_or_create(conn_id);
            if (h2conn != nullptr) {
                bool collect = callback_collect_resp_body();
                auto feed_res = h2_feed(h2conn, static_cast<const uint8_t*>(buf), len, false, collect);
                if (!feed_res.early_checks.empty() || !feed_res.data_chunks.empty() || !feed_res.completed.empty()) {
                    callback_kotlin_h2(conn_id, feed_res);
                }
                return false;
            }
        }
    }
    return callback_kotlin(id, is_write, buf, len, true);
}

bool callback_collect_resp_body() {
    if (gNativeRequestHookClass == nullptr || gCollectRespBodyMethod == nullptr) return false;
    JNIEnv *env = get_jni_env();
    if (!env) return false;
    jboolean res = env->CallStaticBooleanMethod(gNativeRequestHookClass, gCollectRespBodyMethod);
    if (check_exception(env)) return false;
    return (bool)res;
}

ssize_t hook_send(int s, const void *buf, size_t len, int flags) {
    if (g_is_in_hook) return orig_send(s, buf, len, flags);
    ScopedHookGuard guard;
    if (callback_kotlin((jlong)s, true, buf, len, false)) { errno = ECONNRESET; return -1; }
    return orig_send(s, buf, len, flags);
}
ssize_t hook_recv(int s, void *buf, size_t len, int flags) {
    if (g_is_in_hook) return orig_recv(s, buf, len, flags);
    ScopedHookGuard guard;
    ssize_t ret = orig_recv(s, buf, len, flags);
    if (ret > 0) callback_kotlin((jlong)s, false, buf, ret, false);
    return ret;
}
ssize_t hook_sendto(int s, const void *buf, size_t len, int flags, const struct sockaddr *to, socklen_t tolen) {
    if (g_is_in_hook) return orig_sendto(s, buf, len, flags, to, tolen);
    ScopedHookGuard guard;
    if (callback_kotlin((jlong)s, true, buf, len, false)) { errno = ECONNRESET; return -1; }
    return orig_sendto(s, buf, len, flags, to, tolen);
}
ssize_t hook_recvfrom(int s, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen) {
    if (g_is_in_hook) return orig_recvfrom(s, buf, len, flags, from, fromlen);
    ScopedHookGuard guard;
    ssize_t ret = orig_recvfrom(s, buf, len, flags, from, fromlen);
    if (ret > 0) callback_kotlin((jlong)s, false, buf, ret, false);
    return ret;
}
// v1.31.5 P0-2: hook_write/hook_read 已移除（见文件头注释）——write/read 覆盖文件/管道/eventfd，
//   对 Flutter 引擎高频调用，inline hook 崩溃风险最大；网络数据已由 send/recv/sendto/recvfrom 覆盖。
int hook_close(int fd) {
    if (g_is_in_hook) return orig_close(fd);
    ScopedHookGuard guard;
    bool was_network = false;
    if (fd >= 0 && fd < 65536) {
        // v1.28 P1: 只对已跟踪的网络连接（state==2）通知 Kotlin onConnClosed
        was_network = g_fd_cache[fd].load(std::memory_order_relaxed) == 2;
        g_fd_cache[fd].store(0, std::memory_order_relaxed);
    }
    { std::lock_guard<std::mutex> lock(g_cache_mutex); g_stack_cache.erase((jlong)fd); g_socket_info_cache.erase(fd); }
    if (was_network) notify_kotlin_close((jlong)fd, false);
    return orig_close(fd);
}

// v1.25 P0-3: 公共写逻辑（orig 由调用方传入，SSL_* 与 NativeCrypto_* 各用各的指针）
template<int IDX>
int do_ssl_write_common(void *ssl, const void *buf, int num, type_SSL_write orig) {
    if (orig == nullptr) return -1; // 符号未 hook 成功，绝不应发生（hook 成功才写 orig）
    if (g_is_in_hook) return orig(ssl, buf, num);
    // v1.45.3 P0: 首次数据回调时用 dladdr 解析 SSL_get_fd（dlsym RTLD_DEFAULT 失败场景兜底）
    if (real_SSL_get_fd == nullptr) resolve_ssl_get_fd_via_dladdr((void*)orig);
    ScopedHookGuard guard;
    uintptr_t conn_id = reinterpret_cast<uintptr_t>(ssl);
    // v1.59: 首次数据回调提取 TLS 元数据（版本/SNI/ALPN/算法/证书）——per-ssl 只一次
    collect_tls_meta_once(conn_id, (void*)orig);
    std::shared_ptr<Http2Connection> h2conn = h2_get_or_create(conn_id);
    
    std::vector<std::vector<uint8_t>> local_rst_queue;

    if (h2conn != nullptr && buf != nullptr && num > 0) {
        bool collect = h2conn->h2_checked && h2conn->is_h2 && callback_collect_resp_body();
        auto feed_res = h2_feed(h2conn, static_cast<const uint8_t*>(buf), (size_t)num, true, collect);
        if (!feed_res.early_checks.empty() || !feed_res.data_chunks.empty() || !feed_res.completed.empty()) {
            callback_kotlin_h2(conn_id, feed_res);
        }
        
        auto new_rst = h2_take_rst_frames(conn_id);
        if (!new_rst.empty()) {
            local_rst_queue.insert(local_rst_queue.end(), new_rst.begin(), new_rst.end());
        }
        
        if (h2conn->is_h2) {
            int ret = orig(ssl, buf, num);
            if (ret > 0 && !local_rst_queue.empty()) {
                for (const auto& frame : local_rst_queue) {
                    orig(ssl, frame.data(), (int)frame.size());
                }
            }
            return ret;
        }
    }

    if (buf != nullptr && num > 0) {
        if (callback_kotlin(reinterpret_cast<jlong>(ssl), true, buf, num, true)) {
            return -1;
        }
    }
    
    return orig(ssl, buf, num);
}

template<int IDX>
int hook_SSL_write_t(void *ssl, const void *buf, int num) {
    return do_ssl_write_common<IDX>(ssl, buf, num, g_ssl_hooks[IDX].orig_ssl_write);
}

template<int IDX>
int hook_NativeCrypto_SSL_write_t(void *ssl, const void *buf, int num) {
    return do_ssl_write_common<IDX>(ssl, buf, num, g_ssl_hooks[IDX].orig_native_write);
}

// v1.25 P0-3: 公共读逻辑（orig 由调用方传入）
template<int IDX>
int do_ssl_read_common(void *ssl, void *buf, int num, type_SSL_read orig) {
    if (orig == nullptr) return -1;
    if (g_is_in_hook) return orig(ssl, buf, num);
    // v1.45.3 P0: 首次数据回调时用 dladdr 解析 SSL_get_fd
    if (real_SSL_get_fd == nullptr) resolve_ssl_get_fd_via_dladdr((void*)orig);
    ScopedHookGuard guard;
    // v1.59: 首次数据回调提取 TLS 元数据（版本/SNI/ALPN/算法/证书）
    collect_tls_meta_once(reinterpret_cast<uintptr_t>(ssl), (void*)orig);
    int ret = orig(ssl, buf, num);
    if (ret > 0 && buf != nullptr) {
        uintptr_t conn_id = reinterpret_cast<uintptr_t>(ssl);
        if (h2_is_http2(conn_id)) {
            std::shared_ptr<Http2Connection> h2conn = h2_get_or_create(conn_id);
            if (h2conn != nullptr) {
                bool collect = callback_collect_resp_body();
                auto feed_res = h2_feed(h2conn, static_cast<const uint8_t*>(buf), (size_t)ret, false, collect);
                if (!feed_res.early_checks.empty() || !feed_res.data_chunks.empty() || !feed_res.completed.empty()) {
                    callback_kotlin_h2(conn_id, feed_res);
                }
            }
        } else callback_kotlin(reinterpret_cast<jlong>(ssl), false, buf, ret, true);
    }
    return ret;
}

template<int IDX>
int hook_SSL_read_t(void *ssl, void *buf, int num) {
    return do_ssl_read_common<IDX>(ssl, buf, num, g_ssl_hooks[IDX].orig_ssl_read);
}

template<int IDX>
int hook_NativeCrypto_SSL_read_t(void *ssl, void *buf, int num) {
    return do_ssl_read_common<IDX>(ssl, buf, num, g_ssl_hooks[IDX].orig_native_read);
}

// v1.63 P1-3: SSL_write_ex/SSL_read_ex —— 与 SSL_write/SSL_read 同构（BoringSSL/OpenSSL 1.1.1+）。
//   签名差异：返回 1=成功 0=失败，实际写/读字节数通过 *written/*readbytes 输出。
//   注意：ex 变体成功返回 1，不能像 SSL_write 那样用 ret 当字节数；
//   回调 len 用 *written/*readbytes（成功时）或 num（失败时无数据不回调）。

template<int IDX>
int do_ssl_write_ex_common(void *ssl, const void *buf, size_t num, size_t *written, type_SSL_write_ex orig) {
    if (orig == nullptr) return 0; // 符号未 hook 成功（hook 成功才写 orig）
    if (g_is_in_hook) return orig(ssl, buf, num, written);
    if (real_SSL_get_fd == nullptr) resolve_ssl_get_fd_via_dladdr((void*)orig);
    ScopedHookGuard guard;
    uintptr_t conn_id = reinterpret_cast<uintptr_t>(ssl);
    collect_tls_meta_once(conn_id, (void*)orig);
    std::shared_ptr<Http2Connection> h2conn = h2_get_or_create(conn_id);

    std::vector<std::vector<uint8_t>> local_rst_queue;

    if (h2conn != nullptr && buf != nullptr && num > 0) {
        bool collect = h2conn->h2_checked && h2conn->is_h2 && callback_collect_resp_body();
        auto feed_res = h2_feed(h2conn, static_cast<const uint8_t*>(buf), num, true, collect);
        if (!feed_res.early_checks.empty() || !feed_res.data_chunks.empty() || !feed_res.completed.empty()) {
            callback_kotlin_h2(conn_id, feed_res);
        }
        auto new_rst = h2_take_rst_frames(conn_id);
        if (!new_rst.empty()) {
            local_rst_queue.insert(local_rst_queue.end(), new_rst.begin(), new_rst.end());
        }
        if (h2conn->is_h2) {
            int ret = orig(ssl, buf, num, written);
            if (ret > 0 && !local_rst_queue.empty()) {
                size_t dummy = 0;
                for (const auto& frame : local_rst_queue) {
                    orig(ssl, frame.data(), frame.size(), &dummy);
                }
            }
            return ret;
        }
    }

    if (buf != nullptr && num > 0) {
        if (callback_kotlin(reinterpret_cast<jlong>(ssl), true, buf, num, true)) {
            if (written != nullptr) *written = 0;
            return 0; // 被拦截（block），ex 语义失败=0
        }
    }

    return orig(ssl, buf, num, written);
}

template<int IDX>
int do_ssl_read_ex_common(void *ssl, void *buf, size_t num, size_t *readbytes, type_SSL_read_ex orig) {
    if (orig == nullptr) return 0;
    if (g_is_in_hook) return orig(ssl, buf, num, readbytes);
    if (real_SSL_get_fd == nullptr) resolve_ssl_get_fd_via_dladdr((void*)orig);
    ScopedHookGuard guard;
    collect_tls_meta_once(reinterpret_cast<uintptr_t>(ssl), (void*)orig);
    int ret = orig(ssl, buf, num, readbytes);
    size_t got = (ret > 0 && readbytes != nullptr) ? *readbytes : 0;
    if (got > 0 && buf != nullptr) {
        uintptr_t conn_id = reinterpret_cast<uintptr_t>(ssl);
        if (h2_is_http2(conn_id)) {
            std::shared_ptr<Http2Connection> h2conn = h2_get_or_create(conn_id);
            if (h2conn != nullptr) {
                bool collect = callback_collect_resp_body();
                auto feed_res = h2_feed(h2conn, static_cast<const uint8_t*>(buf), got, false, collect);
                if (!feed_res.early_checks.empty() || !feed_res.data_chunks.empty() || !feed_res.completed.empty()) {
                    callback_kotlin_h2(conn_id, feed_res);
                }
            }
        } else callback_kotlin(reinterpret_cast<jlong>(ssl), false, buf, got, true);
    }
    return ret;
}

template<int IDX>
int hook_SSL_write_ex_t(void *ssl, const void *buf, size_t num, size_t *written) {
    return do_ssl_write_ex_common<IDX>(ssl, buf, num, written, g_ssl_hooks[IDX].orig_ssl_write_ex);
}

template<int IDX>
int hook_SSL_read_ex_t(void *ssl, void *buf, size_t num, size_t *readbytes) {
    return do_ssl_read_ex_common<IDX>(ssl, buf, num, readbytes, g_ssl_hooks[IDX].orig_ssl_read_ex);
}

// v1.25 P0-3: 公共释放逻辑（orig 由调用方传入）
template<int IDX>
void do_ssl_free_common(void *ssl, type_SSL_free orig) {
    if (orig == nullptr) return;
    if (g_is_in_hook) { orig(ssl); return; }
    ScopedHookGuard guard;
    { std::lock_guard<std::mutex> lock(g_cache_mutex); g_stack_cache.erase(reinterpret_cast<jlong>(ssl)); }
    // v1.62 P1-2: notify_kotlin_close 必须先于 g_ssl_fd_map.erase——
    //   close 通知内部 get_ssl_fd_from_hook((uintptr_t)id) 依赖 fd 映射还在；
    //   此前先 erase 后通知 → fd=0 → Java 侧 onConnectionClosed 拿不到四元组
    //   （且 fd=0 绕过 is_self_internal 检查，自家连接 close 也会进 Java 回调）。
    notify_kotlin_close(reinterpret_cast<jlong>(ssl), true);
    // v1.45.6: 清理 SSL_set_fd 记录的 ssl→fd 映射
    { std::lock_guard<std::mutex> lock(g_ssl_fd_mutex); g_ssl_fd_map.erase(reinterpret_cast<uintptr_t>(ssl)); }
    // v1.59: 清理 TLS 元数据 per-ssl 标记（防指针复用）
    { std::lock_guard<std::mutex> lock(g_tls_meta_mutex); g_tls_meta_done.erase(reinterpret_cast<uintptr_t>(ssl)); g_tls_meta_attempts.erase(reinterpret_cast<uintptr_t>(ssl)); }
    h2_free(reinterpret_cast<uintptr_t>(ssl));
    orig(ssl);
}

template<int IDX>
void hook_SSL_free_t(void *ssl) {
    do_ssl_free_common<IDX>(ssl, g_ssl_hooks[IDX].orig_ssl_free);
}

template<int IDX>
void hook_NativeCrypto_SSL_free_t(void *ssl) {
    do_ssl_free_common<IDX>(ssl, g_ssl_hooks[IDX].orig_native_free);
}

static type_SSL_write ssl_write_hooks[] = { hook_SSL_write_t<0>, hook_SSL_write_t<1>, hook_SSL_write_t<2>, hook_SSL_write_t<3> };
static type_SSL_read ssl_read_hooks[] = { hook_SSL_read_t<0>, hook_SSL_read_t<1>, hook_SSL_read_t<2>, hook_SSL_read_t<3> };
static type_SSL_free ssl_free_hooks[] = { hook_SSL_free_t<0>, hook_SSL_free_t<1>, hook_SSL_free_t<2>, hook_SSL_free_t<3> };
// v1.63 P1-3: ex 变体 hooks 数组
static type_SSL_write_ex ssl_write_ex_hooks[] = { hook_SSL_write_ex_t<0>, hook_SSL_write_ex_t<1>, hook_SSL_write_ex_t<2>, hook_SSL_write_ex_t<3> };
static type_SSL_read_ex ssl_read_ex_hooks[] = { hook_SSL_read_ex_t<0>, hook_SSL_read_ex_t<1>, hook_SSL_read_ex_t<2>, hook_SSL_read_ex_t<3> };
static type_SSL_write native_write_hooks[] = { hook_NativeCrypto_SSL_write_t<0>, hook_NativeCrypto_SSL_write_t<1>, hook_NativeCrypto_SSL_write_t<2>, hook_NativeCrypto_SSL_write_t<3> };
static type_SSL_read native_read_hooks[] = { hook_NativeCrypto_SSL_read_t<0>, hook_NativeCrypto_SSL_read_t<1>, hook_NativeCrypto_SSL_read_t<2>, hook_NativeCrypto_SSL_read_t<3> };
static type_SSL_free native_free_hooks[] = { hook_NativeCrypto_SSL_free_t<0>, hook_NativeCrypto_SSL_free_t<1>, hook_NativeCrypto_SSL_free_t<2>, hook_NativeCrypto_SSL_free_t<3> };

// v1.30.4: native→Java 日志桥——shadowhook init/hook 结果写 LogStore，任意线程可调
static void native_log(const char* msg) {
    if (msg == nullptr) return;
    if (gNativeRequestHookClass == nullptr || gNativeLogMethod == nullptr) return;
    JNIEnv* env = nullptr;
    bool need_detach = false;
    jint attach = gJvm->GetEnv((void**)&env, JNI_VERSION_1_6);
    if (attach == JNI_EDETACHED) {
        if (gJvm->AttachCurrentThread(&env, nullptr) != JNI_OK) return;
        need_detach = true;
    }
    if (env == nullptr) return;
    jstring jmsg = env->NewStringUTF(msg);
    if (jmsg != nullptr) {
        env->CallStaticVoidMethod(gNativeRequestHookClass, gNativeLogMethod, jmsg);
        env->DeleteLocalRef(jmsg);
    }
    if (need_detach) gJvm->DetachCurrentThread();
}

// v1.45.4 P0: SSL_get_fd 解析终极方案——dlsym(RTLD_DEFAULT) 失败（目标 App SSL 库 RTLD_LOCAL
//   加载/内置，符号不进全局表）；dladdr 也被 Android 对 zip 内 so 误判（返回自身库）。
//   最终方案：遍历 /proc/self/maps 收集所有 .so 路径 → 逐个 dlopen(RTLD_NOLOAD) 拿句柄 →
//   dlsym(句柄, "SSL_get_fd")。RTLD_NOLOAD 返回已加载库的句柄，dlsym 沿句柄依赖链查找，
//   RTLD_LOCAL/GLOBAL 完全不影响；命中一次即缓存。
static long now_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// v1.47 P2-2: 删除 v1.45.5/v1.45.6 遗留死代码 gnu_hash_name + find_ssl_get_fd_via_phdr +
//   resolve_ssl_get_fd_scan（v1.46.0 起由 resolve_ssl_get_fd_via_dladdr 单次尝试取代，
//   全库 phdr/maps 扫描在 Conscrypt 场景必然失败且每 2s 重扫拖崩目标进程——见 v1.46.0 注释）

// v1.45.6 P0: SSL_set_fd hook——标准 TLS 流程 SSL_new→SSL_set_fd(ssl,fd) 必有，直接记录 ssl→fd
//   映射，绕开 SSL_get_fd 符号解析（跨库/namespace 全免疫）。v1.47 P2-2 曾误删本函数签名，已恢复。
static int hook_SSL_set_fd(void *ssl, int fd) {
    if (ssl != nullptr && fd > 0) {
        std::lock_guard<std::mutex> lock(g_ssl_fd_mutex);
        g_ssl_fd_map[reinterpret_cast<uintptr_t>(ssl)] = fd;
    }
    if (orig_ssl_set_fd != nullptr) return orig_ssl_set_fd(ssl, fd);
    return 0;
}

// v1.45.6 P0: callback 里查 ssl→fd 映射（SSL_set_fd 记录的），查不到再用 SSL_get_fd
static int get_ssl_fd_from_hook(uintptr_t ssl_ptr) {
    {
        std::lock_guard<std::mutex> lock(g_ssl_fd_mutex);
        auto it = g_ssl_fd_map.find(ssl_ptr);
        if (it != g_ssl_fd_map.end()) return it->second;
    }
    if (real_SSL_get_fd != nullptr) {
        int fd = real_SSL_get_fd((const void*)ssl_ptr);
        if (fd > 0) return fd;
    }
    return -1;
}
// v1.47 P2-2: 死代码 resolve_ssl_get_fd_scan 已删除（见上）
// v1.46.0 P0 (闪退根治): SSL_get_fd 解析只尝试一次，失败永久放弃。
//   真机铁证：目标 App 走 Conscrypt（Android 系统 TLS），SSL 用内存 BIO，
//   SSL_get_fd 不在任何 so 的动态符号表（静态链接/隐藏符号）——phdr 485 so + maps + dlopen
//   全库扫描必然失败，且每次遍历 485 个 so 拿 linker 锁、做 ELF 解析，播放视频时 SSL
//   高频回调每 2 秒触发一次重扫 → 目标进程崩溃（02:33:46 scan FAIL -> 02:33:47 进程死）。
//   v1.45.6 的 SSL_set_fd 映射 hook 在 Conscrypt 场景同样拿不到（从不调用 SSL_set_fd）。
//   正确方向：pcap 无四元组时用占位地址照常导出明文（见 PcapWriter.feed v1.46.0）。
static void resolve_ssl_get_fd_via_dladdr(void* sym) {
    static std::atomic<bool> g_ssl_fd_resolve_tried{false};
    if (g_ssl_fd_resolve_tried.load(std::memory_order_relaxed)) return;
    g_ssl_fd_resolve_tried.store(true, std::memory_order_relaxed);
    if (real_SSL_get_fd != nullptr || sym == nullptr) return;
    // 仅保留 dladdr 轻量一次尝试（个别机型动态导出场景能成功，无副作用）
    Dl_info info;
    if (dladdr(sym, &info) != 0 && info.dli_fname != nullptr) {
        void* h = dlopen(info.dli_fname, RTLD_NOW | RTLD_NOLOAD);
        if (h != nullptr) {
            real_SSL_get_fd = (type_SSL_get_fd)dlsym(h, "SSL_get_fd");
            if (real_SSL_get_fd != nullptr) {
                char buf[256];
                snprintf(buf, sizeof(buf), "XH pcap: SSL_get_fd resolved via dladdr %s", info.dli_fname);
                native_log(buf);
                dlclose(h);
                return;
            }
            dlclose(h);
        }
    }
    native_log("XH pcap: SSL_get_fd resolve failed (skip scan - Conscrypt static sym, avoid crash)");
}

// ================= v1.59: TLS 元数据 + 服务端证书提取 =================
// 总览页对齐小黄鸟：TLS 版本/SNI/ALPN/算法列表/选择算法 + 证书 Subject/Issuer/序列号/指纹/有效期。
// 安全策略与 v1.45.3 相同：所有符号从 orig 回调函数所在库 dladdr+dlsym 解析（同库实例安全），
// 任一符号缺失只跳过对应字段；per-ssl 只提取一次；全程空指针检查，绝不崩溃。
typedef const char* (*type_SSL_get_version)(const void* ssl);
typedef const char* (*type_SSL_get_servername)(const void* ssl, int type);
typedef int  (*type_SSL_get_alpn_selected)(const void* ssl, const unsigned char** data, unsigned int* len);
typedef void* (*type_SSL_get_current_cipher)(const void* ssl);
typedef const char* (*type_SSL_CIPHER_get_name)(const void* cipher);
typedef void* (*type_SSL_get_ciphers)(const void* ssl);
typedef int  (*type_sk_SSL_CIPHER_num)(const void* sk);
typedef void* (*type_sk_SSL_CIPHER_value)(const void* sk, int i);
typedef void* (*type_SSL_get1_peer_certificate)(const void* ssl);
typedef void  (*type_X509_free)(void* x509);
typedef void* (*type_X509_get_subject_name)(const void* x509);
typedef void* (*type_X509_get_issuer_name)(const void* x509);
typedef int  (*type_X509_NAME_get_text_by_NID)(const void* name, int nid, char* buf, int len);
typedef void* (*type_X509_get_serialNumber)(const void* x509);
typedef long (*type_ASN1_INTEGER_get)(const void* a);
typedef void* (*type_X509_get0_notBefore)(const void* x509);
typedef void* (*type_X509_get0_notAfter)(const void* x509);
typedef int  (*type_ASN1_TIME_to_tm)(const void* t, void* tm);
typedef int  (*type_X509_digest)(const void* x509, const void* md, unsigned char* out, unsigned int* outlen);
typedef const void* (*type_EVP_sha256)(void);

struct TlsMetaSymbols {
    type_SSL_get_version get_version;
    type_SSL_get_servername get_servername;
    type_SSL_get_alpn_selected get_alpn_selected;
    type_SSL_get_current_cipher get_current_cipher;
    type_SSL_CIPHER_get_name cipher_get_name;
    type_SSL_get_ciphers get_ciphers;
    type_sk_SSL_CIPHER_num sk_num;
    type_sk_SSL_CIPHER_value sk_value;
    type_SSL_get1_peer_certificate get1_peer_cert;
    type_X509_free x509_free;
    type_X509_get_subject_name x509_get_subject_name;
    type_X509_get_issuer_name x509_get_issuer_name;
    type_X509_NAME_get_text_by_NID name_get_text_by_nid;
    type_X509_get_serialNumber x509_get_serial;
    type_ASN1_INTEGER_get asn1_integer_get;
    type_X509_get0_notBefore x509_get_notbefore;
    type_X509_get0_notAfter x509_get_notafter;
    type_ASN1_TIME_to_tm asn1_time_to_tm;
    type_X509_digest x509_digest;
    type_EVP_sha256 evp_sha256;
};

static TlsMetaSymbols g_tls_syms;
static std::atomic<bool> g_tls_syms_tried{false};

// OpenSSL 标准 NID（BoringSSL 相同）
#define NID_commonName 13
#define NID_countryName 14
#define NID_localityName 15
#define NID_stateOrProvinceName 16
#define NID_organizationName 17
#define NID_organizationalUnitName 18
#define TLSEXT_NAMETYPE_host_name 0

static void resolve_tls_meta_symbols(void* sym) {
    if (g_tls_syms_tried.load(std::memory_order_relaxed)) return;
    g_tls_syms_tried.store(true, std::memory_order_relaxed);
    Dl_info info;
    if (dladdr(sym, &info) != 0 && info.dli_fname != nullptr) {
        void* h = dlopen(info.dli_fname, RTLD_NOW | RTLD_NOLOAD);
        if (h != nullptr) {
            g_tls_syms.get_version        = (type_SSL_get_version)dlsym(h, "SSL_get_version");
            g_tls_syms.get_servername     = (type_SSL_get_servername)dlsym(h, "SSL_get_servername");
            g_tls_syms.get_alpn_selected  = (type_SSL_get_alpn_selected)dlsym(h, "SSL_get_alpn_selected");
            g_tls_syms.get_current_cipher = (type_SSL_get_current_cipher)dlsym(h, "SSL_get_current_cipher");
            g_tls_syms.cipher_get_name    = (type_SSL_CIPHER_get_name)dlsym(h, "SSL_CIPHER_get_name");
            g_tls_syms.get_ciphers        = (type_SSL_get_ciphers)dlsym(h, "SSL_get_ciphers");
            g_tls_syms.sk_num             = (type_sk_SSL_CIPHER_num)dlsym(h, "sk_SSL_CIPHER_num");
            g_tls_syms.sk_value           = (type_sk_SSL_CIPHER_value)dlsym(h, "sk_SSL_CIPHER_value");
            g_tls_syms.get1_peer_cert     = (type_SSL_get1_peer_certificate)dlsym(h, "SSL_get1_peer_certificate");
            g_tls_syms.x509_free          = (type_X509_free)dlsym(h, "X509_free");
            g_tls_syms.x509_get_subject_name = (type_X509_get_subject_name)dlsym(h, "X509_get_subject_name");
            g_tls_syms.x509_get_issuer_name  = (type_X509_get_issuer_name)dlsym(h, "X509_get_issuer_name");
            g_tls_syms.name_get_text_by_nid  = (type_X509_NAME_get_text_by_NID)dlsym(h, "X509_NAME_get_text_by_NID");
            g_tls_syms.x509_get_serial       = (type_X509_get_serialNumber)dlsym(h, "X509_get_serialNumber");
            g_tls_syms.asn1_integer_get      = (type_ASN1_INTEGER_get)dlsym(h, "ASN1_INTEGER_get");
            g_tls_syms.x509_get_notbefore    = (type_X509_get0_notBefore)dlsym(h, "X509_get0_notBefore");
            g_tls_syms.x509_get_notafter     = (type_X509_get0_notAfter)dlsym(h, "X509_get0_notAfter");
            g_tls_syms.asn1_time_to_tm       = (type_ASN1_TIME_to_tm)dlsym(h, "ASN1_TIME_to_tm");
            g_tls_syms.x509_digest           = (type_X509_digest)dlsym(h, "X509_digest");
            g_tls_syms.evp_sha256            = (type_EVP_sha256)dlsym(h, "EVP_sha256");
            dlclose(h);
        }
    }
    // 解析失败静默（只丢元数据，不影响抓包主链路）
}

static std::string json_escape(const std::string& s) {
    std::ostringstream o;
    for (size_t i = 0; i < s.size(); i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
            case '"': o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\n': o << "\\n"; break;
            case '\r': o << "\\r"; break;
            case '\t': o << "\\t"; break;
            default:
                if (c < 0x20) o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c << std::dec;
                else o << s[i];
        }
    }
    return o.str();
}

// 取证书 DN 的指定 NID 字段（最多取 3 个同名项，如多个 CN 时取第一个非空）
static std::string x509_name_field(const void* name, int nid, type_X509_NAME_get_text_by_NID fn) {
    char buf[256];
    int len = fn(name, nid, buf, sizeof(buf) - 1);
    if (len > 0) { buf[len] = 0; return std::string(buf); }
    return "";
}

static std::string asn1_time_str(const void* t, type_ASN1_TIME_to_tm fn) {
    struct tm tm_val;
    memset(&tm_val, 0, sizeof(tm_val));
    if (t != nullptr && fn != nullptr && fn(t, &tm_val) == 1) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
                 tm_val.tm_year + 1900, tm_val.tm_mon + 1, tm_val.tm_mday,
                 tm_val.tm_hour, tm_val.tm_min, tm_val.tm_sec);
        return std::string(buf);
    }
    return "";
}

static std::string build_tls_meta_json(const void* ssl) {
    const TlsMetaSymbols& s = g_tls_syms;
    std::ostringstream o;
    o << "{";

    bool any = false;
    if (s.get_version != nullptr) {
        const char* v = s.get_version(ssl);
        if (v != nullptr) { o << "\"v\":\"" << json_escape(v) << "\""; any = true; }
    }
    if (s.get_servername != nullptr) {
        const char* sni = s.get_servername(ssl, TLSEXT_NAMETYPE_host_name);
        if (sni != nullptr) {
            if (any) o << ",";
            o << "\"sni\":\"" << json_escape(sni) << "\""; any = true;
        }
    }
    if (s.get_alpn_selected != nullptr) {
        const unsigned char* data = nullptr;
        unsigned int len = 0;
        if (s.get_alpn_selected(ssl, &data, &len) == 1 && data != nullptr && len > 0) {
            std::string alpn((const char*)data, len);
            if (any) o << ",";
            o << "\"alpn\":\"" << json_escape(alpn) << "\""; any = true;
        }
    }
    // 选择算法 + 算法列表
    std::string cipher_sel;
    std::string cipher_list;
    if (s.get_current_cipher != nullptr && s.cipher_get_name != nullptr) {
        void* c = s.get_current_cipher(ssl);
        if (c != nullptr) {
            const char* name = s.cipher_get_name(c);
            if (name != nullptr) cipher_sel = name;
        }
    }
    if (s.get_ciphers != nullptr && s.sk_num != nullptr && s.sk_value != nullptr && s.cipher_get_name != nullptr) {
        void* sk = s.get_ciphers(ssl);
        if (sk != nullptr) {
            int n = s.sk_num(sk);
            if (n > 64) n = 64; // 只取前 64 个防超大
            for (int i = 0; i < n; i++) {
                void* c = s.sk_value(sk, i);
                if (c != nullptr) {
                    const char* name = s.cipher_get_name(c);
                    if (name != nullptr) {
                        if (!cipher_list.empty()) cipher_list += ";";
                        cipher_list += name;
                    }
                }
            }
        }
    }
    if (!cipher_sel.empty()) { if (any) o << ","; o << "\"cipher\":\"" << json_escape(cipher_sel) << "\""; any = true; }
    if (!cipher_list.empty()) { if (any) o << ","; o << "\"ciphers\":\"" << json_escape(cipher_list) << "\""; any = true; }

    // 服务端证书（SSL_get1_peer_certificate 引用计数 +1，必须 X509_free）
    // v1.61: +DN 细分字段（subjectCn/C/St/L/O/Ou + issuerCn/C/O），供小黄鸟式证书板块
    if (s.get1_peer_cert != nullptr && s.x509_free != nullptr) {
        void* x509 = s.get1_peer_cert(ssl);
        if (x509 != nullptr) {
            std::string subject, issuer, serial, sha256, not_before, not_after;
            std::string subj_cn, subj_c, subj_st, subj_l, subj_o, subj_ou;
            std::string iss_cn, iss_c, iss_o;
            if (s.x509_get_subject_name != nullptr && s.name_get_text_by_nid != nullptr) {
                void* sn = s.x509_get_subject_name(x509);
                if (sn != nullptr) {
                    std::string cn = x509_name_field(sn, NID_commonName, s.name_get_text_by_nid);
                    std::string c  = x509_name_field(sn, NID_countryName, s.name_get_text_by_nid);
                    std::string st = x509_name_field(sn, NID_stateOrProvinceName, s.name_get_text_by_nid);
                    std::string l  = x509_name_field(sn, NID_localityName, s.name_get_text_by_nid);
                    std::string o  = x509_name_field(sn, NID_organizationName, s.name_get_text_by_nid);
                    std::string ou = x509_name_field(sn, NID_organizationalUnitName, s.name_get_text_by_nid);
                    if (!c.empty())  subject += "C=" + c;
                    if (!st.empty()) subject += (subject.empty() ? "" : ";") + std::string("ST=") + st;
                    if (!l.empty())  subject += (subject.empty() ? "" : ";") + std::string("L=") + l;
                    if (!o.empty())  subject += (subject.empty() ? "" : ";") + std::string("O=") + o;
                    if (!ou.empty()) subject += (subject.empty() ? "" : ";") + std::string("OU=") + ou;
                    if (!cn.empty()) subject += (subject.empty() ? "" : ";") + std::string("CN=") + cn;
                    subj_cn = cn; subj_c = c; subj_st = st; subj_l = l; subj_o = o; subj_ou = ou;
                }
            }
            if (s.x509_get_issuer_name != nullptr && s.name_get_text_by_nid != nullptr) {
                void* in = s.x509_get_issuer_name(x509);
                if (in != nullptr) {
                    std::string cn = x509_name_field(in, NID_commonName, s.name_get_text_by_nid);
                    std::string c  = x509_name_field(in, NID_countryName, s.name_get_text_by_nid);
                    std::string o  = x509_name_field(in, NID_organizationName, s.name_get_text_by_nid);
                    if (!c.empty()) issuer += "C=" + c;
                    if (!o.empty()) issuer += (issuer.empty() ? "" : ";") + std::string("O=") + o;
                    if (!cn.empty()) issuer += (issuer.empty() ? "" : ";") + std::string("CN=") + cn;
                    iss_cn = cn; iss_c = c; iss_o = o;
                }
            }
            if (s.x509_get_serial != nullptr && s.asn1_integer_get != nullptr) {
                void* a = s.x509_get_serial(x509);
                if (a != nullptr) {
                    long v = s.asn1_integer_get(a);
                    char buf[40];
                    snprintf(buf, sizeof(buf), "0x%lx", v);
                    serial = buf;
                }
            }
            if (s.x509_digest != nullptr && s.evp_sha256 != nullptr) {
                unsigned char md[32];
                unsigned int mdlen = 0;
                if (s.x509_digest(x509, s.evp_sha256(), md, &mdlen) == 1 && mdlen >= 16) {
                    std::ostringstream hx;
                    for (unsigned int i = 0; i < mdlen; i++) {
                        if (i) hx << ":";
                        hx << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (int)md[i];
                    }
                    sha256 = hx.str();
                }
            }
            if (s.x509_get_notbefore != nullptr) not_before = asn1_time_str(s.x509_get_notbefore(x509), s.asn1_time_to_tm);
            if (s.x509_get_notafter != nullptr)  not_after  = asn1_time_str(s.x509_get_notafter(x509), s.asn1_time_to_tm);

            if (any) o << ",";
            o << "\"cert\":{\"subject\":\"" << json_escape(subject) << "\",\"issuer\":\"" << json_escape(issuer)
              << "\",\"serial\":\"" << json_escape(serial) << "\",\"sha256\":\"" << json_escape(sha256)
              << "\",\"notBefore\":\"" << json_escape(not_before) << "\",\"notAfter\":\"" << json_escape(not_after)
              << "\",\"subjectCn\":\"" << json_escape(subj_cn) << "\",\"subjectC\":\"" << json_escape(subj_c)
              << "\",\"subjectSt\":\"" << json_escape(subj_st) << "\",\"subjectL\":\"" << json_escape(subj_l)
              << "\",\"subjectO\":\"" << json_escape(subj_o) << "\",\"subjectOu\":\"" << json_escape(subj_ou)
              << "\",\"issuerCn\":\"" << json_escape(iss_cn) << "\",\"issuerC\":\"" << json_escape(iss_c)
              << "\",\"issuerO\":\"" << json_escape(iss_o) << "\"}";
            any = true;

            s.x509_free(x509);
        }
    }

    o << "}";
    if (!any) return "";
    return o.str();
}

// v1.59: 首次数据回调提取 TLS 元数据（per-ssl 只一次）
// v1.60 P0 修复: 原实现"首次数据回调即永久标记 done"——但首次回调是握手阶段（ClientHello/ServerHello），
//   SSL_get1_peer_certificate 返回 null、SSL_get_version 可能尚未协商完成 → json 空 → 但 g_tls_meta_done
//   已 insert → 后续永不提取 → 详情页 TLS/证书分区永远为空（用户截图实锤）。
//   修法: 只有提取到**证书（sha256 非空）**才算成功才标记 done；空结果/仅 v+sni（握手早期）不标记，
//   握手完成后的下一次数据回调再试（每次数据回调都会调本函数，见 do_ssl_write/read_common）。
//   尝试次数上限 12 次兜底：符号解析失败/握手失败场景防每次数据回调都 build 的开销。
static void collect_tls_meta_once(uintptr_t conn_id, void* orig_sym) {
    if (gNativeRequestHookClass == nullptr || gOnTlsMetaMethod == nullptr) return;
    {
        std::lock_guard<std::mutex> lock(g_tls_meta_mutex);
        if (g_tls_meta_done.count(conn_id) > 0) return; // 已成功提取过
    }
    resolve_tls_meta_symbols(orig_sym);
    std::string json = build_tls_meta_json((const void*)conn_id);
    // 成功条件：json 非空 且 含证书 sha256 非空（握手完成才有；v/sni 早期也有但证书才是完整标志）
    bool hasCert = !json.empty() && json.find("\"cert\":{") != std::string::npos
                   && json.find("\"sha256\":\"\"") == std::string::npos;
    if (hasCert) {
        JNIEnv* env = get_jni_env();
        if (env == nullptr) return;
        jstring jMeta = env->NewStringUTF(json.c_str());
        if (jMeta != nullptr) {
            env->CallStaticVoidMethod(gNativeRequestHookClass, gOnTlsMetaMethod, (jlong)conn_id, jMeta);
            env->DeleteLocalRef(jMeta);
        }
        check_exception(env);
        { std::lock_guard<std::mutex> lock(g_tls_meta_mutex); g_tls_meta_done.insert(conn_id); }
        return;
    }
    // 未成功：尝试次数上限兜底（防符号解析失败时每次数据回调都 build）
    {
        std::lock_guard<std::mutex> lock(g_tls_meta_mutex);
        int n = ++g_tls_meta_attempts[conn_id];
        if (n >= 12) g_tls_meta_done.insert(conn_id); // 放弃，标记防重复尝试
    }
}

// ================= v1.38 P0-2/P0-3: BoringSSL verify 绕过 + keylog =================
// hooker just_trust_me.js (native 部分) + find_boringssl_custom_verify_func.js + ssl_log.js 借鉴
// 符号在 libssl.so（BoringSSL），xhook PLT/GOT hook 对调用方生效（libconscrypt_jni 等 GOT 表项）
typedef int (*ssl_verify_callback_t)(void *ssl, uint8_t *out_alert);   // ssl_verify_ok=0, invalid=1, retry=2
typedef int (*type_SSL_CTX_set_custom_verify)(void *ctx, int mode, ssl_verify_callback_t cb);
typedef void (*type_SSL_CTX_set_verify)(void *ctx, int mode, void *cb);
typedef void (*type_SSL_set_verify)(void *ssl, int mode, void *cb);
typedef int (*type_SSL_CTX_set_cert_verify_callback)(void *ctx, void *cb, void *arg);
typedef long (*type_SSL_get_verify_result)(const void *ssl);
typedef void (*ssl_keylog_callback_t)(const void *ssl, const char *line);
typedef void (*type_SSL_CTX_set_keylog_callback)(void *ctx, ssl_keylog_callback_t cb);
typedef void* (*type_SSL_get_SSL_CTX)(const void *ssl);
typedef void* (*type_SSL_new)(void *ctx);

static type_SSL_CTX_set_custom_verify orig_ctx_set_custom_verify = nullptr;
static type_SSL_CTX_set_verify orig_ctx_set_verify = nullptr;
static type_SSL_set_verify orig_ssl_set_verify = nullptr;
static type_SSL_CTX_set_cert_verify_callback orig_ctx_set_cert_verify = nullptr;
static type_SSL_get_verify_result orig_ssl_get_verify_result = nullptr;
static type_SSL_CTX_set_keylog_callback orig_ctx_set_keylog = nullptr;
static type_SSL_new orig_ssl_new = nullptr;
// dlsym 拿真实函数指针（在 hook 回调里调用原函数用；走 GOT 会触发 xhook 递归）
static type_SSL_get_SSL_CTX real_SSL_get_SSL_CTX = nullptr;
static type_SSL_CTX_set_keylog_callback real_ctx_set_keylog = nullptr;

// v1.62 P2-13: keylog 同库解析——与 v1.45.6 SSL_get_fd 同款修复。
//   此前 real_SSL_get_SSL_CTX / real_ctx_set_keylog 用 dlsym(RTLD_DEFAULT) 拿：
//   目标进程同时加载系统 BoringSSL + App 私有 SSL 库时，RTLD_DEFAULT 命中第一个
//   导出符号的库（通常是系统 BoringSSL），而 ssl 对象来自 App 私有库（xhook 按符号名
//   全库 hook）→ 跨库调用 SSL_get_SSL_CTX 返回垃圾 ctx / set_keylog 不生效。
//   改为与 orig_ssl_new 同库解析（dladdr + dlopen RTLD_NOLOAD + dlsym）。
static void resolve_keylog_via_dladdr(void* sym) {
    static std::atomic<bool> g_keylog_resolve_tried{false};
    if (g_keylog_resolve_tried.load(std::memory_order_relaxed)) return;
    g_keylog_resolve_tried.store(true, std::memory_order_relaxed);
    if (real_SSL_get_SSL_CTX != nullptr && real_ctx_set_keylog != nullptr) return;
    if (sym == nullptr) return;
    Dl_info info;
    if (dladdr(sym, &info) != 0 && info.dli_fname != nullptr) {
        void* h = dlopen(info.dli_fname, RTLD_NOW | RTLD_NOLOAD);
        if (h != nullptr) {
            if (real_SSL_get_SSL_CTX == nullptr)
                real_SSL_get_SSL_CTX = (type_SSL_get_SSL_CTX)dlsym(h, "SSL_get_SSL_CTX");
            if (real_ctx_set_keylog == nullptr)
                real_ctx_set_keylog = (type_SSL_CTX_set_keylog_callback)dlsym(h, "SSL_CTX_set_keylog_callback");
            char buf[256];
            snprintf(buf, sizeof(buf), "XH keylog: resolve via dladdr %s (ctx=%p set=%p)",
                     info.dli_fname, (void*)real_SSL_get_SSL_CTX, (void*)real_ctx_set_keylog);
            native_log(buf);
            dlclose(h);
            return;
        }
    }
    // 兜底：保留 init 时 RTLD_DEFAULT 已拿到的（单 SSL 库场景仍有效）
    native_log("XH keylog: dladdr resolve fail, keep RTLD_DEFAULT ptrs");
}

// BoringSSL: ssl_verify_ok = 0
static int always_verify_ok(void *ssl, uint8_t *out_alert) { return 0; }
// SSL_CTX_set_cert_verify_callback 回调：返回 1 = 验证通过
static int always_cert_ok(void *store, void *arg) { return 1; }

// keylog 回调：CLIENT_RANDOM <64hex> <96hex> → Java NativeProbe.nativeKeylog(String)
static void keylog_cb(const void *ssl, const char *line) {
    if (line == nullptr) return;
    if (gNativeRequestHookClass == nullptr || gNativeKeylogMethod == nullptr) return;
    JNIEnv* env = nullptr;
    bool need_detach = false;
    jint attach = gJvm->GetEnv((void**)&env, JNI_VERSION_1_6);
    if (attach == JNI_EDETACHED) {
        if (gJvm->AttachCurrentThread(&env, nullptr) != JNI_OK) return;
        need_detach = true;
    }
    if (env == nullptr) return;
    jstring jline = env->NewStringUTF(line);
    if (jline != nullptr) {
        env->CallStaticVoidMethod(gNativeRequestHookClass, gNativeKeylogMethod, jline);
        env->DeleteLocalRef(jline);
    }
    if (need_detach) gJvm->DetachCurrentThread();
}

// P0-2: 自定义 verify 回调替换——无论 app 设置什么 verify 回调，都换成总是通过
static int hook_SSL_CTX_set_custom_verify(void *ctx, int mode, ssl_verify_callback_t cb) {
    if (orig_ctx_set_custom_verify == nullptr) return -1;
    if (g_is_in_hook) return orig_ctx_set_custom_verify(ctx, mode, cb);
    ScopedHookGuard guard;
    native_log("BoringSSL: SSL_CTX_set_custom_verify intercepted (verify -> always OK)");
    return orig_ctx_set_custom_verify(ctx, mode, always_verify_ok);
}
// P0-2: verify mode 强制 SSL_VERIFY_NONE(0)
static void hook_SSL_CTX_set_verify(void *ctx, int mode, void *cb) {
    if (orig_ctx_set_verify == nullptr) return;
    if (g_is_in_hook) { orig_ctx_set_verify(ctx, mode, cb); return; }
    ScopedHookGuard guard;
    native_log("BoringSSL: SSL_CTX_set_verify intercepted (mode -> SSL_VERIFY_NONE)");
    orig_ctx_set_verify(ctx, 0, cb);
}
static void hook_SSL_set_verify(void *ssl, int mode, void *cb) {
    if (orig_ssl_set_verify == nullptr) return;
    if (g_is_in_hook) { orig_ssl_set_verify(ssl, mode, cb); return; }
    ScopedHookGuard guard;
    orig_ssl_set_verify(ssl, 0, cb);
}
// P0-2: cert verify callback 替换为总是返回 1
static int hook_SSL_CTX_set_cert_verify_callback(void *ctx, void *cb, void *arg) {
    if (orig_ctx_set_cert_verify == nullptr) return -1;
    if (g_is_in_hook) return orig_ctx_set_cert_verify(ctx, cb, arg);
    ScopedHookGuard guard;
    native_log("BoringSSL: SSL_CTX_set_cert_verify_callback intercepted (always OK)");
    return orig_ctx_set_cert_verify(ctx, (void*)always_cert_ok, arg);
}
// P0-2: 手动查 verify_result 强制返回 X509_V_OK(0)
static long hook_SSL_get_verify_result(const void *ssl) {
    if (orig_ssl_get_verify_result == nullptr) return 0;
    if (g_is_in_hook) return orig_ssl_get_verify_result(ssl);
    ScopedHookGuard guard;
    return 0; // X509_V_OK
}

// P0-3: set_keylog_callback 拦截——无论 app 设置什么，都换成我们的 keylog 回调
static void hook_SSL_CTX_set_keylog_callback(void *ctx, ssl_keylog_callback_t cb) {
    if (orig_ctx_set_keylog == nullptr) return;
    if (g_is_in_hook) { orig_ctx_set_keylog(ctx, cb); return; }
    ScopedHookGuard guard;
    native_log("BoringSSL: SSL_CTX_set_keylog_callback intercepted (keylog enabled)");
    orig_ctx_set_keylog(ctx, keylog_cb);
}
// P0-3: SSL_new 时主动给 ctx 设置 keylog（即使 app 从不调用 set_keylog_callback）
//   real_SSL_get_SSL_CTX / real_ctx_set_keylog 是 dlsym 真实指针，不触发 xhook 递归
static void* hook_SSL_new(void *ctx) {
    if (orig_ssl_new == nullptr) return nullptr;
    if (g_is_in_hook) return orig_ssl_new(ctx);
    // v1.45.2 P0: SSL_get_fd 延迟解析——init 时 libssl.so 可能尚未加载导致 dlsym(RTLD_DEFAULT) 失败，
    //   real_SSL_get_fd=nullptr → SSL 回调拿不到 fd → socketInfo 全 null → pcap 永远 0 数据。
    //   SSL_new 被调用时 libssl.so 必已加载，此刻解析必成功（xhook 延迟补挂已生效）。
    // v1.45.6 P0: 改为 orig_ssl_new 同库解析（resolve_ssl_get_fd_via_dladdr 内部先 dladdr 后 phdr 同库）。
    //   不再用 dlsym(RTLD_DEFAULT)——那可能拿到系统 BoringSSL 的 SSL_get_fd，而 ssl 对象来自
    //   App 私有 SSL 库（xhook 按符号名全库 hook），跨库调用返回垃圾 fd（v1.45.5 真机 NOEP 根因）。
    if (real_SSL_get_fd == nullptr) {
        resolve_ssl_get_fd_via_dladdr((void*)orig_ssl_new);
    }
    // v1.62 P2-13: keylog 也改同库解析（此前 RTLD_DEFAULT 可能拿到系统 BoringSSL 的
    //   SSL_get_SSL_CTX/SSL_CTX_set_keylog_callback，与 ssl 对象所在私有库跨库不生效）
    if (real_SSL_get_SSL_CTX == nullptr || real_ctx_set_keylog == nullptr) {
        resolve_keylog_via_dladdr((void*)orig_ssl_new);
    }
    ScopedHookGuard guard;
    void* ssl = orig_ssl_new(ctx);
    if (ssl != nullptr && real_SSL_get_SSL_CTX != nullptr && real_ctx_set_keylog != nullptr) {
        void* sctx = real_SSL_get_SSL_CTX(ssl);
        if (sctx != nullptr) real_ctx_set_keylog(sctx, keylog_cb);
    }
    return ssl;
}

// v1.34: shadowhook(inline) → xhook(PLT/GOT)。xhook 只改 GOT 表项、不改函数入口指令，
// 完全免疫 Android 16 PAC（Pointer Authentication Code）导致的 pc=0 崩溃。
// 注意 xhook 的 old_func 语义：register 后 xh_core 会在 refresh 时把 GOT 原值回填到 orig_func。
bool hook_func(const char *lib_name, const char *sym_name, void *hook_func, void **orig_func) {
    char buf[256];
    // xhook 的 pathname_regex 匹配"调用方 so 的路径"，而不是被 hook 库。
    // 用 .* 匹配所有已加载 so（PLT/GOT hook 本质是改调用方的 GOT 表项）。
    // xhook 本身会跳过 libc 内部符号解析（不走 GOT 的直接调用不受影响，这正是 PLT hook 特性）。
    int ret = xhook_register(".*", sym_name, hook_func, orig_func);
    if (ret == 0) {
        LOGI("xHook REGISTER OK: %s (via %s)", sym_name, lib_name ? lib_name : "any");
        snprintf(buf, sizeof(buf), "XH reg OK: %s", sym_name);
        native_log(buf);
        return true;
    }
    // 注册失败（参数错误/OOM），不写 orig（保持 nullptr），回调里已做空指针保护
    LOGE("xHook REGISTER FAIL(%d): %s", ret, sym_name);
    snprintf(buf, sizeof(buf), "XH reg FAIL(%d): %s", ret, sym_name);
    native_log(buf);
    return false;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_dustinky_spyprobe_NativeProbe_initNativeHook(JNIEnv *env, jobject thiz, jboolean enableNativeHook) {
    env->GetJavaVM(&gJvm);
    pthread_key_create(&g_thread_key, detach_current_thread);
    jclass clazz = env->FindClass("com/dustinky/spyprobe/NativeProbe");
    if (!clazz) return JNI_FALSE;
    gNativeRequestHookClass = (jclass) env->NewGlobalRef(clazz);
    
    gOnNativeDataMethod = env->GetStaticMethodID(clazz, "onNativeData", "(JZLjava/nio/ByteBuffer;Ljava/lang/String;Ljava/lang/String;Z)Z");
    gOnH2RequestMethod = env->GetStaticMethodID(clazz, "onH2Request", "(JILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;IZ)Z");
    gOnH2DataChunkMethod = env->GetStaticMethodID(clazz, "onH2DataChunk", "(JIZLjava/nio/ByteBuffer;)V");
    gCollectRespBodyMethod = env->GetStaticMethodID(clazz, "getCollectResponseBody", "()Z");
    gOnConnClosedMethod = env->GetStaticMethodID(clazz, "onConnectionClosed", "(JZ)V");
    // v1.59: TLS 元数据回调（JSON 字符串）
    gOnTlsMetaMethod = env->GetStaticMethodID(clazz, "onTlsMeta", "(JLjava/lang/String;)V");
    gNativeLogMethod = env->GetStaticMethodID(clazz, "nativeLog", "(Ljava/lang/String;)V");
    // v1.38 P0-3: keylog 回调方法
    gNativeKeylogMethod = env->GetStaticMethodID(clazz, "nativeKeylog", "(Ljava/lang/String;)V");
    if (gNativeKeylogMethod == nullptr) {
        native_log("XH keylog: GetStaticMethodID(nativeKeylog) FAIL");
    }

    if (enableNativeHook) {
        char buf[256];
        // v1.34: xhook 无需 init，注册后统一 refresh。PLT/GOT hook 只改调用方 GOT 表项，
        // 不碰函数指令 → Android 16 PAC 免疫（治本：OnePlus/OPPO 空指针崩溃根因）。
        // xhook 内部用 dl_iterate_phdr 遍历已加载 so，对符号进行 PLT/GOT 改写；
        // 对尚未加载的 so，后续 dlopen 时 xhook 会自动监控并 hook（xhook 支持 dlopen 回调）。
        // 先开启 SIGSEGV 保护，xhook 内部改 GOT 时若目标 so 异常可安全跳过
        xhook_enable_sigsegv_protection(1);
        xhook_enable_debug(0);

        // v1.30.4 P0 保留：dlopen 强制加载 SSL 库，确保 GOT 里符号可解析
        // v1.31.5 P0-3: 跳过 libflutter.so（Flutter 内部网络栈，默认不 hook）
        for (int i = 0; i < SSL_HOOK_COUNT; i++) {
            const char* lib = g_ssl_hooks[i].lib_name;
            if (strcmp(lib, "libflutter.so") == 0 && !ENABLE_FLUTTER_SSL_HOOK) {
                native_log("XH skip dlopen libflutter.so (Flutter SSL hook disabled)");
                continue;
            }
            void* h = dlopen(lib, RTLD_NOW);
            snprintf(buf, sizeof(buf), "dlopen %s -> %s", lib, h != nullptr ? "OK" : (dlerror() ? dlerror() : "unknown error"));
            native_log(buf);
            if (h != nullptr) dlclose(h);
        }
        // v1.38 P0-3: keylog 需要的真实函数指针（dlsym 直接拿，hook 回调里调用不走 GOT → 不触发递归）
        real_SSL_get_SSL_CTX = (type_SSL_get_SSL_CTX)dlsym(RTLD_DEFAULT, "SSL_get_SSL_CTX");
        real_ctx_set_keylog = (type_SSL_CTX_set_keylog_callback)dlsym(RTLD_DEFAULT, "SSL_CTX_set_keylog_callback");
        if (real_SSL_get_SSL_CTX == nullptr || real_ctx_set_keylog == nullptr) {
            native_log("XH keylog: dlsym SSL_get_SSL_CTX/SSL_CTX_set_keylog_callback FAIL (libssl.so 未加载?)");
        }
        // v1.39 P0: pcap 导出需要 SSL_get_fd（SSL 明文 → 底层 fd → socket 四元组）
        // v1.45.6 P0: 不再直接 dlsym(RTLD_DEFAULT) 赋值！dlsym 会命中系统 BoringSSL 的
        //   SSL_get_fd，而 ssl 对象来自 App 私有 SSL 库（xhook 按符号名全库 hook）→
        //   跨库调用返回垃圾 fd（v1.45.5 真机 NOEP 根因，且所有解析日志全消失）。
        //   保持 null，交给 hook_SSL_new 用 orig_ssl_new 同库解析 / SSL_set_fd 映射主路径。
        real_SSL_get_fd = nullptr;

        // v1.34: xhook 按符号注册（对所有已加载 so 的 GOT 生效），lib_name 仅作日志标注
        hook_func("libc.so", "send", (void*)hook_send, (void**)&orig_send);
        hook_func("libc.so", "recv", (void*)hook_recv, (void**)&orig_recv);
        hook_func("libc.so", "sendto", (void*)hook_sendto, (void**)&orig_sendto);
        hook_func("libc.so", "recvfrom", (void*)hook_recvfrom, (void**)&orig_recvfrom);
        // v1.31.5 P0-2: libc write/read 不再 hook（文件/管道/eventfd IO 入口，Flutter 高频，风险最大）
        hook_func("libc.so", "close", (void*)hook_close, (void**)&orig_close);
        // v1.31.5 P0-3: 跳过 libflutter.so 的 SSL hook（Flutter 内部网络栈风险高）
        for (int i = 0; i < SSL_HOOK_COUNT; i++) {
            const char* lib = g_ssl_hooks[i].lib_name;
            if (strcmp(lib, "libflutter.so") == 0 && !ENABLE_FLUTTER_SSL_HOOK) {
                native_log("XH skip hook libflutter.so (Flutter SSL hook disabled)");
                continue;
            }
            // v1.25 P0-3: SSL_* 与 NativeCrypto_* 变体各自独立 orig 指针，不再互相覆盖
            hook_func(lib, "SSL_write", (void*)ssl_write_hooks[i], (void**)&g_ssl_hooks[i].orig_ssl_write);
            hook_func(lib, "SSL_read", (void*)ssl_read_hooks[i], (void**)&g_ssl_hooks[i].orig_ssl_read);
            hook_func(lib, "SSL_free", (void*)ssl_free_hooks[i], (void**)&g_ssl_hooks[i].orig_ssl_free);
            // v1.63 P1-3: ex 变体——直接调 SSL_write_ex/SSL_read_ex 的库（部分 Flutter/WebSocket/自定义 TLS）不再漏抓
            hook_func(lib, "SSL_write_ex", (void*)ssl_write_ex_hooks[i], (void**)&g_ssl_hooks[i].orig_ssl_write_ex);
            hook_func(lib, "SSL_read_ex", (void*)ssl_read_ex_hooks[i], (void**)&g_ssl_hooks[i].orig_ssl_read_ex);
            hook_func(lib, "NativeCrypto_SSL_write", (void*)native_write_hooks[i], (void**)&g_ssl_hooks[i].orig_native_write);
            hook_func(lib, "NativeCrypto_SSL_read", (void*)native_read_hooks[i], (void**)&g_ssl_hooks[i].orig_native_read);
            hook_func(lib, "NativeCrypto_SSL_free", (void*)native_free_hooks[i], (void**)&g_ssl_hooks[i].orig_native_free);
        }
        // v1.38 P0-2: BoringSSL 自定义 verify 绕过（just_trust_me native 部分借鉴）
        //   libssl.so 符号，对调用方 GOT 生效（libconscrypt_jni 等）；未加载时 xhook 自动补挂
        hook_func("libssl.so", "SSL_CTX_set_custom_verify", (void*)hook_SSL_CTX_set_custom_verify, (void**)&orig_ctx_set_custom_verify);
        hook_func("libssl.so", "SSL_CTX_set_verify", (void*)hook_SSL_CTX_set_verify, (void**)&orig_ctx_set_verify);
        hook_func("libssl.so", "SSL_set_verify", (void*)hook_SSL_set_verify, (void**)&orig_ssl_set_verify);
        hook_func("libssl.so", "SSL_CTX_set_cert_verify_callback", (void*)hook_SSL_CTX_set_cert_verify_callback, (void**)&orig_ctx_set_cert_verify);
        hook_func("libssl.so", "SSL_get_verify_result", (void*)hook_SSL_get_verify_result, (void**)&orig_ssl_get_verify_result);
        // v1.38 P0-3: SSL keylog（ssl_log.js 借鉴）——Wireshark 导入 CLIENT_RANDOM 还原 TLS 明文
        hook_func("libssl.so", "SSL_CTX_set_keylog_callback", (void*)hook_SSL_CTX_set_keylog_callback, (void**)&orig_ctx_set_keylog);
        hook_func("libssl.so", "SSL_new", (void*)hook_SSL_new, (void**)&orig_ssl_new);
        // v1.45.6 P0: SSL_set_fd —— 标准流程必有（SSL_new→SSL_set_fd→SSL_connect），
        //   直接记录 ssl→fd 映射，绕开 SSL_get_fd 符号解析（跨库/namespace 全免疫）
        hook_func("libssl.so", "SSL_set_fd", (void*)hook_SSL_set_fd, (void**)&orig_ssl_set_fd);

        // 同步执行 GOT 改写（async=0 同步，确保返回时 hook 已生效）
        int xh_ret = xhook_refresh(0);
        snprintf(buf, sizeof(buf), "xhook_refresh ret=%d (0=OK)", xh_ret);
        native_log(buf);
        LOGI("xHook refresh ret=%d", xh_ret);
    }
    return JNI_TRUE;
}

// v1.20 P0-1: 补 JNI_OnLoad —— 之前缺此函数，System.loadLibrary("native_hook") 时
// dlsym 找不到本库的 JNI_OnLoad，fallback 到依赖库 libshadowhook.so 的 JNI_OnLoad，
// 其返回 JNI_ERR 导致整个 native 层（libc/SSL/HTTP2 hook）加载失败。
// 这里显式返回 JNI_VERSION_1_6，并顺手缓存 gJvm（initNativeHook 里 GetJavaVM 也保留，双保险）。
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    gJvm = vm;
    return JNI_VERSION_1_6;
}
