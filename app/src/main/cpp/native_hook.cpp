#include <jni.h>
#include <string>
#include <cstring>
#include <android/log.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/stat.h>
#include <unwind.h>
#include <iomanip>
#include <sstream>
#include <pthread.h>
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
//   需要时置 1 重新启用（对 Flutter 网络栈做 native 抓包）。
#define ENABLE_FLUTTER_SSL_HOOK 0

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

static pthread_key_t g_thread_key;
thread_local bool g_is_in_hook = false;
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
    type_SSL_write orig_native_write;
    type_SSL_read  orig_native_read;
    type_SSL_free  orig_native_free;
};

static SslHookEntry g_ssl_hooks[] = {
    { "libssl.so",             nullptr, nullptr, nullptr, nullptr, nullptr, nullptr },
    { "libconscrypt_jni.so",   nullptr, nullptr, nullptr, nullptr, nullptr, nullptr },
    { "libttboringssl.so",     nullptr, nullptr, nullptr, nullptr, nullptr, nullptr },
    { "libflutter.so",         nullptr, nullptr, nullptr, nullptr, nullptr, nullptr },
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

std::string get_cached_socket_info(int fd) {
    if (fd <= 0) return "";
    {
        std::lock_guard<std::mutex> lock(g_cache_mutex);
        auto it = g_socket_info_cache.find(fd);
        if (it != g_socket_info_cache.end()) return it->second;
    }
    struct sockaddr_storage addr; socklen_t len = sizeof(addr);
    if (getpeername(fd, (struct sockaddr*)&addr, &len) != 0) return "";
    char ip_str[INET6_ADDRSTRLEN] = {0}; int port = 0;
    if (addr.ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)&addr;
        port = ntohs(s->sin_port); inet_ntop(AF_INET, &s->sin_addr, ip_str, sizeof(ip_str));
    } else if (addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
        port = ntohs(s->sin6_port); inet_ntop(AF_INET6, &s->sin6_addr, ip_str, sizeof(ip_str));
    } else return "unknown";
    std::string info = std::string(ip_str) + ":" + std::to_string(port);
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

void notify_kotlin_close(jlong id, bool is_ssl) {
    if (gNativeRequestHookClass == nullptr || gOnConnClosedMethod == nullptr) return;
    JNIEnv *env = get_jni_env();
    if (!env) return;
    env->CallStaticVoidMethod(gNativeRequestHookClass, gOnConnClosedMethod, id, (jboolean)is_ssl);
    check_exception(env);
}

bool callback_kotlin(jlong id, bool is_write, const void *buf, size_t len, bool is_ssl) {
    if (gNativeRequestHookClass == nullptr || buf == nullptr || len == 0) return false;
    if (len > JNI_MAX_BUFFER_MAPPING) return false;
    if (!is_ssl && !is_network_fd((int)id)) return false;

    JNIEnv *env = get_jni_env();
    if (!env) return false;

    JniLocalRefGuard refGuard(env);

    jobject jBuffer = refGuard.add(env->NewDirectByteBuffer((void*)buf, len));
    if (jBuffer == nullptr) return false;
    
    jstring jInfo = nullptr;
    std::string info = (!is_ssl && id > 0) ? get_cached_socket_info((int)id) : "";
    if (!info.empty()) {
        jInfo = refGuard.add(env->NewStringUTF(info.c_str()));
        if (check_exception(env)) jInfo = nullptr;
    }
    
    jstring jStack = nullptr;
    if (is_write) {
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
        if (chunk.data.size() > JNI_MAX_BUFFER_MAPPING) continue;
        
        JniLocalRefGuard refGuard(env);
        jobject jBuffer = refGuard.add(env->NewDirectByteBuffer((void*)chunk.data.data(), chunk.data.size()));
        if (jBuffer == nullptr) continue;

        env->CallStaticVoidMethod(gNativeRequestHookClass, gOnH2DataChunkMethod,
                                  (jlong)conn_id, (jint)chunk.stream_id, (jboolean)chunk.is_request, jBuffer);
        check_exception(env);
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
    ScopedHookGuard guard;
    uintptr_t conn_id = reinterpret_cast<uintptr_t>(ssl);
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
    ScopedHookGuard guard;
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

// v1.25 P0-3: 公共释放逻辑（orig 由调用方传入）
template<int IDX>
void do_ssl_free_common(void *ssl, type_SSL_free orig) {
    if (orig == nullptr) return;
    if (g_is_in_hook) { orig(ssl); return; }
    ScopedHookGuard guard;
    { std::lock_guard<std::mutex> lock(g_cache_mutex); g_stack_cache.erase(reinterpret_cast<jlong>(ssl)); }
    h2_free(reinterpret_cast<uintptr_t>(ssl));
    notify_kotlin_close(reinterpret_cast<jlong>(ssl), true);
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
