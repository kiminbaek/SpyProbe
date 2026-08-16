/*
 * conscrypt_hook.cpp — v7x (M5 废弃清理)
 * Conscrypt JNI SSL_write/SSL_read hook（业务流量明文根治）
 *
 * 历史（v1.70，2026-08-13 真机日志 + 静态反汇编实锤）：
 *   91aw 业务流量（dart:io）走 Conscrypt（Android 系统 TLS 引擎，libconscrypt_jni.so
 *   内嵌 BoringSSL 静态链接 + JNI 调用）→ xhook(PLT/GOT) 双失效 → 业务 API 明文全漏。
 *   KL 定位的 libflutter.so ssl_log_secret 反汇编实锤是 Dart VM native 函数（误匹配）。
 *
 * 方案：shadowhook inline hook Conscrypt 的 JNI 导出函数
 *   Java_org_conscrypt_NativeCrypto_SSL_write / SSL_read
 *   （JNI 静态导出符号 dlsym 可定位；参数是 ByteBuffer 明文，直接喂 callback_kotlin
 *   结构化通道 REQ#）。通杀所有走 Conscrypt 的 app（Android 默认 TLS 引擎）。
 *
 * v7x M5：从 flutter_keylog.cpp 拆分——keylog/dart:io hook 路线废弃（v1.70 起仅辅助，
 *   后实锤不可通用），仅保留 Conscrypt JNI hook。shadowhook 延迟重试保留（libconscrypt_jni.so
 *   可能在 App 启动早期未加载）。
 */

#include <jni.h>
#include <string>
#include <cstring>
#include <android/log.h>
#include <dlfcn.h>
#include <unistd.h>
#include <pthread.h>
#include <atomic>

#define LOG_TAG "SpyProbe-Conscrypt"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ============ JNI 全局（由 init 设置） ============
static JavaVM *g_cs_jvm = nullptr;
static jclass g_cs_class = nullptr;
static jmethodID g_cs_log_method = nullptr; // NativeProbe.nativeLog(String)
static std::atomic<bool> g_in_progress{false};

// shadowhook 动态符号（dlopen libshadowhook.so，与 native_hook.cpp 一致）
typedef int (*fn_shadowhook_init)(int mode);
typedef void *(*fn_shadowhook_hook_func_addr)(void *func, void *replace, void **orig);
typedef const char *(*fn_shadowhook_get_errno)(void);
static fn_shadowhook_init g_sh_init = nullptr;
static fn_shadowhook_hook_func_addr g_sh_hook_addr = nullptr;
static fn_shadowhook_get_errno g_sh_get_errno = nullptr;

static void cs_native_log(const char *msg);

// ============ shadowhook 加载 + hook ============
static bool load_shadowhook() {
    if (g_sh_hook_addr) return true;
    void *h = dlopen("libshadowhook.so", RTLD_NOW | RTLD_NOLOAD);
    if (!h) h = dlopen("libshadowhook.so", RTLD_NOW);
    if (!h) {
        cs_native_log("shadowhook dlopen FAIL");
        return false;
    }
    g_sh_init = (fn_shadowhook_init)dlsym(h, "shadowhook_init");
    g_sh_hook_addr = (fn_shadowhook_hook_func_addr)dlsym(h, "shadowhook_hook_func_addr");
    g_sh_get_errno = (fn_shadowhook_get_errno)dlsym(h, "shadowhook_get_errno");
    if (!g_sh_init || !g_sh_hook_addr) {
        cs_native_log("shadowhook symbols FAIL");
        return false;
    }
    if (g_sh_init(1) != 0) { // 1 = SHADOWHOOK_MODE_DEFAULT
        const char *e = g_sh_get_errno ? g_sh_get_errno() : "?";
        char buf[128];
        snprintf(buf, sizeof(buf), "shadowhook_init ret!=0 errno=%s", e);
        cs_native_log(buf);
        return false;
    }
    return true;
}

static void cs_native_log(const char *msg) {
    if (!msg) return;
    LOGI("%s", msg);
    if (g_cs_jvm && g_cs_class && g_cs_log_method) {
        JNIEnv *env = nullptr;
        if (g_cs_jvm->GetEnv((void **)&env, JNI_VERSION_1_6) == JNI_OK && env) {
            jstring js = env->NewStringUTF(msg);
            env->CallStaticVoidMethod(g_cs_class, g_cs_log_method, js);
            env->DeleteLocalRef(js);
        }
    }
}

// ============ Conscrypt JNI SSL_write/SSL_read hook (v1.70) ============
// native_hook.cpp 提供的结构化明文入口（HTTP1 解析 + REQ# 卡片）
extern bool callback_kotlin(jlong id, bool is_write, const void *buf, size_t len, bool is_ssl);
extern "C" bool process_conscrypt_plain(jlong id, bool is_write, const void *buf, size_t len);

typedef jint (*orig_cs_ssl_write_t)(JNIEnv*, jclass, jlong, jobject, jint, jint);
typedef jint (*orig_cs_ssl_read_t)(JNIEnv*, jclass, jlong, jobject, jint, jint, jint);
static orig_cs_ssl_write_t g_orig_cs_write = nullptr;
static orig_cs_ssl_read_t  g_orig_cs_read  = nullptr;
static std::atomic<bool> g_conscrypt_hooked{false};
static std::atomic<int> g_cs_write_calls{0};
static std::atomic<int> g_cs_read_calls{0};
static std::atomic<bool> g_cs_in_hook{false};
static jclass g_bb_class = nullptr;      // java/nio/ByteBuffer 全局引用
static jmethodID g_bb_has_array = nullptr;
static jmethodID g_bb_array = nullptr;

// 从 ByteBuffer(direct/heap)/byte[] 提取明文到 out（拷贝，安全）。
static bool cs_extract_plain(JNIEnv* env, jobject obj, jint offset, jint len,
                             uint8_t* out, size_t out_cap, size_t* out_len) {
    if (!obj || len <= 0 || (size_t)len > out_cap) return false;
    if (g_bb_class == nullptr) {
        jclass bb = env->FindClass("java/nio/ByteBuffer");
        if (!bb) return false;
        g_bb_class = (jclass)env->NewGlobalRef(bb);
        g_bb_has_array = env->GetMethodID(bb, "hasArray", "()Z");
        g_bb_array = env->GetMethodID(bb, "array", "()[B");
    }
    jboolean hasArr = env->CallBooleanMethod(obj, g_bb_has_array);
    if (hasArr) {
        jbyteArray arr = (jbyteArray)env->CallObjectMethod(obj, g_bb_array);
        if (!arr) return false;
        jsize arrLen = env->GetArrayLength(arr);
        jsize start = offset, end = offset + len;
        if (start < 0) start = 0;
        if (end > arrLen) end = arrLen;
        if (end <= start) { env->DeleteLocalRef(arr); return false; }
        env->GetByteArrayRegion(arr, start, end - start, (jbyte*)out);
        *out_len = (size_t)(end - start);
        env->DeleteLocalRef(arr);
        return true;
    }
    // DirectByteBuffer
    void* base = env->GetDirectBufferAddress(obj);
    if (base) {
        jlong cap = env->GetDirectBufferCapacity(obj);
        jlong start = offset, end = (jlong)offset + len;
        if (start < 0) start = 0;
        if (end > cap) end = cap;
        if (end <= start) return false;
        memcpy(out, (const uint8_t*)base + start, (size_t)(end - start));
        *out_len = (size_t)(end - start);
        return true;
    }
    return false;
}

// 1) DirectByteBuffer（Conscrypt 网络路径主流）
static jint my_cs_ssl_write_bb(JNIEnv* env, jclass, jlong ssl, jobject src, jint offset, jint len) {
    jint ret = g_orig_cs_write(env, nullptr, ssl, src, offset, len);
    if (ret > 0 && !g_cs_in_hook.exchange(true)) {
        g_cs_write_calls++;
        uint8_t tmp[262144];
        size_t plen = 0;
        if (cs_extract_plain(env, src, offset, (jint)ret, tmp, sizeof(tmp), &plen) && plen > 0) {
            process_conscrypt_plain((jlong)ssl, true, tmp, plen);
        }
        g_cs_in_hook = false;
    }
    return ret;
}

// 2) byte[]（老版 Conscrypt 签名 NativeCrypto.SSL_write(long,byte[],int,int)）
static jint my_cs_ssl_write_arr(JNIEnv* env, jclass, jlong ssl, jbyteArray src, jint offset, jint len) {
    jint ret = g_orig_cs_write(env, nullptr, ssl, src, offset, len);
    if (ret > 0 && !g_cs_in_hook.exchange(true)) {
        g_cs_write_calls++;
        uint8_t tmp[262144];
        jsize arrLen = env->GetArrayLength(src);
        jsize start = offset, end = offset + ret;
        if (start < 0) start = 0;
        if (end > arrLen) end = arrLen;
        if (end > start && (size_t)(end - start) <= sizeof(tmp)) {
            env->GetByteArrayRegion(src, start, end - start, (jbyte*)tmp);
            process_conscrypt_plain((jlong)ssl, true, tmp, (size_t)(end - start));
        }
        g_cs_in_hook = false;
    }
    return ret;
}

static jint my_cs_ssl_read(JNIEnv* env, jclass, jlong ssl, jobject dst, jint offset, jint len, jint source) {
    jint ret = g_orig_cs_read(env, nullptr, ssl, dst, offset, len, source);
    if (ret > 0 && !g_cs_in_hook.exchange(true)) {
        g_cs_read_calls++;
        uint8_t tmp[262144];
        size_t plen = 0;
        if (cs_extract_plain(env, dst, offset, (jint)ret, tmp, sizeof(tmp), &plen) && plen > 0) {
            process_conscrypt_plain((jlong)ssl, false, tmp, plen);
        }
        g_cs_in_hook = false;
    }
    return ret;
}

static bool install_conscrypt_hook() {
    if (g_conscrypt_hooked.load()) return true;
    if (!g_sh_hook_addr) { cs_native_log("CS install: shadowhook not loaded"); return false; }
    void* h = dlopen("libconscrypt_jni.so", RTLD_NOW | RTLD_NOLOAD);
    if (!h) h = dlopen("libconscrypt_jni.so", RTLD_NOW);
    if (!h) { cs_native_log("CS dlopen libconscrypt_jni.so FAIL"); return false; }
    void* write_fn = dlsym(h, "Java_org_conscrypt_NativeCrypto_SSL_write");
    void* read_fn  = dlsym(h, "Java_org_conscrypt_NativeCrypto_SSL_read");
    if (!write_fn || !read_fn) {
        char b[128];
        snprintf(b, sizeof(b), "CS dlsym NativeCrypto_SSL_write=%p SSL_read=%p FAIL", write_fn, read_fn);
        cs_native_log(b);
        return false;
    }
    if (g_sh_hook_addr(write_fn, (void*)my_cs_ssl_write_bb, (void**)&g_orig_cs_write) != 0) {
        char b[128];
        snprintf(b, sizeof(b), "CS SSL_write hook FAIL errno=%d", g_sh_get_errno ? g_sh_get_errno()[0] : -1);
        cs_native_log(b);
        return false;
    }
    if (g_sh_hook_addr(read_fn, (void*)my_cs_ssl_read, (void**)&g_orig_cs_read) != 0) {
        char b[128];
        snprintf(b, sizeof(b), "CS SSL_read hook FAIL errno=%d", g_sh_get_errno ? g_sh_get_errno()[0] : -1);
        cs_native_log(b);
        return false;
    }
    g_conscrypt_hooked.store(true);
    char ok[128];
    snprintf(ok, sizeof(ok), "CS SSL_write hook OK (fn=%p)", write_fn);
    cs_native_log(ok);
    return true;
}

// v1.70.1: Conscrypt JNI hook 延迟重试线程
//   App 启动早期（SpyProbe 注入时）libconscrypt_jni.so 尚未加载
//   install_conscrypt_hook() 的 dlopen FAIL → 业务流量（Conscrypt 内嵌
//   BoringSSL）明文全漏。后台线程每 1s 检查 /proc/self/maps，
//   libconscrypt_jni.so 加载后立即 install_conscrypt_hook() → 业务明文 → REQ#。
static void *cs_wait_thread(void *) {
    // v1.75 打磨 B2: 180 次轮询窗口期满时留痕——此前静默退出，无任何日志，
    //   排障时无法区分"App 不用 Conscrypt"与"窗口不够长"。窗口结束补一行日志。
    for (int i = 0; i < 180; i++) { // 最多 180s（3 分钟），每 1s 检查
        if (g_conscrypt_hooked.load()) break;
        usleep(1000 * 1000);
        bool loaded = false;
        FILE *f = fopen("/proc/self/maps", "r");
        if (f) {
            char line[512];
            while (fgets(line, sizeof(line), f)) {
                if (strstr(line, "libconscrypt_jni.so")) { loaded = true; break; }
            }
            fclose(f);
        }
        if (!loaded) continue;
        if (install_conscrypt_hook()) {
            cs_native_log("CS Conscrypt JNI hook OK (delayed after libconscrypt_jni.so loaded)");
            break;
        }
    }
    if (!g_conscrypt_hooked.load()) {
        cs_native_log("CS Conscrypt JNI hook retry window expired (180s, libconscrypt_jni.so never loaded) — target may not use Conscrypt");
    }
    return nullptr;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_dustinky_spyprobe_NativeProbe_conscryptHookInit(JNIEnv *env, jobject thiz) {
    if (g_conscrypt_hooked.load()) return JNI_TRUE;
    if (g_in_progress.exchange(true)) return JNI_FALSE;

    env->GetJavaVM(&g_cs_jvm);
    jclass clazz = env->FindClass("com/dustinky/spyprobe/NativeProbe");
    if (!clazz) { g_in_progress = false; return JNI_FALSE; }
    g_cs_class = (jclass)env->NewGlobalRef(clazz);
    g_cs_log_method = env->GetStaticMethodID(clazz, "nativeLog", "(Ljava/lang/String;)V");

    if (!load_shadowhook()) { g_in_progress = false; return JNI_FALSE; }

    // v1.70: Conscrypt JNI hook（独立于 libflutter.so，App 启动早期即可安装）
    // v1.70.1 P0: 一次性 install 在 App 启动早期会因 libconscrypt_jni.so 未加载
    //   而 dlopen FAIL → 后台线程延迟重试（dart:io 第一次 TLS 后库加载，重试即成功）
    bool ok = install_conscrypt_hook();
    if (!ok) {
        cs_native_log("CS install FAIL (libconscrypt_jni.so not loaded yet) — delayed retry started");
        pthread_t cs_tid;
        pthread_create(&cs_tid, nullptr, cs_wait_thread, nullptr);
        pthread_detach(cs_tid);
    }
    g_in_progress = false;
    return ok ? JNI_TRUE : JNI_FALSE;
}
