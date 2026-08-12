/*
 * flutter_keylog.cpp — v1.67
 * libflutter.so 静态 BoringSSL keylog 注入器
 *
 * 背景（2026-08-12 实锤）：
 *   dart:io 自带 BoringSSL，符号静态链接在 libflutter.so 内，不导出 → xhook(PLT/GOT)
 *   无效（v1.66 实测 Flutter 层业务 API 全漏）。但 libc send/recv 层密文全量可抓，
 *   配合 keylog(CLIENT_RANDOM + secrets) 即可在 Java 侧内部解密 TLS → 明文。
 *
 * 定位策略（跨 Flutter 版本 4 样本验证）：
 *   1. 扫描 .rodata 找 5 个 label 锚点字符串（CLIENT_RANDOM 等）虚拟地址
 *   2. 扫描 .text 找 adrp+add 指令对引用锚点的位置
 *   3. 从引用点回溯函数头（sub sp / stp x29,x30）
 *   4. 收集函数体内 bl/b 目标（thunk 一层展开）
 *   5. 多 label 调用者的 bl 目标取交集 → ssl_log_secret 候选
 *   6. 结构指纹精筛：ldr(读ssl) → ldr(读ctx) → cbz(判空) → blr(调用keylog cb)
 *
 * 注入（shadowhook 2.0.1 预编译 .so，dlopen 动态加载）：
 *   shadowhook_hook_func_addr(ssl_log_secret, my_ssl_log_secret, &orig)
 *   hook 里：设置 ctx->keylog_callback = 我们的回调 → 调原函数 → BoringSSL 自动
 *   组装完整 keylog 行（"CLIENT_RANDOM <64hex> <96hex>"）→ 回调转发 Java。
 *
 * 结构偏移动态提取（不依赖具体版本）：
 *   在 ssl_log_secret 函数头内找 "ldr x8,[x0,#A]" 和 "ldr x8,[x8,#B]" 序列：
 *     A = ssl->ctx 偏移（典型 0x68）
 *     B = ctx->keylog_callback 偏移（典型 0x228）
 */

#include <jni.h>
#include <string>
#include <cstring>
#include <android/log.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <atomic>
#include <vector>
#include <set>
#include <map>
#include <mutex>

#define LOG_TAG "SpyProbe-FlutterKL"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ============ JNI 全局（由 init 设置） ============
static JavaVM *g_kl_jvm = nullptr;
static jclass g_kl_class = nullptr;
static jmethodID g_kl_method = nullptr;   // NativeProbe.nativeKeylog(String)
static jmethodID g_kl_log_method = nullptr; // NativeProbe.nativeLog(String)
static std::atomic<bool> g_hooked{false};
static std::atomic<bool> g_in_progress{false};

// shadowhook 动态符号
typedef void *(*fn_shadowhook_init)(int debuggable, int recordable);
typedef void *(*fn_shadowhook_hook_func_addr)(void *func_addr, void *new_addr, void **orig_addr);
typedef int (*fn_shadowhook_get_errno)(void);
static fn_shadowhook_init g_sh_init = nullptr;
static fn_shadowhook_hook_func_addr g_sh_hook_addr = nullptr;
static fn_shadowhook_get_errno g_sh_get_errno = nullptr;

// ============ 定位结果（跨函数共享） ============
static uintptr_t g_ssl_log_secret_addr = 0;  // 运行时绝对地址（so 基址 + 偏移）
static uintptr_t g_ctx_off = 0;              // ssl->ctx 偏移
static uintptr_t g_cb_off = 0;               // ctx->keylog_callback 偏移
static bool g_offsets_valid = false;

static void kl_native_log(const char *msg);

// ============ ARM64 指令解码（自实现，零依赖） ============

// adrp: 0x90000000 mask 0x9F000000 ; 提取 21 位立即数（页偏移）
static bool decode_adrp(uint32_t insn, uintptr_t pc, uintptr_t *target_page, int *rd) {
    if ((insn & 0x9F000000u) != 0x90000000u) return false;
    uint32_t immlo = (insn >> 29) & 0x3u;
    uint32_t immhi = (insn >> 5) & 0x7FFFFu;
    int64_t imm21 = (int64_t)((immhi << 2) | immlo);
    if (imm21 & (1 << 20)) imm21 -= (1 << 21);
    *target_page = (pc & ~0xFFFULL) + (uintptr_t)(imm21 << 12);
    *rd = (int)(insn & 0x1F);
    return true;
}

// add xd, xn, #imm12 (0x91000000 变体, sf=1)
static bool decode_add_imm(uint32_t insn, int *rd, int *rn, uint32_t *imm) {
    if ((insn & 0xFFC00000u) != 0x91000000u) return false;
    *imm = (insn >> 10) & 0xFFFu;
    *rn = (int)((insn >> 5) & 0x1F);
    *rd = (int)(insn & 0x1F);
    return true;
}

// bl: 0x94000000 ; b: 0x14000000（仅取 26 位立即数）
static bool decode_bl_b(uint32_t insn, uintptr_t pc, uintptr_t *target) {
    uint32_t op = insn & 0xFC000000u;
    if (op != 0x94000000u && op != 0x14000000u) return false;
    int64_t imm26 = (int64_t)(insn & 0x03FFFFFFu);
    if (imm26 & (1 << 25)) imm26 -= (1 << 26);
    *target = pc + (uintptr_t)(imm26 << 2);
    return true;
}

// sub sp, sp, #imm（函数头）: 0xD10003FF mask
static bool is_sub_sp(uint32_t insn) {
    // sf=1 sub (imm): 0xD1000000 | Rn=sp(31) Rd=sp(31)
    return (insn & 0xFFC003FFu) == 0xD10003FFu;
}

// stp x29, x30, [sp, #-imm]!（函数头）: 0xA9A00000 变体 mask
static bool is_stp_x29x30_pre(uint32_t insn) {
    // 1010 1001 1 00 imm7 Rt=30 Rt2=29 Rn=31
    return (insn & 0xFFC003FFu) == 0xA98003FFu;
}

// ldr xT, [xN, #imm]（unsigned imm12, 64bit）: 0xF9400000 mask
static bool decode_ldr_imm(uint32_t insn, int *rt, int *rn, uint32_t *imm) {
    if ((insn & 0xFFC00000u) != 0xF9400000u) return false;
    *imm = (insn >> 10) & 0xFFFu;
    *rn = (int)((insn >> 5) & 0x1F);
    *rt = (int)(insn & 0x1F);
    return true;
}

// cbz/cbnz xT, #imm（判空）
static bool is_cbz(uint32_t insn) {
    uint32_t op = insn & 0x7F000000u;
    return op == 0x34000000u || op == 0x35000000u;
}

// blr xN（间接调用）
static bool is_blr(uint32_t insn) {
    return (insn & 0xFFFFFC1Fu) == 0xD63F0000u;
}

// ============ ELF 段定位（读 /proc/self/maps） ============

struct SoRange {
    uintptr_t base = 0;
    uintptr_t text_addr = 0;   // 文件内 .text 虚拟偏移（相对基址）
    size_t text_size = 0;
    uintptr_t rodata_addr = 0;
    size_t rodata_size = 0;
    uintptr_t load_bias = 0;   // 基址 - 最小 vaddr（用于 maps 虚拟地址换算）
};

// 从 /proc/self/maps 中找 libflutter.so 各段的内存范围（已加载态，非文件偏移）
static bool find_libflutter_ranges(SoRange &out) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) {
        kl_native_log("KL find: fopen /proc/self/maps FAIL");
        return false;
    }
    char line[512];
    uintptr_t min_vaddr = 0, max_end = 0;
    std::vector<std::pair<uintptr_t, uintptr_t>> exec_ranges, ro_ranges;
    int match_cnt = 0, parse_ok = 0;
    char diag[768] = {0};
    size_t diag_len = 0;
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, "libflutter.so")) continue;
        match_cnt++;
        uintptr_t start, end;
        char perms[8] = {0};
        unsigned long ls, le;
        if (sscanf(line, "%lx-%lx %7s", &ls, &le, perms) != 3) {
            snprintf(diag + diag_len, sizeof(diag) - diag_len, "[parse-fail:%s]", line);
            diag_len = strlen(diag);
            continue;
        }
        parse_ok++;
        start = (uintptr_t)ls; end = (uintptr_t)le;
        snprintf(diag + diag_len, sizeof(diag) - diag_len, "[%lx-%lx %s]", ls, le, perms);
        diag_len = strlen(diag);
        if (diag_len > 600) break;
        if (perms[0] == 'r' && perms[2] == 'x') {
            exec_ranges.push_back({start, end});
        } else if (perms[0] == 'r' && perms[1] == '-' && perms[2] == '-') {
            ro_ranges.push_back({start, end});
        }
        if (min_vaddr == 0 || start < min_vaddr) min_vaddr = start;
        if (end > max_end) max_end = end;
    }
    fclose(f);
    {
        char buf[512];
        snprintf(buf, sizeof(buf), "KL find: matches=%d parse_ok=%d exec=%zu ro=%zu diag=%s",
                 match_cnt, parse_ok, exec_ranges.size(), ro_ranges.size(), diag);
        kl_native_log(buf);
    }
    if (exec_ranges.empty() || ro_ranges.empty()) return false;
    out.base = min_vaddr;
    out.load_bias = min_vaddr; // maps 虚拟地址 = 文件 vaddr + load_bias（首个映射为 base）
    // .text 段取最大的可执行范围
    uintptr_t best_exec = 0; size_t best_size = 0;
    for (auto &r : exec_ranges) {
        size_t sz = r.second - r.first;
        if (sz > best_size) { best_size = sz; best_exec = r.first; }
    }
    out.text_addr = best_exec;
    out.text_size = best_size;
    // .rodata 段取最大的只读范围（排除 header 小段）
    uintptr_t best_ro = 0; size_t best_ro_size = 0;
    for (auto &r : ro_ranges) {
        size_t sz = r.second - r.first;
        if (sz > best_ro_size && sz > 4096) { best_ro_size = sz; best_ro = r.first; }
    }
    out.rodata_addr = best_ro;
    out.rodata_size = best_ro_size;
    return true;
}

// 在只读段内搜字符串（返回绝对虚拟地址）
// 安全：每页内只读到 min(页尾, 段尾)，跨页边界用逐字节缓冲拼接检测
static uintptr_t find_anchor_in_range(const uintptr_t start, const size_t len, const char *needle) {
    size_t nlen = strlen(needle) + 1; // 含 \0
    const char *base = (const char *)start;
    // 简单可靠：整段顺序扫描（maps 段连续可读，段尾以 len 截断）
    for (size_t i = 0; i + nlen <= len; i++) {
        if (base[i] == needle[0] && memcmp(base + i, needle, nlen) == 0) {
            return start + i;
        }
    }
    return 0;
}

// ============ 定位 ssl_log_secret ============

// 扫描 .text 找引用 anchor 的 adrp+add 指令对 → 返回所有 add 指令地址
static void scan_adrp_add_refs(const SoRange &rng, uintptr_t anchor,
                               std::vector<uintptr_t> &refs) {
    const uint32_t *code = (const uint32_t *)rng.text_addr;
    size_t n = rng.text_size / 4;
    // 维护最近 64 条 adrp 记录 (addr, rd, target_page)，超出时整体丢弃最旧一半
    struct Adrp { uintptr_t addr; int rd; uintptr_t page; };
    Adrp recent[64];
    int recent_n = 0;
    for (size_t i = 0; i < n; i++) {
        uintptr_t pc = rng.text_addr + i * 4;
        uint32_t insn = code[i];
        uintptr_t tpage; int rd;
        if (decode_adrp(insn, pc, &tpage, &rd)) {
            if (recent_n < 64) {
                recent[recent_n++] = {pc, rd, tpage};
            } else {
                // 滑动：移掉最旧一半，腾出空间
                int keep = 32;
                for (int k = 0; k < keep; k++) recent[k] = recent[recent_n - keep + k];
                recent_n = keep;
                recent[recent_n++] = {pc, rd, tpage};
            }
            continue;
        }
        int add_rd, add_rn; uint32_t add_imm;
        if (decode_add_imm(insn, &add_rd, &add_rn, &add_imm)) {
            // 找 64 条内、同 rn、页面+imm==anchor 的 adrp（从最新往前）
            for (int k = recent_n - 1; k >= 0; k--) {
                if (recent[k].rd == add_rn && pc - recent[k].addr < 64 * 4) {
                    if (recent[k].page + add_imm == anchor) {
                        refs.push_back(pc);
                    }
                    break;
                }
            }
        }
    }
}

// 从引用点回溯函数头
static uintptr_t find_func_head(const SoRange &rng, uintptr_t ref_addr) {
    const uint32_t *code = (const uint32_t *)rng.text_addr;
    uintptr_t start = ref_addr > 0x400 ? ref_addr - 0x400 : rng.text_addr;
    uintptr_t head = 0;
    for (uintptr_t pc = start; pc < ref_addr; pc += 4) {
        uint32_t insn = code[(pc - rng.text_addr) / 4];
        if (is_sub_sp(insn) || is_stp_x29x30_pre(insn)) head = pc;
    }
    return head;
}

// movz/movn/movk（立即数 mov，thunk 常见）
static bool is_mov_imm(uint32_t insn) {
    return (insn & 0xFF800000u) == 0xD2800000u   // movz xD, #imm16 (sf=1)
        || (insn & 0xFF800000u) == 0x92800000u   // movn
        || (insn & 0xFF800000u) == 0xF2800000u;  // movk
}

// mov xD, xM（ORR xD, xzr, xM——Rn=31, imm6=0, shift=00, N=0）
// mask: 保留 bit31-21 + bit15-10 + bit9-5；忽略 Rm/Rd
static bool is_mov_reg(uint32_t insn) {
    return (insn & 0xFFE0FFE0u) == 0xAA4003E0u;
}

// 收集函数体内 bl/b 目标（thunk 一层展开）
static void collect_callees(const SoRange &rng, uintptr_t head, std::set<uintptr_t> &out) {
    const uint32_t *code = (const uint32_t *)rng.text_addr;
    const size_t MAX_FUNC = 0x800 / 4;
    uintptr_t end = head + 0x800;
    uintptr_t text_end = rng.text_addr + rng.text_size;
    if (end > text_end) end = text_end;
    std::vector<uintptr_t> direct;
    for (uintptr_t pc = head; pc < end; pc += 4) {
        uint32_t insn = code[(pc - rng.text_addr) / 4];
        uintptr_t tgt;
        if (decode_bl_b(insn, pc, &tgt)) {
            direct.push_back(tgt);
            out.insert(tgt);
        }
    }
    // thunk 一层展开：mov(任意形式); b target → 展开 b 目标
    for (uintptr_t t : direct) {
        if (t + 8 > text_end || t < rng.text_addr) continue;
        uint32_t i0 = code[(t - rng.text_addr) / 4];
        uint32_t i1 = code[(t - rng.text_addr) / 4 + 1];
        if (is_mov_imm(i0) || is_mov_reg(i0)) {
            uintptr_t t2;
            if (decode_bl_b(i1, t + 4, &t2)) out.insert(t2);
        }
    }
}

// 结构指纹：ldr(读ssl) → ldr(读ctx) → cbz(判空) 序列
// 同时提取 ssl->ctx / ctx->keylog_callback 偏移
// 策略（v1.67 修）：不依赖 blr 定位（blr 可能在函数中段，被中间 cbz 干扰），
//   直接全函数扫描严格模式：ldr x8,[x0,#A] → ldr x8,[x8,#B] → 后面有 cbz/cbnz
static bool fingerprint_and_extract(const SoRange &rng, uintptr_t cand,
                                    uintptr_t *ctx_off, uintptr_t *cb_off) {
    const uint32_t *code = (const uint32_t *)rng.text_addr;
    uintptr_t text_end = rng.text_addr + rng.text_size;
    uintptr_t end = cand + 0x800;
    if (end > text_end) end = text_end;
    std::vector<uint32_t> insns;
    for (uintptr_t pc = cand; pc < end && insns.size() < 250; pc += 4) {
        insns.push_back(code[(pc - rng.text_addr) / 4]);
    }
    int n = (int)insns.size();
    for (int i = 0; i < n - 2; i++) {
        int rt1, rn1, rt2, rn2;
        uint32_t imm1, imm2;
        // 严格模式：ldr x8,[x0,#A] 紧邻 ldr x8,[x8,#B]
        if (!decode_ldr_imm(insns[i], &rt1, &rn1, &imm1)) continue;
        if (rn1 != 0 || rt1 != 8) continue;
        if (!decode_ldr_imm(insns[i + 1], &rt2, &rn2, &imm2)) continue;
        if (rn2 != 8 || rt2 != 8) continue;
        // 其后 32 条内必须有判空（cbz/cbnz）
        bool has_cond = false;
        for (int j = i + 2; j < n && j <= i + 34; j++) {
            if (is_cbz(insns[j])) { has_cond = true; break; }
        }
        if (has_cond) {
            // 关键：ldr x（64位）imm12 是 8 字节对齐的缩放值，真实字节偏移 = imm12 << 3
            *ctx_off = imm1 << 3;
            *cb_off = imm2 << 3;
            return true;
        }
    }
    return false;
}

// 主定位入口：返回 ssl_log_secret 绝对地址；*ctx_off/*cb_off 输出
static uintptr_t locate_ssl_log_secret(SoRange &rng, uintptr_t *ctx_off, uintptr_t *cb_off) {
    static const char *ANCHORS[] = {
        "CLIENT_RANDOM",
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        "CLIENT_TRAFFIC_SECRET_0",
        "SERVER_TRAFFIC_SECRET_0",
    };
    const int ANCHOR_N = 5;
    if (!find_libflutter_ranges(rng)) return 0;

    char buf[256];
    snprintf(buf, sizeof(buf), "KL libflutter.so base=0x%lx text=0x%lx+%zu rodata=0x%lx+%zu",
             (unsigned long)rng.base, (unsigned long)rng.text_addr, rng.text_size,
             (unsigned long)rng.rodata_addr, rng.rodata_size);
    kl_native_log(buf);

    std::set<uintptr_t> common; // 交集累积
    bool first = true;
    for (int a = 0; a < ANCHOR_N; a++) {
        uintptr_t anchor = find_anchor_in_range(rng.rodata_addr, rng.rodata_size, ANCHORS[a]);
        if (!anchor) {
            snprintf(buf, sizeof(buf), "KL anchor[%d] %s NOT FOUND", a, ANCHORS[a]);
            kl_native_log(buf);
            continue;
        }
        std::vector<uintptr_t> refs;
        scan_adrp_add_refs(rng, anchor, refs);
        std::set<uintptr_t> heads;
        for (uintptr_t r : refs) {
            uintptr_t h = find_func_head(rng, r);
            if (h) heads.insert(h);
        }
        std::set<uintptr_t> callees;
        for (uintptr_t h : heads) collect_callees(rng, h, callees);
        snprintf(buf, sizeof(buf), "KL %s: refs=%zu heads=%zu callees=%zu",
                 ANCHORS[a], refs.size(), heads.size(), callees.size());
        kl_native_log(buf);
        if (first) { common = callees; first = false; }
        else {
            std::set<uintptr_t> inter;
            for (uintptr_t c : common) if (callees.count(c)) inter.insert(c);
            common = inter;
        }
        if (common.empty()) break;
    }
    if (common.empty()) {
        kl_native_log("KL intersection EMPTY — 定位失败");
        return 0;
    }
    for (uintptr_t c : common) {
        uintptr_t co, cbo;
        if (fingerprint_and_extract(rng, c, &co, &cbo)) {
            snprintf(buf, sizeof(buf),
                     "KL ssl_log_secret FOUND 0x%lx (so+0x%lx) ctx_off=0x%lx cb_off=0x%lx",
                     (unsigned long)c, (unsigned long)(c - rng.base),
                     (unsigned long)co, (unsigned long)cbo);
            kl_native_log(buf);
            *ctx_off = co; *cb_off = cbo;
            return c;
        }
    }
    kl_native_log("KL 交集无指纹匹配");
    return 0;
}

// ============ keylog 回调 → Java ============
static void kl_keylog_cb(const void *ssl, const char *line) {
    if (line == nullptr || g_kl_class == nullptr || g_kl_method == nullptr) return;
    JNIEnv *env = nullptr;
    bool detach = false;
    jint st = g_kl_jvm->GetEnv((void **)&env, JNI_VERSION_1_6);
    if (st == JNI_EDETACHED) {
        if (g_kl_jvm->AttachCurrentThread(&env, nullptr) != JNI_OK) return;
        detach = true;
    }
    if (env) {
        jstring jline = env->NewStringUTF(line);
        if (jline) {
            env->CallStaticVoidMethod(g_kl_class, g_kl_method, jline);
            env->DeleteLocalRef(jline);
        }
        if (detach) g_kl_jvm->DetachCurrentThread();
    }
}

// ============ ssl_log_secret hook 函数 ============
// BoringSSL 签名：void ssl_log_secret(const SSL *ssl, const char *label,
//   const uint8_t *client_random, size_t client_random_len,
//   const uint8_t *secret, size_t secret_len)
typedef void (*orig_ssl_log_secret_t)(const void *ssl, const char *label,
                                      const uint8_t *client_random, size_t client_random_len,
                                      const uint8_t *secret, size_t secret_len);
static orig_ssl_log_secret_t g_orig_ssl_log_secret = nullptr;

static void my_ssl_log_secret(const void *ssl, const char *label,
                              const uint8_t *client_random, size_t client_random_len,
                              const uint8_t *secret, size_t secret_len) {
    if (g_orig_ssl_log_secret == nullptr) return;
    // 确保 ctx->keylog_callback 已设置（版本无关：偏移动态提取）
    if (g_offsets_valid && ssl != nullptr) {
        void *ctx = *(void **)((uintptr_t)ssl + g_ctx_off);
        if (ctx != nullptr) {
            void **cb_slot = (void **)((uintptr_t)ctx + g_cb_off);
            if (*cb_slot == nullptr) {
                *cb_slot = (void *)kl_keylog_cb;
            }
        }
    }
    g_orig_ssl_log_secret(ssl, label, client_random, client_random_len, secret, secret_len);
}

// ============ shadowhook 加载 + hook ============
static bool load_shadowhook() {
    void *h = dlopen("libshadowhook.so", RTLD_NOW | RTLD_NOLOAD);
    if (!h) h = dlopen("libshadowhook.so", RTLD_NOW);
    if (!h) {
        kl_native_log("KL dlopen libshadowhook.so FAIL");
        return false;
    }
    g_sh_init = (fn_shadowhook_init)dlsym(h, "shadowhook_init");
    g_sh_hook_addr = (fn_shadowhook_hook_func_addr)dlsym(h, "shadowhook_hook_func_addr");
    g_sh_get_errno = (fn_shadowhook_get_errno)dlsym(h, "shadowhook_get_errno");
    if (!g_sh_init || !g_sh_hook_addr) {
        kl_native_log("KL shadowhook symbols FAIL");
        return false;
    }
    g_sh_init(0, 0); // debuggable=0, recordable=0
    kl_native_log("KL shadowhook init OK");
    return true;
}

static void kl_native_log(const char *msg) {
    LOGI("%s", msg);
    if (g_kl_class == nullptr || g_kl_log_method == nullptr) return;
    JNIEnv *env = nullptr;
    bool detach = false;
    if (g_kl_jvm == nullptr) return;
    jint st = g_kl_jvm->GetEnv((void **)&env, JNI_VERSION_1_6);
    if (st == JNI_EDETACHED) {
        if (g_kl_jvm->AttachCurrentThread(&env, nullptr) != JNI_OK) return;
        detach = true;
    }
    if (env) {
        jstring jmsg = env->NewStringUTF(msg);
        if (jmsg) {
            env->CallStaticVoidMethod(g_kl_class, g_kl_log_method, jmsg);
            env->DeleteLocalRef(jmsg);
        }
        if (detach) g_kl_jvm->DetachCurrentThread();
    }
}

// ============ JNI 入口 ============

// 后台轮询线程：等待 libflutter.so 加载后自动定位 + hook（Flutter 引擎可能延迟加载）
static void *kl_wait_thread(void *) {
    for (int i = 0; i < 300; i++) { // 最多等 300s（5 分钟），每 1s 检查一次
        if (g_hooked.load()) break;
        usleep(1000 * 1000);
        // 快速检查 libflutter.so 是否已加载
        bool loaded = false;
        FILE *f = fopen("/proc/self/maps", "r");
        if (f) {
            char line[512];
            while (fgets(line, sizeof(line), f)) {
                if (strstr(line, "libflutter.so")) { loaded = true; break; }
            }
            fclose(f);
        }
        if (!loaded) continue;

        // 已加载 → 定位 + hook
        SoRange rng;
        uintptr_t co = 0, cbo = 0;
        uintptr_t target = locate_ssl_log_secret(rng, &co, &cbo);
        if (!target) {
            kl_native_log("KL retry: libflutter.so loaded but locate FAIL");
            continue; // 继续等（可能部分加载）
        }
        g_ctx_off = co;
        g_cb_off = cbo;
        g_offsets_valid = (co != 0 && cbo != 0);
        g_ssl_log_secret_addr = target;
        void *orig = nullptr;
        void *stub = g_sh_hook_addr((void *)target, (void *)my_ssl_log_secret, &orig);
        if (stub == nullptr || orig == nullptr) {
            char buf[128];
            int err = g_sh_get_errno ? g_sh_get_errno() : -1;
            snprintf(buf, sizeof(buf), "KL retry: shadowhook_hook_func_addr FAIL errno=%d", err);
            kl_native_log(buf);
            continue;
        }
        g_orig_ssl_log_secret = (orig_ssl_log_secret_t)orig;
        g_hooked.store(true);
        kl_native_log("KL hook OK (delayed) — libflutter.so keylog 注入成功");
        break;
    }
    return nullptr;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_dustinky_spyprobe_NativeProbe_flutterKeylogInit(JNIEnv *env, jobject thiz) {
    if (g_hooked.load()) return JNI_TRUE;
    if (g_in_progress.exchange(true)) return JNI_FALSE; // 防重入

    env->GetJavaVM(&g_kl_jvm);
    jclass clazz = env->FindClass("com/dustinky/spyprobe/NativeProbe");
    if (!clazz) { g_in_progress = false; return JNI_FALSE; }
    g_kl_class = (jclass)env->NewGlobalRef(clazz);
    g_kl_method = env->GetStaticMethodID(clazz, "nativeKeylog", "(Ljava/lang/String;)V");
    g_kl_log_method = env->GetStaticMethodID(clazz, "nativeLog", "(Ljava/lang/String;)V");

    if (!load_shadowhook()) { g_in_progress = false; return JNI_FALSE; }

    // 立即尝试一次（libflutter.so 已加载场景）
    SoRange rng;
    uintptr_t co = 0, cbo = 0;
    uintptr_t target = locate_ssl_log_secret(rng, &co, &cbo);
    if (target) {
        g_ctx_off = co;
        g_cb_off = cbo;
        g_offsets_valid = (co != 0 && cbo != 0);
        g_ssl_log_secret_addr = target;
        void *orig = nullptr;
        void *stub = g_sh_hook_addr((void *)target, (void *)my_ssl_log_secret, &orig);
        if (stub != nullptr && orig != nullptr) {
            g_orig_ssl_log_secret = (orig_ssl_log_secret_t)orig;
            g_hooked.store(true);
            g_in_progress = false;
            kl_native_log("KL hook OK — libflutter.so keylog 注入成功");
            return JNI_TRUE;
        }
        char buf[128];
        int err = g_sh_get_errno ? g_sh_get_errno() : -1;
        snprintf(buf, sizeof(buf), "KL shadowhook_hook_func_addr FAIL errno=%d", err);
        kl_native_log(buf);
        g_in_progress = false;
        return JNI_FALSE;
    }

    // libflutter.so 尚未加载（或加载了但定位失败）→ 后台线程持续重试
    kl_native_log("KL libflutter.so not loaded yet — background retry started");
    g_in_progress = false;
    pthread_t tid;
    pthread_create(&tid, nullptr, kl_wait_thread, nullptr);
    pthread_detach(tid);
    return JNI_FALSE; // 立即返回 false（后台继续），Java 侧 log "FAILED/not-yet"
}
