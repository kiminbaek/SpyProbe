/*
 * flutter_keylog.cpp — v1.70
 * Conscrypt JNI SSL_write/SSL_read hook（业务流量明文根治）+ libflutter.so keylog 注入器
 *
 * v1.70 重大转向（2026-08-13，用户质疑"通用性"后真机日志+反汇编实锤）：
 *   1) KL 定位的 libflutter.so ssl_log_secret（so+0x71d278）反汇编实锤是 Dart VM native
 *      函数（bl 目标全在 Dart runtime 区），不是 BoringSSL → v1.67/1.68/1.69 keylog 路线
 *      目标函数错、参数 ABI 不匹配、keylog 0 行 → 路线废弃（不可通用）。
 *   2) 91aw 业务流量（dart:io）走 Conscrypt（libconscrypt_jni.so 内嵌 BoringSSL 静态链接
 *      + JNI 调用）→ xhook(PLT/GOT) 双失效 → 业务 API 明文全漏。
 *   3) 根治：shadowhook inline hook Conscrypt JNI 导出函数
 *      Java_org_conscrypt_NativeCrypto_SSL_write / SSL_read（dlsym 可定位），
 *      提取 ByteBuffer 明文直喂 callback_kotlin（REQ# 结构化通道）。
 *      通杀：所有走 Conscrypt 的 app（Android 默认 TLS 引擎，覆盖 OkHttp/dart:io）。
 *
 * 背景（2026-08-12 实锤）：
 *   dart:io 自带 BoringSSL，符号静态链接在 libflutter.so 内，不导出 → xhook(PLT/GOT)
 *   无效（v1.66 实测 Flutter 层业务 API 全漏）。但 libc send/recv 层密文全量可抓，
 *   配合 keylog(CLIENT_RANDOM + secrets) 即可在 Java 侧内部解密 TLS → 明文。
 *   （注：v1.70 起 keylog 仅作辅助手段保留，主路径改为 Conscrypt JNI 明文 hook）
 *
 * v1.68 修复（2026-08-13，真机 keylog 0 行根因）：
 *   v1.67 的 locator 用"多 label 调用者的 bl 目标取交集"选目标 → 交集命中两个
 *   keylog 函数（TLS1.2 ssl_log_master_secret / TLS1.3 ssl_log_secret）的公共
 *   中间块（so+0x71751c，非函数头、参数 ABI 不匹配）→ hook 空转，keylog 0 行。
 *
 *   根治：不取 callees 交集，直接定位真实函数头——
 *     a) 引用 "CLIENT_RANDOM" 的函数头 = TLS1.2 ssl_log_master_secret（5 参）
 *     b) 引用 4 个 "TRAFFIC_SECRET" label 的函数头 = TLS1.3 ssl_log_secret（6 参）
 *   每个 wrapper 用 shadowhook hook 后，直接拿参数拼 keylog 行转发 Java：
 *      TLS1.3: "<label> <cr_hex> <secret_hex>"
 *      TLS1.2: "CLIENT_RANDOM <cr_hex> <ms_hex>"
 *   （不再依赖 keylog_callback 结构偏移——彻底绕开偏移提取错误）
 *
 * v1.69 新增（2026-08-13，v1.68 真机日志零 KL 行排查）：
 *   1) 日志双通道：KL 调试日志（nativeLog）同时进 LogStore（抓包日志页）——
 *      用户导出的抓包日志即可直接看到 keylog/dart:io hook 状态（此前只走 DebugLog 看不见）。
 *   2) 新增 dart:io native entries 函数 hook（定位来自 .rela.dyn RELATIVE 重定位实锤）：
 *        Filter_Process      so+0x82f1f4  dart:io _SecureFilter.process   （TLS 加密前明文）
 *        Filter_Processed    so+0x82f4a8  dart:io _SecureFilter.processed （TLS 解密后明文）
 *        SecureSocket_Init   so+0x834140  dart:io 创建 SSL_CTX 入口
 *        SecureSocket_Connect so+0x83507c dart:io 建立 TLS 连接入口
 *      每次 IO 必调用（不受 keep-alive 影响）；v1.69 先打 invoked 日志验证 hook 触发，
 *      v1.70 再基于触发情况提取明文参数（Dart_NativeArguments 解析）。
 *
 * 定位策略（跨 Flutter 版本 4 样本验证）：
 *   1. 扫描 .rodata 找 label 锚点字符串（CLIENT_RANDOM / TRAFFIC_SECRET 系列）
 *   2. 扫描 .text 找 adrp+add 指令对引用锚点的位置
 *   3. 从引用点回溯函数头（sub sp / stp x29,x30）
 *   4. TLS1.3 = 4 个 TRAFFIC_SECRET label 引用函数头交集
 *      TLS1.2 = CLIENT_RANDOM 引用函数头
 *
 * 注入（shadowhook 2.0.1 预编译 .so，dlopen 动态加载）：
 *   shadowhook_hook_func_addr(func, my_func, &orig) × 2（TLS1.2 + TLS1.3）
 *   + × 4（dart:io native entries，v1.69）
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
#include <sys/mman.h>
#include <sys/syscall.h>

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
static uintptr_t g_tls13_func = 0;  // TLS1.3 ssl_log_secret 运行时绝对地址
static uintptr_t g_tls12_func = 0;  // TLS1.2 ssl_log_master_secret 运行时绝对地址

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

// sub sp, sp, #imm（函数头）: 0xD10003FF mask
static bool is_sub_sp(uint32_t insn) {
    return (insn & 0xFFC003FFu) == 0xD10003FFu;
}

// stp x29, x30, [sp, #-imm]!（函数头）: 0xA9A00000 变体 mask
static bool is_stp_x29x30_pre(uint32_t insn) {
    return (insn & 0xFFC003FFu) == 0xA98003FFu;
}

// bl/b 立即数跳转解码：返回目标地址（0 = 非 bl/b）
static uintptr_t decode_bl_b(uint32_t insn, uintptr_t pc) {
    uint32_t op;
    if ((insn & 0xFC000000u) == 0x94000000u) op = 0;        // BL
    else if ((insn & 0xFC000000u) == 0x14000000u) op = 0;   // B
    else return 0;
    int32_t imm26 = (int32_t)(insn & 0x03FFFFFFu);
    if (imm26 & (1 << 25)) imm26 -= (1 << 26);              // 符号扩展
    return pc + (uintptr_t)imm26 * 4;
}

// ldr xRt, [xRn, #imm]（64 位立即数偏移）: 0xF9400000 变体 mask
static bool decode_ldr_imm(uint32_t insn, int *rt, int *rn, uint32_t *imm) {
    if ((insn & 0xFFC00000u) != 0xF9400000u) return false;
    *rt = (int)(insn & 0x1F);
    *rn = (int)((insn >> 5) & 0x1F);
    *imm = ((insn >> 10) & 0xFFFu) * 8u;  // scaled by 8 (64-bit)
    return true;
}

// cbz xRt, #imm（64 位）: 0xB4000000 变体 mask
static bool decode_cbz(uint32_t insn) {
    return (insn & 0x7F000000u) == 0x34000000u ||
           (insn & 0x7F000000u) == 0x35000000u; // cbz/cbnz
}

// blr xN: 0xD63F0000 mask 0xFFFFFC1F
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
static uintptr_t find_anchor_in_range(const uintptr_t start, const size_t len, const char *needle) {
    size_t nlen = strlen(needle) + 1; // 含 \0
    const char *base = (const char *)start;
    for (size_t i = 0; i + nlen <= len; i++) {
        if (base[i] == needle[0] && memcmp(base + i, needle, nlen) == 0) {
            return start + i;
        }
    }
    return 0;
}

// 模式验证：候选函数头 0x300 内是否含 keylog_callback 调用特征
//   ldr x?, [x?, #0x50~0x90]   (ssl->ctx 读取)
//   ldr x?, [x?, #0x1E0~0x250] (ctx->keylog_callback 读取)
//   cbz/cbnz + blr（callback 判空 + 间接调用）
static bool verify_keylog_func(const SoRange &rng, uintptr_t head) {
    const uint32_t *code = (const uint32_t *)rng.text_addr;
    bool found_ctx = false;
    int cb_ldr = 0;
    bool found_cbz = false;
    bool found_blr = false;
    if (head < rng.text_addr || head >= rng.text_addr + rng.text_size) return false;
    size_t max_insns = (rng.text_addr + rng.text_size - head) / 4;
    if (max_insns > 0x300 / 4) max_insns = 0x300 / 4;
    for (size_t i = 0; i < max_insns; i++) {
        uint32_t insn = code[(head - rng.text_addr) / 4 + i];
        int rt, rn; uint32_t imm;
        if (decode_ldr_imm(insn, &rt, &rn, &imm)) {
            if (imm >= 0x50 && imm <= 0x90) found_ctx = true;
            if (imm >= 0x1E0 && imm <= 0x250) cb_ldr++;
            continue;
        }
        if (decode_cbz(insn)) { found_cbz = true; continue; }
        if (is_blr(insn)) { found_blr = true; continue; }
    }
    return found_ctx && cb_ldr >= 1 && found_cbz && found_blr;
}

// 从 label 引用点向后扫 bl/b 目标，返回验证通过的候选（wrapper -> 真函数）
static void scan_bl_b_targets(const SoRange &rng, uintptr_t ref,
                              std::set<uintptr_t> &verified) {
    if (ref < rng.text_addr || ref >= rng.text_addr + rng.text_size) return;
    const uint32_t *code = (const uint32_t *)rng.text_addr;
    size_t max_insns = (rng.text_addr + rng.text_size - ref) / 4;
    if (max_insns > 0x200 / 4) max_insns = 0x200 / 4;   // 向后扫 0x200 字节
    for (size_t i = 0; i < max_insns; i++) {
        uint32_t insn = code[(ref - rng.text_addr) / 4 + i];
        uintptr_t tgt = decode_bl_b(insn, ref + i * 4);
        if (tgt && tgt != ref && tgt >= rng.text_addr && tgt < rng.text_addr + rng.text_size) {
            if (verify_keylog_func(rng, tgt)) {
                verified.insert(tgt);
            }
        }
    }
}


// ============ 定位 keylog 函数 ============

// 扫描 .text 找引用 anchor 的 adrp+add 指令对 → 返回所有 add 指令地址
static void scan_adrp_add_refs(const SoRange &rng, uintptr_t anchor,
                               std::vector<uintptr_t> &refs) {
    const uint32_t *code = (const uint32_t *)rng.text_addr;
    size_t n = rng.text_size / 4;
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
                int keep = 32;
                for (int k = 0; k < keep; k++) recent[k] = recent[recent_n - keep + k];
                recent_n = keep;
                recent[recent_n++] = {pc, rd, tpage};
            }
            continue;
        }
        int add_rd, add_rn; uint32_t add_imm;
        if (decode_add_imm(insn, &add_rd, &add_rn, &add_imm)) {
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

// 主定位入口：定位两个 keylog 函数绝对地址（0 = 未找到）
// *out_tls13 = TLS1.3 ssl_log_secret（4 个 TRAFFIC_SECRET label 引用 → 回溯函数头 或 bl/b 目标）
// *out_tls12 = TLS1.2 ssl_log_master_secret（CLIENT_RANDOM 引用 → 同上）
// v2.2.2 通用修复（2026-08-17，91aw v2.2.4 反汇编实锤）：
//   旧 find_func_head 从 label 引用点回溯 0x400 认错了函数头（0x71d278 是 Flutter 普通函数，
//   真 ssl_log_secret 0x71751c 在引用点之前很远，且 label 是调用方通过 x1 传入、函数内不引用）。
//   新法：从 label 引用点向后扫 bl/b 目标（wrapper → 真函数一跳），候选必须通过
//   verify_keylog_func 模式验证（ldr ctx + ldr callback + cbz + blr），跨版本通用。
//   双法并集取交集 + 投票兜底：任何 APP 只要 label 引用点存在就能定位，不依赖具体偏移。
static void locate_keylog_funcs(SoRange &rng, uintptr_t *out_tls13, uintptr_t *out_tls12) {
    static const char *ANCHORS_TLS13[] = {
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        "CLIENT_TRAFFIC_SECRET_0",
        "SERVER_TRAFFIC_SECRET_0",
    };
    const int TLS13_N = 4;
    *out_tls13 = 0;
    *out_tls12 = 0;
    if (!find_libflutter_ranges(rng)) {
        kl_native_log("KL locate: find_libflutter_ranges FAIL");
        return;
    }

    char buf[256];
    snprintf(buf, sizeof(buf), "KL libflutter.so base=0x%lx text=0x%lx+%zu rodata=0x%lx+%zu",
             (unsigned long)rng.base, (unsigned long)rng.text_addr, rng.text_size,
             (unsigned long)rng.rodata_addr, rng.rodata_size);
    kl_native_log(buf);

    // 收集一个 anchor 的全部候选函数头：旧法（find_func_head）+ 新法（bl/b 目标验证）
    auto collect_candidates = [&](const char *anchor_name,
                                  std::set<uintptr_t> &cands,
                                  std::map<uintptr_t,int> &votes) {
        uintptr_t anchor = find_anchor_in_range(rng.rodata_addr, rng.rodata_size, anchor_name);
        if (!anchor) {
            snprintf(buf, sizeof(buf), "KL anchor %s NOT FOUND", anchor_name);
            kl_native_log(buf);
            return;
        }
        std::vector<uintptr_t> refs;
        scan_adrp_add_refs(rng, anchor, refs);
        snprintf(buf, sizeof(buf), "KL anchor %s: refs=%zu", anchor_name, refs.size());
        kl_native_log(buf);
        for (uintptr_t r : refs) {
            // 旧法：回溯函数头（标准 BoringSSL：label 由函数体内部引用）
            uintptr_t h = find_func_head(rng, r);
            if (h && verify_keylog_func(rng, h)) {
                cands.insert(h);
                votes[h]++;
            }
            // 新法：向后扫 bl/b 目标（91aw/部分 Dart 版本：label 由 wrapper 引用后跳转真函数）
            std::set<uintptr_t> blb;
            scan_bl_b_targets(rng, r, blb);
            for (uintptr_t t : blb) {
                cands.insert(t);
                votes[t]++;
            }
        }
        snprintf(buf, sizeof(buf), "KL anchor %s: cands=%zu", anchor_name, cands.size());
        kl_native_log(buf);
    };

    // ---- TLS1.3：4 个 TRAFFIC_SECRET label 候选交集（带投票兜底） ----
    std::set<uintptr_t> common;
    std::map<uintptr_t,int> votes;
    bool first = true;
    for (int a = 0; a < TLS13_N; a++) {
        std::set<uintptr_t> cands;
        std::map<uintptr_t,int> v;
        collect_candidates(ANCHORS_TLS13[a], cands, v);
        for (auto &kv : v) votes[kv.first] += kv.second;
        snprintf(buf, sizeof(buf), "KL TLS13[%d] %s: cands=%zu",
                 a, ANCHORS_TLS13[a], cands.size());
        kl_native_log(buf);
        if (first) { common = cands; first = false; }
        else {
            std::set<uintptr_t> inter;
            for (uintptr_t c : common) if (cands.count(c)) inter.insert(c);
            common = inter;
        }
        if (common.empty()) break;
    }
    if (!common.empty()) {
        *out_tls13 = *common.begin();
        snprintf(buf, sizeof(buf), "KL TLS1.3 ssl_log_secret FOUND 0x%lx (so+0x%lx)",
                 (unsigned long)*out_tls13, (unsigned long)(*out_tls13 - rng.base));
        kl_native_log(buf);
    } else {
        // 投票兜底：取验证通过次数最多的候选（跨 label 一致）
        int best = 0;
        for (auto &kv : votes) {
            if (kv.second > best) { best = kv.second; *out_tls13 = kv.first; }
        }
        if (*out_tls13) {
            snprintf(buf, sizeof(buf), "KL TLS1.3 ssl_log_secret FOUND(vote) 0x%lx (so+0x%lx) votes=%d",
                     (unsigned long)*out_tls13, (unsigned long)(*out_tls13 - rng.base), best);
            kl_native_log(buf);
        } else {
            kl_native_log("KL TLS1.3 交集 EMPTY — ssl_log_secret 定位失败");
        }
    }

    // ---- TLS1.2：CLIENT_RANDOM 候选（同样双法） ----
    {
        std::set<uintptr_t> cands;
        std::map<uintptr_t,int> v;
        collect_candidates("CLIENT_RANDOM", cands, v);
        snprintf(buf, sizeof(buf), "KL TLS1.2 CLIENT_RANDOM: cands=%zu", cands.size());
        kl_native_log(buf);
        if (!cands.empty()) {
            *out_tls12 = *cands.begin();
            snprintf(buf, sizeof(buf), "KL TLS1.2 ssl_log_master_secret FOUND 0x%lx (so+0x%lx)",
                     (unsigned long)*out_tls12, (unsigned long)(*out_tls12 - rng.base));
            kl_native_log(buf);
        } else {
            kl_native_log("KL TLS1.2 CLIENT_RANDOM 定位失败");
        }
    }
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

// v2.2.2 通用安全读取：mincore 校验指针可读后再拷贝，杜绝参数乱码/不可读指针导致崩溃
static bool safe_read(const void *p, size_t len, void *out, size_t cap) {
    if (p == nullptr || out == nullptr || len == 0 || len > cap) return false;
    uintptr_t a = (uintptr_t)p;
    if (a < 0x1000 || (a & 0xFFF) + len < len) return false;   // 低地址/溢出
    // mincore: 检查覆盖页是否已映射（不检查具体读权限，但至少避免野指针段错误）
    unsigned char vec[16];
    uintptr_t start_page = a & ~(uintptr_t)0xFFF;
    size_t pages = ((a - start_page) + len + 0xFFF) / 0x1000;
    if (pages > 16) return false;
#if defined(__linux__)
    if (syscall(SYS_mincore, (void *)start_page, pages * 0x1000, vec) != 0) return false;
    for (size_t i = 0; i < pages; i++) if (!(vec[i] & 1)) return false;
#endif
    memcpy(out, p, len);
    return true;
}

// 安全拷贝 label（可能不可读/非字符串），返回规范化字符串
static const char *safe_label(const char *label, char *buf, size_t cap) {
    if (label == nullptr) return "(null)";
    if (!safe_read(label, cap - 1, buf, cap - 1)) return "(unreadable)";
    buf[cap - 1] = '\0';
    // 只保留可打印 ASCII，防止乱码刷屏
    for (size_t i = 0; i < cap - 1; i++) {
        char c = buf[i];
        if (c == '\0') break;
        if (c < 0x20 || c > 0x7E) buf[i] = '?';
    }
    return buf;
}

// 通用：拼 keylog 行并转发 Java（不依赖 keylog_callback 结构偏移）
static void kl_emit_line(const void *ssl, const char *label,
                         const uint8_t *cr, size_t cr_len,
                         const uint8_t *sec, size_t sec_len) {
    if (label == nullptr || cr == nullptr || sec == nullptr) return;
    // label + ' ' + cr_hex + ' ' + secret_hex
    size_t llen = strlen(label);
    size_t need = llen + 1 + cr_len * 2 + 1 + sec_len * 2 + 1;
    if (need > 1024) return;
    char line[1024];
    size_t off = 0;
    memcpy(line + off, label, llen); off += llen;
    line[off++] = ' ';
    for (size_t i = 0; i < cr_len; i++) {
        static const char HEX[] = "0123456789abcdef";
        line[off++] = HEX[(cr[i] >> 4) & 0xF];
        line[off++] = HEX[cr[i] & 0xF];
    }
    line[off++] = ' ';
    for (size_t i = 0; i < sec_len; i++) {
        static const char HEX[] = "0123456789abcdef";
        line[off++] = HEX[(sec[i] >> 4) & 0xF];
        line[off++] = HEX[sec[i] & 0xF];
    }
    line[off] = '\0';
    kl_keylog_cb(ssl, line);
}

// ============ TLS1.3 ssl_log_secret hook ============
// BoringSSL 签名：void ssl_log_secret(const SSL *ssl, const char *label,
//   const uint8_t *client_random, size_t client_random_len,
//   const uint8_t *secret, size_t secret_len)
typedef void (*orig_ssl_log_secret_t)(const void *ssl, const char *label,
                                      const uint8_t *client_random, size_t client_random_len,
                                      const uint8_t *secret, size_t secret_len);
static orig_ssl_log_secret_t g_orig_ssl_log_secret = nullptr;

static std::atomic<int> g_tls13_calls{0};
static std::atomic<int> g_tls12_calls{0};

static void my_ssl_log_secret(const void *ssl, const char *label,
                              const uint8_t *client_random, size_t client_random_len,
                              const uint8_t *secret, size_t secret_len) {
    // v2.2.2 通用化：所有指针经 safe_read 校验 + 规范化 label 后才使用，
    // 参数乱码/不可读指针不再直接解引用（v2.2.0 断网根因之一）
    int n = g_tls13_calls.fetch_add(1) + 1;
    char lbl_buf[96];
    const char *lbl = safe_label(label, lbl_buf, sizeof(lbl_buf));
    if (n <= 5 || (n % 50) == 0) {
        char b[224];
        snprintf(b, sizeof(b), "KL T13 CALL #%d ssl=%p label=%s crptr=%p crlen=%zu secptr=%p seclen=%zu",
                 n, ssl, lbl, client_random, client_random_len, secret, secret_len);
        kl_native_log(b);
    }
    // 诊断：secret 前 8 字节 hex（确认参数有效性）
    if (n <= 3) {
        uint8_t tmp[8];
        if (safe_read(secret, 8, tmp, sizeof(tmp))) {
            char b[80];
            snprintf(b, sizeof(b), "KL T13 secret[0:8]=%02x%02x%02x%02x%02x%02x%02x%02x",
                     tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5], tmp[6], tmp[7]);
            kl_native_log(b);
        } else {
            kl_native_log("KL T13 secret unreadable");
        }
        uint8_t cr[8];
        if (safe_read(client_random, 8, cr, sizeof(cr))) {
            char b[80];
            snprintf(b, sizeof(b), "KL T13 cr[0:8]=%02x%02x%02x%02x%02x%02x%02x%02x",
                     cr[0], cr[1], cr[2], cr[3], cr[4], cr[5], cr[6], cr[7]);
            kl_native_log(b);
        } else {
            kl_native_log("KL T13 cr unreadable");
        }
    }
    // 仅当 label/cr/secret 均可读且长度合理才 emit（防乱码进日志页）
    if (client_random_len <= 64 && secret_len <= 256) {
        uint8_t cr[64], sec[256];
        if (safe_read(client_random, client_random_len, cr, sizeof(cr)) &&
            safe_read(secret, secret_len, sec, sizeof(sec)) &&
            cr != nullptr && sec != nullptr) {
            kl_emit_line(ssl, lbl, cr, client_random_len, sec, secret_len);
        }
    }
    if (g_orig_ssl_log_secret != nullptr) {
        g_orig_ssl_log_secret(ssl, label, client_random, client_random_len, secret, secret_len);
    }
}

// ============ TLS1.2 ssl_log_master_secret hook ============
// BoringSSL 签名：void ssl_log_master_secret(const SSL_HANDSHAKE *hs,
//   const uint8_t *client_random, size_t client_random_len,
//   const uint8_t *master_secret, size_t master_secret_len)
typedef void (*orig_ssl_log_master_secret_t)(const void *hs,
                                             const uint8_t *client_random, size_t client_random_len,
                                             const uint8_t *master_secret, size_t master_secret_len);
static orig_ssl_log_master_secret_t g_orig_ssl_log_master_secret = nullptr;

static void my_ssl_log_master_secret(const void *hs,
                                     const uint8_t *client_random, size_t client_random_len,
                                     const uint8_t *master_secret, size_t master_secret_len) {
    // v2.2.2 通用化：safe_read 校验后使用
    int n = g_tls12_calls.fetch_add(1) + 1;
    if (n <= 5 || (n % 50) == 0) {
        char b[192];
        snprintf(b, sizeof(b), "KL T12 CALL #%d hs=%p crlen=%zu mslen=%zu",
                 n, hs, client_random_len, master_secret_len);
        kl_native_log(b);
    }
    if (client_random_len <= 64 && master_secret_len <= 256) {
        uint8_t cr[64], sec[256];
        if (safe_read(client_random, client_random_len, cr, sizeof(cr)) &&
            safe_read(master_secret, master_secret_len, sec, sizeof(sec))) {
            kl_emit_line(hs, "CLIENT_RANDOM", cr, client_random_len, sec, master_secret_len);
        }
    }
    if (g_orig_ssl_log_master_secret != nullptr) {
        g_orig_ssl_log_master_secret(hs, client_random, client_random_len, master_secret, master_secret_len);
    }
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

// 尝试 hook 两个 keylog 函数；返回成功 hook 数
static int hook_keylog_funcs(SoRange &rng, uintptr_t tls13, uintptr_t tls12) {
    int ok = 0;
    // v2.2.2: TLS12 与 TLS13 可能是同一函数（91aw 反汇编实锤 CLIENT_RANDOM 与
    //   TRAFFIC_SECRET wrapper 都 bl 到 0x71751c）→ 相同地址只 hook 一次，
    //   my_ssl_log_secret 按 label 同时服务 TLS1.2/1.3。
    if (tls13 != 0 && tls12 == tls13) {
        void *orig = nullptr;
        void *stub = g_sh_hook_addr((void *)tls13, (void *)my_ssl_log_secret, &orig);
        if (stub != nullptr && orig != nullptr) {
            g_orig_ssl_log_secret = (orig_ssl_log_secret_t)orig;
            g_tls13_func = tls13;
            g_tls12_func = tls12;
            ok++;
            kl_native_log("KL ssl_log_secret hook OK (TLS1.2+1.3 同函数)");
        } else {
            char buf[160];
            int err = g_sh_get_errno ? g_sh_get_errno() : -1;
            snprintf(buf, sizeof(buf), "KL ssl_log_secret hook FAIL errno=%d", err);
            kl_native_log(buf);
        }
        return ok;
    }
    if (tls13 != 0) {
        void *orig = nullptr;
        void *stub = g_sh_hook_addr((void *)tls13, (void *)my_ssl_log_secret, &orig);
        if (stub != nullptr && orig != nullptr) {
            g_orig_ssl_log_secret = (orig_ssl_log_secret_t)orig;
            g_tls13_func = tls13;
            ok++;
            kl_native_log("KL TLS1.3 ssl_log_secret hook OK");
        } else {
            char buf[160];
            int err = g_sh_get_errno ? g_sh_get_errno() : -1;
            snprintf(buf, sizeof(buf), "KL TLS1.3 hook FAIL errno=%d", err);
            kl_native_log(buf);
        }
    }
    if (tls12 != 0) {
        void *orig = nullptr;
        void *stub = g_sh_hook_addr((void *)tls12, (void *)my_ssl_log_master_secret, &orig);
        if (stub != nullptr && orig != nullptr) {
            g_orig_ssl_log_master_secret = (orig_ssl_log_master_secret_t)orig;
            g_tls12_func = tls12;
            ok++;
            kl_native_log("KL TLS1.2 ssl_log_master_secret hook OK");
        } else {
            char buf[160];
            int err = g_sh_get_errno ? g_sh_get_errno() : -1;
            snprintf(buf, sizeof(buf), "KL TLS1.2 hook FAIL errno=%d", err);
            kl_native_log(buf);
        }
    }
    return ok;
}

// ============ v1.69: dart:io native entries 函数 hook ============
// 91aw libflutter.so 静态 vaddr（.rela.dyn RELATIVE 重定位 addend 实锤：
//   名槽 name_ptr 指向 rodata 字符串，函数槽 func_ptr 运行时 = base + addend）
// 每次 dart:io TLS IO 必调用（不受 keep-alive 影响），用于验证 hook 触发 + 后续明文提取。
static const uintptr_t OFF_FILTER_PROCESS = 0x82f1f4;        // _SecureFilter.process（TLS 加密前明文）
static const uintptr_t OFF_FILTER_PROCESSED = 0x82f4a8;      // _SecureFilter.processed（TLS 解密后明文）
static const uintptr_t OFF_SECURE_SOCKET_INIT = 0x834140;    // SecureSocket_Init（SSL_CTX 创建）
static const uintptr_t OFF_SECURE_SOCKET_CONNECT = 0x83507c; // SecureSocket_Connect（TLS 握手）

typedef void (*dart_native_fn_t)(void *args);
static dart_native_fn_t g_orig_filter_process = nullptr;
static dart_native_fn_t g_orig_filter_processed = nullptr;
static dart_native_fn_t g_orig_secure_socket_init = nullptr;
static dart_native_fn_t g_orig_secure_socket_connect = nullptr;
static std::atomic<bool> g_dart_io_hooked{false};

// v2.1.0 P2: invoked 调试行结构化升级——每函数累计计数 + 节流。
//   此前 Filter_Process/Processed 每个 TLS 块都无条件打一条 → 日志页整屏纯文本刷屏。
//   现按 T13 CALL 同款节流（前 5 次 + 每 100 次打一条），行内带 #N 真实累计调用次数，
//   Java 侧 NativeProbe.klAggregate 解析 #N 聚合为 SpyEvent(KL) 事件卡（标题含真实次数）。
static std::map<std::string, std::atomic<uint64_t>> g_kl_invoked_count;

static void kl_log_invoked(const char *name, void *args) {
    uint64_t n = g_kl_invoked_count[std::string(name)].fetch_add(1) + 1;
    if (n > 5 && (n % 100) != 0) return;   // 节流：>5 后每 100 次留痕一条
    char buf[192];
    snprintf(buf, sizeof(buf), "KL dart:io %s #%llu invoked (args=%p)",
             name, (unsigned long long)n, args);
    kl_native_log(buf);
}

static void my_filter_process(void *args) {
    kl_log_invoked("Filter_Process", args);
    if (g_orig_filter_process) g_orig_filter_process(args);
}
static void my_filter_processed(void *args) {
    kl_log_invoked("Filter_Processed", args);
    if (g_orig_filter_processed) g_orig_filter_processed(args);
}
static void my_secure_socket_init(void *args) {
    kl_log_invoked("SecureSocket_Init", args);
    if (g_orig_secure_socket_init) g_orig_secure_socket_init(args);
}
static void my_secure_socket_connect(void *args) {
    kl_log_invoked("SecureSocket_Connect", args);
    if (g_orig_secure_socket_connect) g_orig_secure_socket_connect(args);
}

static int hook_dart_io_functions(const SoRange &rng) {
    if (!g_sh_hook_addr || g_dart_io_hooked.load()) return 0;
    int ok = 0;
    struct HookDef {
        const char *name;
        uintptr_t off;
        dart_native_fn_t *orig;
        dart_native_fn_t wrap;
    };
    HookDef hooks[] = {
        {"Filter_Process", OFF_FILTER_PROCESS, &g_orig_filter_process, my_filter_process},
        {"Filter_Processed", OFF_FILTER_PROCESSED, &g_orig_filter_processed, my_filter_processed},
        {"SecureSocket_Init", OFF_SECURE_SOCKET_INIT, &g_orig_secure_socket_init, my_secure_socket_init},
        {"SecureSocket_Connect", OFF_SECURE_SOCKET_CONNECT, &g_orig_secure_socket_connect, my_secure_socket_connect},
    };
    for (auto &h : hooks) {
        uintptr_t target = rng.base + h.off;
        void *orig = nullptr;
        void *stub = g_sh_hook_addr((void *)target, (void *)h.wrap, &orig);
        if (stub != nullptr && orig != nullptr) {
            *h.orig = (dart_native_fn_t)orig;
            ok++;
            char buf[192];
            snprintf(buf, sizeof(buf), "KL dart:io hook %s OK (0x%lx)", h.name, (unsigned long)target);
            kl_native_log(buf);
        } else {
            char buf[192];
            int err = g_sh_get_errno ? g_sh_get_errno() : -1;
            snprintf(buf, sizeof(buf), "KL dart:io hook %s FAIL errno=%d (0x%lx)", h.name, err, (unsigned long)target);
            kl_native_log(buf);
        }
    }
    if (ok > 0) g_dart_io_hooked.store(true);
    return ok;
}

// ============ Conscrypt JNI SSL_write/SSL_read hook (v1.70) ============
// 背景（2026-08-13 真机日志 + 静态反汇编实锤）：
//   91aw 业务流量（dart:io）走 Conscrypt（Android 系统 TLS 引擎，libconscrypt_jni.so
//   内嵌 BoringSSL 静态链接 + JNI 调用）→ xhook(PLT/GOT) 双失效 → 业务 API 明文全漏，
//   只抓到走系统 BoringSSL 的播放链路（OkHttp/ExoPlayer）。
//   KL 定位的 libflutter.so ssl_log_secret 反汇编实锤是 Dart VM native 函数（误匹配）。
// 方案：shadowhook inline hook Conscrypt 的 JNI 导出函数
//   Java_org_conscrypt_NativeCrypto_SSL_write / SSL_read
//   （JNI 静态导出符号 dlsym 可定位；参数是 ByteBuffer 明文，直接喂 callback_kotlin
//   结构化通道 REQ#）。通杀所有走 Conscrypt 的 app（Android 默认 TLS 引擎）。
// native_hook.cpp 提供的结构化明文入口（HTTP1 解析 + REQ# 卡片）
extern bool callback_kotlin(jlong id, bool is_write, const void *buf, size_t len, bool is_ssl);

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
    *out_len = 0;
    if (!obj || len <= 0 || out_cap == 0) return false;
    size_t n = (size_t)len;
    if (n > out_cap) n = out_cap;
    // 1) DirectByteBuffer（Conscrypt 网络路径主流）
    void* direct = env->GetDirectBufferAddress(obj);
    if (direct) {
        memcpy(out, (const uint8_t*)direct + offset, n);
        *out_len = n;
        return true;
    }
    // 2) Heap ByteBuffer（hasArray() → array()）
    if (g_bb_class && env->IsInstanceOf(obj, g_bb_class)) {
        if (env->CallBooleanMethod(obj, g_bb_has_array)) {
            jbyteArray arr = (jbyteArray)env->CallObjectMethod(obj, g_bb_array);
            if (arr) {
                jsize alen = env->GetArrayLength(arr);
                jbyte* elems = env->GetByteArrayElements(arr, nullptr);
                if (elems) {
                    if (offset < alen) {
                        size_t avail = (size_t)(alen - offset);
                        if (n > avail) n = avail;
                        memcpy(out, elems + offset, n);
                        *out_len = n;
                    }
                    env->ReleaseByteArrayElements(arr, elems, JNI_ABORT);
                    return true;
                }
            }
        }
        return false;
    }
    // 3) byte[]（老版 Conscrypt 签名 NativeCrypto.SSL_write(long,byte[],int,int)）
    jbyteArray arr = (jbyteArray)obj;
    jsize alen = env->GetArrayLength(arr);
    jbyte* elems = env->GetByteArrayElements(arr, nullptr);
    if (elems) {
        if (offset < alen) {
            size_t avail = (size_t)(alen - offset);
            if (n > avail) n = avail;
            memcpy(out, elems + offset, n);
            *out_len = n;
        }
        env->ReleaseByteArrayElements(arr, elems, JNI_ABORT);
        return true;
    }
    return false;
}

static jint my_cs_SSL_write(JNIEnv* env, jclass clazz, jlong ssl, jobject source, jint offset, jint len) {
    int n = g_cs_write_calls.fetch_add(1) + 1;
    if (n <= 5 || (n % 200) == 0) {
        char b[160];
        snprintf(b, sizeof(b), "CS SSL_write CALL #%d ssl=%lld len=%d", n, (long long)ssl, len);
        kl_native_log(b);
    }
    if (source && len > 0 && !g_cs_in_hook.exchange(true)) {
        uint8_t tmp[65536];
        size_t plen = 0;
        if ((size_t)len <= sizeof(tmp) && cs_extract_plain(env, source, offset, len, tmp, sizeof(tmp), &plen) && plen > 0) {
            callback_kotlin((jlong)ssl, true, tmp, plen, true);
        }
        g_cs_in_hook.store(false);
    }
    if (g_orig_cs_write) return g_orig_cs_write(env, clazz, ssl, source, offset, len);
    return -1;
}

static jint my_cs_SSL_read(JNIEnv* env, jclass clazz, jlong ssl, jobject target, jint offset, jint len, jint timeout) {
    jint ret = g_orig_cs_read ? g_orig_cs_read(env, clazz, ssl, target, offset, len, timeout) : -1;
    int n = g_cs_read_calls.fetch_add(1) + 1;
    if (n <= 5 || (n % 200) == 0) {
        char b[160];
        snprintf(b, sizeof(b), "CS SSL_read CALL #%d ssl=%lld ret=%d", n, (long long)ssl, ret);
        kl_native_log(b);
    }
    if (ret > 0 && target && !g_cs_in_hook.exchange(true)) {
        uint8_t tmp[65536];
        size_t plen = 0;
        if ((size_t)ret <= sizeof(tmp) && cs_extract_plain(env, target, offset, ret, tmp, sizeof(tmp), &plen) && plen > 0) {
            callback_kotlin((jlong)ssl, false, tmp, plen, true);
        }
        g_cs_in_hook.store(false);
    }
    return ret;
}

static bool install_conscrypt_hook() {
    if (g_conscrypt_hooked.load()) return true;
    if (!g_sh_hook_addr) { kl_native_log("CS install: shadowhook not loaded"); return false; }
    void* h = dlopen("libconscrypt_jni.so", RTLD_NOW | RTLD_NOLOAD);
    if (!h) h = dlopen("libconscrypt_jni.so", RTLD_NOW);
    if (!h) { kl_native_log("CS dlopen libconscrypt_jni.so FAIL"); return false; }
    void* write_fn = dlsym(h, "Java_org_conscrypt_NativeCrypto_SSL_write");
    void* read_fn  = dlsym(h, "Java_org_conscrypt_NativeCrypto_SSL_read");
    if (!write_fn || !read_fn) {
        char b[192];
        snprintf(b, sizeof(b), "CS dlsym NativeCrypto_SSL_write=%p SSL_read=%p FAIL", write_fn, read_fn);
        kl_native_log(b);
        dlclose(h);
        return false;
    }
    // 缓存 ByteBuffer 类与方法（heap buffer 提取用）
    if (!g_bb_class && g_kl_jvm) {
        JNIEnv* e = nullptr;
        g_kl_jvm->GetEnv((void**)&e, JNI_VERSION_1_6);
        if (e) {
            jclass tmp = e->FindClass("java/nio/ByteBuffer");
            if (tmp) {
                g_bb_class = (jclass)e->NewGlobalRef(tmp);
                e->DeleteLocalRef(tmp);
                g_bb_has_array = e->GetMethodID(g_bb_class, "hasArray", "()Z");
                g_bb_array = e->GetMethodID(g_bb_class, "array", "()[B");
            }
        }
    }
    void* w_orig = nullptr; void* r_orig = nullptr;
    void* ws = g_sh_hook_addr(write_fn, (void*)my_cs_SSL_write, &w_orig);
    void* rs = g_sh_hook_addr(read_fn,  (void*)my_cs_SSL_read,  &r_orig);
    char b[192];
    if (ws != nullptr && w_orig != nullptr) {
        g_orig_cs_write = (orig_cs_ssl_write_t)w_orig;
        g_conscrypt_hooked.store(true);
        snprintf(b, sizeof(b), "CS SSL_write hook OK (fn=%p)", write_fn);
    } else {
        int err = g_sh_get_errno ? g_sh_get_errno() : -1;
        snprintf(b, sizeof(b), "CS SSL_write hook FAIL errno=%d", err);
    }
    kl_native_log(b);
    if (rs != nullptr && r_orig != nullptr) {
        g_orig_cs_read = (orig_cs_ssl_read_t)r_orig;
        snprintf(b, sizeof(b), "CS SSL_read hook OK (fn=%p)", read_fn);
    } else {
        int err = g_sh_get_errno ? g_sh_get_errno() : -1;
        snprintf(b, sizeof(b), "CS SSL_read hook FAIL errno=%d", err);
    }
    kl_native_log(b);
    dlclose(h);
    return g_conscrypt_hooked.load();
}

// ============ JNI 入口 ============

// 后台轮询线程：等待 libflutter.so 加载后自动定位 + hook（Flutter 引擎可能延迟加载）
static void *kl_wait_thread(void *) {
    for (int i = 0; i < 300; i++) { // 最多等 300s（5 分钟），每 1s 检查一次
        if (g_hooked.load()) break;
        usleep(1000 * 1000);
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
        uintptr_t t13 = 0, t12 = 0;
        locate_keylog_funcs(rng, &t13, &t12);
        // v1.69: dart:io hooks 独立于 keylog 定位——rng.base 有效即 hook（一次成功不再重复）
        hook_dart_io_functions(rng);
        if (t13 == 0 && t12 == 0) {
            kl_native_log("KL retry: libflutter.so loaded but locate FAIL");
            continue; // 继续等（可能部分加载）
        }
        int ok = hook_keylog_funcs(rng, t13, t12);
        if (ok > 0) {
            char buf[128];
            snprintf(buf, sizeof(buf), "KL hook OK (delayed) — keylog 注入成功 (%d/%d)", ok, (t13 ? 1 : 0) + (t12 ? 1 : 0));
            kl_native_log(buf);
            g_hooked.store(true);
            break;
        }
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

    // v2.0.0 hook-revival: Conscrypt JNI 由独立链路安装（NativeProbe.conscryptHookInit），
    //   此处不再重复 install_conscrypt_hook()，避免与 conscrypt_hook.cpp 的独立安装竞争。

    // 立即尝试一次（libflutter.so 已加载场景）
    SoRange rng;
    uintptr_t t13 = 0, t12 = 0;
    locate_keylog_funcs(rng, &t13, &t12);
    // v1.69: dart:io hooks 独立于 keylog 定位——rng.base 有效即 hook
    hook_dart_io_functions(rng);
    if (t13 != 0 || t12 != 0) {
        int ok = hook_keylog_funcs(rng, t13, t12);
        g_in_progress = false;
        if (ok > 0) {
            g_hooked.store(true);
            return JNI_TRUE;
        }
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
