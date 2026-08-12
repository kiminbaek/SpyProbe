// locator_test.cpp — Linux ELF 版定位器验证（与 flutter_keylog.cpp 同算法）
// 用法: g++ -O2 -o locator_test locator_test.cpp && ./locator_test <libflutter.so>
// 输出: ssl_log_secret 文件偏移 + ctx_off + cb_off（应与 Python auto_locate6.py 一致）
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>
#include <set>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>

// ====== 指令解码（与 flutter_keylog.cpp 一致） ======
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
static bool decode_add_imm(uint32_t insn, int *rd, int *rn, uint32_t *imm) {
    if ((insn & 0xFFC00000u) != 0x91000000u) return false;
    *imm = (insn >> 10) & 0xFFFu;
    *rn = (int)((insn >> 5) & 0x1F);
    *rd = (int)(insn & 0x1F);
    return true;
}
static bool decode_bl_b(uint32_t insn, uintptr_t pc, uintptr_t *target) {
    uint32_t op = insn & 0xFC000000u;
    if (op != 0x94000000u && op != 0x14000000u) return false;
    int64_t imm26 = (int64_t)(insn & 0x03FFFFFFu);
    if (imm26 & (1 << 25)) imm26 -= (1 << 26);
    *target = pc + (uintptr_t)(imm26 << 2);
    return true;
}
static bool is_sub_sp(uint32_t insn) {
    return (insn & 0xFFC003FFu) == 0xD10003FFu;
}
static bool is_stp_x29x30_pre(uint32_t insn) {
    return (insn & 0xFFC003FFu) == 0xA98003FFu;
}
static bool decode_ldr_imm(uint32_t insn, int *rt, int *rn, uint32_t *imm) {
    if ((insn & 0xFFC00000u) != 0xF9400000u) return false;
    *imm = (insn >> 10) & 0xFFFu;
    *rn = (int)((insn >> 5) & 0x1F);
    *rt = (int)(insn & 0x1F);
    return true;
}
static bool is_cbz(uint32_t insn) {
    uint32_t op = insn & 0x7F000000u;
    return op == 0x34000000u || op == 0x35000000u;
}
static bool is_blr(uint32_t insn) {
    return (insn & 0xFFFFFC1Fu) == 0xD63F0000u;
}

// ====== ELF 段提取 ======
struct Seg {
    uint8_t *data;
    size_t size;
    uintptr_t vaddr;
};

static bool extract_seg(const char *path, const char *seg_name, Seg &out) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open"); return false; }
    struct stat st; fstat(fd, &st);
    uint8_t *base = (uint8_t *)mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED) { perror("mmap"); return false; }

    Elf64_Ehdr *eh = (Elf64_Ehdr *)base;
    if (memcmp(eh->e_ident, ELFMAG, 4) != 0) { fprintf(stderr, "not ELF64\n"); return false; }
    Elf64_Shdr *sh = (Elf64_Shdr *)(base + eh->e_shoff);
    const char *shstr = (const char *)(base + sh[eh->e_shstrndx].sh_offset);
    for (int i = 0; i < eh->e_shnum; i++) {
        const char *name = shstr + sh[i].sh_name;
        if (strcmp(name, seg_name) == 0) {
            out.data = base + sh[i].sh_offset;
            out.size = sh[i].sh_size;
            out.vaddr = sh[i].sh_addr;
            return true;
        }
    }
    fprintf(stderr, "segment %s not found\n", seg_name);
    return false;
}

static uintptr_t find_anchor(const Seg &rod, const char *needle) {
    size_t nlen = strlen(needle) + 1;
    for (size_t i = 0; i + nlen <= rod.size; i++) {
        if (rod.data[i] == needle[0] && memcmp(rod.data + i, needle, nlen) == 0) {
            return rod.vaddr + i;
        }
    }
    return 0;
}

static void scan_adrp_add_refs(const Seg &text, uintptr_t anchor, std::vector<uintptr_t> &refs) {
    const uint32_t *code = (const uint32_t *)text.data;
    size_t n = text.size / 4;
    struct Adrp { uintptr_t addr; int rd; uintptr_t page; };
    Adrp recent[64];
    int recent_n = 0;
    for (size_t i = 0; i < n; i++) {
        uintptr_t pc = text.vaddr + i * 4;
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
                    if (recent[k].page + add_imm == anchor) refs.push_back(pc);
                    break;
                }
            }
        }
    }
}

static uintptr_t find_func_head(const Seg &text, uintptr_t ref_addr) {
    const uint32_t *code = (const uint32_t *)text.data;
    uintptr_t start = ref_addr > 0x400 ? ref_addr - 0x400 : text.vaddr;
    uintptr_t head = 0;
    for (uintptr_t pc = start; pc < ref_addr; pc += 4) {
        uint32_t insn = code[(pc - text.vaddr) / 4];
        if (is_sub_sp(insn) || is_stp_x29x30_pre(insn)) head = pc;
    }
    return head;
}

static bool is_mov_imm(uint32_t insn) {
    return (insn & 0xFF800000u) == 0xD2800000u
        || (insn & 0xFF800000u) == 0x92800000u
        || (insn & 0xFF800000u) == 0xF2800000u;
}
static bool is_mov_reg(uint32_t insn) {
    // capstone 的 mov 别名覆盖 ORR/ADD 多种变体，手动 mask 易漏。
    // 务实方案：只要下一条是 b 就当作 thunk 展开（指纹精筛会过滤误展开）。
    return true;
}

static void collect_callees(const Seg &text, uintptr_t head, std::set<uintptr_t> &out) {
    const uint32_t *code = (const uint32_t *)text.data;
    uintptr_t end = head + 0x800;
    uintptr_t text_end = text.vaddr + text.size;
    if (end > text_end) end = text_end;
    std::vector<uintptr_t> direct;
    for (uintptr_t pc = head; pc < end; pc += 4) {
        uint32_t insn = code[(pc - text.vaddr) / 4];
        uintptr_t tgt;
        if (decode_bl_b(insn, pc, &tgt)) {
            direct.push_back(tgt);
            out.insert(tgt);
        }
    }
    for (uintptr_t t : direct) {
        if (t + 8 > text_end || t < text.vaddr) continue;
        uint32_t i0 = code[(t - text.vaddr) / 4];
        uint32_t i1 = code[(t - text.vaddr) / 4 + 1];
        // 第 1 条不是 b/bl（避免把 b 链误当 thunk），第 2 条是 b → 展开
        uintptr_t t2;
        if (!decode_bl_b(i0, t, &t2) && decode_bl_b(i1, t + 4, &t2)) out.insert(t2);
    }
}

static bool fingerprint_and_extract(const Seg &text, uintptr_t cand, uintptr_t *ctx_off, uintptr_t *cb_off) {
    const uint32_t *code = (const uint32_t *)text.data;
    uintptr_t text_end = text.vaddr + text.size;
    uintptr_t end = cand + 0x800;
    if (end > text_end) end = text_end;
    std::vector<uint32_t> insns;
    for (uintptr_t pc = cand; pc < end && insns.size() < 250; pc += 4) {
        insns.push_back(code[(pc - text.vaddr) / 4]);
    }
    int n = (int)insns.size();
    for (int i = 0; i < n - 2; i++) {
        int rt1, rn1, rt2, rn2;
        uint32_t imm1, imm2;
        if (!decode_ldr_imm(insns[i], &rt1, &rn1, &imm1)) continue;
        if (rn1 != 0 || rt1 != 8) continue;
        if (!decode_ldr_imm(insns[i + 1], &rt2, &rn2, &imm2)) continue;
        if (rn2 != 8 || rt2 != 8) continue;
        bool has_cond = false;
        for (int j = i + 2; j < n && j <= i + 34; j++) {
            if (is_cbz(insns[j])) { has_cond = true; break; }
        }
        if (has_cond) {
            // 关键：ldr x（64位）imm12 是 8 字节对齐缩放值，真实偏移 = imm12 << 3
            *ctx_off = imm1 << 3;
            *cb_off = imm2 << 3;
            return true;
        }
    }
    return false;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <libflutter.so>\n", argv[0]); return 1; }
    Seg text, rod;
    if (!extract_seg(argv[1], ".text", text)) return 1;
    if (!extract_seg(argv[1], ".rodata", rod)) return 1;
    printf("[*] .text 0x%lx+%zu .rodata 0x%lx+%zu\n",
           (unsigned long)text.vaddr, text.size, (unsigned long)rod.vaddr, rod.size);

    static const char *ANCHORS[] = {
        "CLIENT_RANDOM",
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        "CLIENT_TRAFFIC_SECRET_0",
        "SERVER_TRAFFIC_SECRET_0",
    };
    std::set<uintptr_t> common;
    bool first = true;
    for (int a = 0; a < 5; a++) {
        uintptr_t anchor = find_anchor(rod, ANCHORS[a]);
        if (!anchor) { printf("[!] anchor[%d] %s NOT FOUND\n", a, ANCHORS[a]); continue; }
        std::vector<uintptr_t> refs;
        scan_adrp_add_refs(text, anchor, refs);
        std::set<uintptr_t> heads;
        for (uintptr_t r : refs) {
            uintptr_t h = find_func_head(text, r);
            if (h) heads.insert(h);
        }
        std::set<uintptr_t> callees;
        for (uintptr_t h : heads) collect_callees(text, h, callees);
        printf("[*] %s: refs=%zu heads=%zu callees=%zu\n", ANCHORS[a], refs.size(), heads.size(), callees.size());
        if (first) { common = callees; first = false; }
        else {
            std::set<uintptr_t> inter;
            for (uintptr_t c : common) if (callees.count(c)) inter.insert(c);
            common = inter;
        }
        if (common.empty()) break;
    }
    printf("[*] intersection=%zu\n", common.size());
    for (uintptr_t c : common) {
        uintptr_t co, cbo;
        if (fingerprint_and_extract(text, c, &co, &cbo)) {
            printf("[+] ssl_log_secret = 0x%lx (offset 0x%lx) ctx_off=0x%lx cb_off=0x%lx\n",
                   (unsigned long)c, (unsigned long)(c - text.vaddr), (unsigned long)co, (unsigned long)cbo);
            return 0;
        }
    }
    printf("[-] no fingerprint match\n");
    return 1;
}
