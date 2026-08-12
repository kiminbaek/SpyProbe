#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_fingerprint.py — 验证 flutter_keylog.cpp fingerprint_and_extract 偏移提取逻辑
对标 C++ 修复：ldr x（64位）imm12 是 8 字节对齐缩放值，真实偏移 = imm12 << 3
用法: python3 verify_fingerprint.py <libflutter.so> [ssl_log_secret_vaddr]
默认在样本上自动跑完整定位（锚点交集 + 指纹提取）
"""
import sys, struct

# ---------- ARM64 指令解码（与 C++ 一致） ----------
def is_ldr_x_imm(insn):
    return (insn & 0xFFC00000) == 0xF9400000

def decode_ldr_imm(insn):
    """返回 (rt, rn, imm12)"""
    imm = (insn >> 10) & 0xFFF
    rn = (insn >> 5) & 0x1F
    rt = insn & 0x1F
    return rt, rn, imm

def is_cbz(insn):
    op = insn & 0x7F000000
    return op == 0x34000000 or op == 0x35000000

def is_sub_sp(insn):
    return (insn & 0xFFC003FF) == 0xA98003FF  # 实际是 stp x29,x30,[sp,#-imm]! 待确认

def is_stp_x29x30(insn):
    return (insn & 0xFFC003FF) == 0xA98003FF  # stp x29, x30, [sp, #-imm]!

# ---------- ELF 解析 ----------
def parse_elf(path):
    with open(path, 'rb') as f:
        data = f.read()
    assert data[:4] == b'\x7fELF', 'not ELF'
    is64 = data[4] == 2
    isle = data[5] == 1
    endian = '<' if isle else '>'
    if not is64:
        raise SystemExit('only 64-bit ELF')
    e_shoff = struct.unpack_from(endian + 'Q', data, 0x28)[0]
    e_shentsize = struct.unpack_from(endian + 'H', data, 0x3A)[0]
    e_shnum = struct.unpack_from(endian + 'H', data, 0x3C)[0]
    e_shstrndx = struct.unpack_from(endian + 'H', data, 0x3E)[0]
    shstr_off = struct.unpack_from(endian + 'Q', data, e_shoff + e_shstrndx * e_shentsize + 0x18)[0]
    shstr_size = struct.unpack_from(endian + 'Q', data, e_shoff + e_shstrndx * e_shentsize + 0x20)[0]
    shstr = data[shstr_off:shstr_off + shstr_size]
    sections = {}
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        name_off = struct.unpack_from(endian + 'I', data, off)[0]
        sh_type = struct.unpack_from(endian + 'I', data, off + 0x04)[0]
        flags = struct.unpack_from(endian + 'Q', data, off + 0x08)[0]
        addr = struct.unpack_from(endian + 'Q', data, off + 0x10)[0]
        offset = struct.unpack_from(endian + 'Q', data, off + 0x18)[0]
        size = struct.unpack_from(endian + 'Q', data, off + 0x20)[0]
        name = shstr[name_off:shstr.find(b'\x00', name_off)].decode('utf-8', 'replace')
        sections[name] = dict(type=sh_type, flags=flags, addr=addr, offset=offset, size=size)
    return data, sections

def find_anchor(text_bytes, rodata_start_off, rodata_size, needle):
    """在 rodata 文件字节里找 needle，返回相对 ELF 的虚拟地址（假设段 addr 即 vaddr）"""
    b = needle.encode() + b'\x00'
    idx = text_bytes.find(b, rodata_start_off, rodata_start_off + rodata_size)
    if idx < 0:
        return None
    return idx  # 文件偏移即 vaddr 偏移（此脚本约定 vaddr = 文件偏移）

# ---------- 主验证 ----------
def fingerprint_at(data, cand_off, text_off, text_size, max_insns=250, window=0x800):
    """对标 C++ fingerprint_and_extract：在 cand 起始 window 内找
    ldr x8,[x0,#A] → ldr x8,[x8,#B] → 后 32 条内有 cbz/cbnz"""
    end = min(cand_off + window, text_off + text_size)
    insns = []
    for pc in range(cand_off, end, 4):
        if pc + 4 > len(data):
            break
        insns.append(struct.unpack_from('<I', data, pc)[0])
        if len(insns) >= max_insns:
            break
    n = len(insns)
    for i in range(n - 2):
        if not is_ldr_x_imm(insns[i]):
            continue
        rt1, rn1, imm1 = decode_ldr_imm(insns[i])
        if rn1 != 0 or rt1 != 8:
            continue
        if not is_ldr_x_imm(insns[i + 1]):
            continue
        rt2, rn2, imm2 = decode_ldr_imm(insns[i + 1])
        if rn2 != 8 or rt2 != 8:
            continue
        has_cond = False
        for j in range(i + 2, min(n, i + 35)):
            if is_cbz(insns[j]):
                has_cond = True
                break
        if has_cond:
            return imm1 << 3, imm2 << 3, cand_off + i * 4  # 修复：<<3
    return None

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    path = sys.argv[1]
    data, sections = parse_elf(path)
    text = sections.get('.text')
    rodata = sections.get('.rodata')
    if not text or not rodata:
        raise SystemExit('no .text/.rodata')
    print(f'.text  file_off=0x{text["offset"]:x} size=0x{text["size"]:x}')
    print(f'.rodata file_off=0x{rodata["offset"]:x} size=0x{rodata["size"]:x}')

    if len(sys.argv) >= 3:
        cand = int(sys.argv[2], 0)
        # 约定 vaddr 以 ELF 虚拟地址为准：.text addr 通常非 0，需要 base 修正
        base = text['addr'] - text['offset']  # ELF load base
        cand_off = cand - base
        print(f'cand vaddr=0x{cand:x} → file_off=0x{cand_off:x}')
        r = fingerprint_at(data, cand_off, text['offset'], text['size'])
        if r:
            ctx, cb, at = r
            print(f'FINGERPRINT HIT @0x{at:x}: ctx_off=0x{ctx:x} cb_off=0x{cb:x}')
            print(f'  → 期望（Python 版 91aw 样本）ctx=0x68 cb=0x220')
        else:
            print('NO FINGERPRINT HIT')
        return

    # 完整定位：锚点交集 + 指纹
    anchors = ['CLIENT_RANDOM', 'CLIENT_HANDSHAKE_TRAFFIC_SECRET',
               'SERVER_HANDSHAKE_TRAFFIC_SECRET', 'CLIENT_TRAFFIC_SECRET_0',
               'SERVER_TRAFFIC_SECRET_0']
    found = {}
    for a in anchors:
        idx = find_anchor(data, rodata['offset'], rodata['size'], a)
        print(f'anchor {a}: {hex(idx) if idx else "NOT FOUND"}')
    print('（完整定位需 ADRP 扫描，见 flutter_keylog.cpp locate_ssl_log_secret）')

if __name__ == '__main__':
    main()
