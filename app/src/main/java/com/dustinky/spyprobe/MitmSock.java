package com.dustinky.spyprobe;

/**
 * v7x: MITM 透明代理 native 辅助（SO_ORIGINAL_DST）
 *
 * iptables REDIRECT 后 accept 的 socket 已改写目标为 127.0.0.1:port，
 * 真实目标地址只能通过 getsockopt(fd, SOL_IP, SO_ORIGINAL_DST) 拿。
 * 返回 "ip:port"（IPv4）；非 REDIRECT 连接返回 null（调用方 fallback SNI DNS）。
 */

// v8x: MITM 透明代理方案已终止（2026-08-14 用户拍板：代理开关致手机卡死/升温 + 真机连续失败）。
//   保留代码（不删）供查；抓 dart:io/Flutter 改走 TUN 接管（TunController/PacketLoop）。
@Deprecated
public class MitmSock {

    static {
        System.loadLibrary("native_hook");
    }

    public static native String getOriginalDst(int fd);
}
