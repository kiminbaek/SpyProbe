package com.dustinky.spyprobe;

/**
 * v7x: MITM 透明代理 native 辅助（SO_ORIGINAL_DST）
 *
 * iptables REDIRECT 后 accept 的 socket 已改写目标为 127.0.0.1:port，
 * 真实目标地址只能通过 getsockopt(fd, SOL_IP, SO_ORIGINAL_DST) 拿。
 * 返回 "ip:port"（IPv4）；非 REDIRECT 连接返回 null（调用方 fallback SNI DNS）。
 */
public class MitmSock {

    static {
        System.loadLibrary("native_hook");
    }

    public static native String getOriginalDst(int fd);
}
