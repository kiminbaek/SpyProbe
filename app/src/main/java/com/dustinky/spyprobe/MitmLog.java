package com.dustinky.spyprobe;

/**
 * v7x: MITM 模块公共日志通道
 *  - Android 主进程：setSink → UiLog（落 files/spyprobe_debug.log + logcat）
 *  - NAS 冒烟：setSink → stdout
 *  - 未 setSink 时静默（MITM 模块绝不因日志崩）
 */

// v8x: MITM 透明代理方案已终止（2026-08-14 用户拍板：代理开关致手机卡死/升温 + 真机连续失败）。
//   保留代码（不删）供查；抓 dart:io/Flutter 改走 TUN 接管（TunController/PacketLoop）。
@Deprecated
public class MitmLog {

    public interface Sink {
        void log(String msg);
    }

    private static volatile Sink sink;

    public static void setSink(Sink s) {
        sink = s;
    }

    public static void log(String msg) {
        Sink s = sink;
        if (s != null) {
            try { s.log(msg); } catch (Throwable ignored) {}
        }
    }
}
