package com.dustinky.spyprobe;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * Native 层抓包（v1.10）
 *
 * 桥接 C++ native_hook（shadowhook inline hook）：
 *   - libc.so: send/recv/sendto/recvfrom/write/read/close  → TCP 明文
 *   - libssl.so / libconscrypt_jni.so / libttboringssl.so / libflutter.so:
 *       SSL_write/SSL_read/SSL_free (+ NativeCrypto_ 变体) → TLS 解密明文
 *   - HTTP/2 帧解析（nghttp2）：onH2Request / onH2DataChunk
 *
 * 探测模式：全部记录到 LogStore，不拦截任何请求（onNativeData 等返回 false）。
 * 覆盖 Java 层 NetProbe 的盲区：Flutter/Unity 等纯 native 网络栈。
 *
 * JNI 函数名必须与 native_hook.cpp 中 Java_com_dustinky_spyprobe_NativeProbe_* 一致。
 */
public class NativeProbe {

    static final String TAG = "SpyProbe.Native";

    /** 单次数据最大记录长度（超长截断，防刷爆 4096 环形缓冲） */
    private static final int MAX_TEXT = 2048;
    private static final int MAX_HEX = 256;

    private static volatile boolean inited = false;

    /** 由 ModuleMain 调用：加载 native 库并启用 hook */
    public static synchronized void init() {
        if (inited) return;
        try {
            System.loadLibrary("native_hook");
            initNativeHook(true);
            inited = true;
            LogStore.get().log(TAG, "native hook active: libc send/recv/read/write + SSL_write/SSL_read (4 libs) + HTTP/2");
        } catch (Throwable t) {
            LogStore.get().log(TAG, "native hook init fail: " + t);
        }
    }

    public static boolean isActive() { return inited; }

    // ================= JNI native 方法（与 native_hook.cpp 对应）=================

    private static native void initNativeHook(boolean enableNativeHook);
    private static native int feedH2Data(long connId, boolean isLocal, byte[] data, int offset, int length, boolean collectRespBody);
    private static native void freeH2Conn(long connId);

    // ================= 静态回调（native → Java，全部写 LogStore，不拦截）=================

    /** libc / SSL 数据：id=socket fd 或 ssl 指针；isWrite=true 上行；isSsl=true TLS 解密明文 */
    @SuppressWarnings("unused")
    private static boolean onNativeData(long id, boolean isWrite, ByteBuffer buf, String socketInfo, String stack, boolean isSsl) {
        try {
            // v1.15 P0-4: native 抓包开关（高频刷屏可关；关时不做任何记录/解析，只放行）
            if (!Config.get().nativeCapture) return false;
            if (buf == null) return false;
            String dir = isWrite ? ">>>" : "<<<";
            String proto = isSsl ? "TLS" : "TCP";
            String loc = (socketInfo != null && !socketInfo.isEmpty()) ? socketInfo : ("#" + id);
            byte[] data = new byte[buf.remaining()];
            buf.get(data);
            LogStore.get().log(TAG, "[" + proto + " " + dir + " " + loc + "] " + toReadable(data));
            if (stack != null && !stack.isEmpty()) {
                LogStore.get().log(TAG, stack);
            }
        } catch (Throwable ignored) {
            // native 回调绝不能抛异常（会崩目标进程）
        }
        return false; // 探测模式：不拦截
    }

    /** HTTP/2 请求元数据（method/path/headers/status）；isResponse=true 时 respHdr/statusCode 有效 */
    @SuppressWarnings("unused")
    private static boolean onH2Request(long connId, int streamId, String method, String path,
                                       String authority, String scheme, String reqHdr, String respHdr,
                                       int statusCode, boolean isResponse) {
        try {
            // v1.15 P0-4: native 抓包开关
            if (!Config.get().nativeCapture) return false;
            if (!isResponse) {
                LogStore.get().log(TAG, "[H2 REQ #" + streamId + "] " + method + " " + scheme + "://" + authority + path);
                if (reqHdr != null && !reqHdr.isEmpty()) {
                    LogStore.get().log(TAG, "[H2 REQ-HDR] " + reqHdr.replace("\n", " | "));
                }
            } else {
                LogStore.get().log(TAG, "[H2 RESP #" + streamId + "] " + statusCode + " " + path);
                if (respHdr != null && !respHdr.isEmpty()) {
                    LogStore.get().log(TAG, "[H2 RESP-HDR] " + respHdr.replace("\n", " | "));
                }
            }
        } catch (Throwable ignored) {
        }
        return false; // 探测模式：不拦截
    }

    /** HTTP/2 body 数据块（isRequest=true 上行 body） */
    @SuppressWarnings("unused")
    private static void onH2DataChunk(long connId, int streamId, boolean isRequest, ByteBuffer buf) {
        try {
            // v1.15 P0-4: native 抓包开关
            if (!Config.get().nativeCapture) return;
            if (buf == null) return;
            byte[] data = new byte[buf.remaining()];
            buf.get(data);
            String dir = isRequest ? ">>>" : "<<<";
            LogStore.get().log(TAG, "[H2 DATA " + dir + " #" + streamId + "] " + toReadable(data));
        } catch (Throwable ignored) {
        }
    }

    /** 是否收集响应体（H2 用）——SpyProbe 探测模式：收集 */
    @SuppressWarnings("unused")
    private static boolean getCollectResponseBody() {
        return true;
    }

    /** 连接关闭（id=socket fd 或 ssl 指针） */
    @SuppressWarnings("unused")
    private static void onConnectionClosed(long id, boolean isSsl) {
        try {
            // v1.15 P0-4: native 抓包开关
            if (!Config.get().nativeCapture) return;
            LogStore.get().log(TAG, "[conn closed " + (isSsl ? "TLS" : "TCP") + " #" + id + "]");
        } catch (Throwable ignored) {
        }
    }

    // ================= 工具 =================

    /** 可打印文本直接展示（截断），否则 hex 摘要 */
    private static String toReadable(byte[] data) {
        if (data == null || data.length == 0) return "(empty)";
        boolean printable = true;
        for (int i = 0; i < data.length && i < 256; i++) {
            byte b = data[i];
            if (b == 0) { printable = false; break; }
            if (b < 0x09 || (b > 0x0d && b < 0x20)) { printable = false; break; }
        }
        if (printable) {
            String s = new String(data, StandardCharsets.UTF_8).trim();
            if (s.length() > MAX_TEXT) s = s.substring(0, MAX_TEXT) + "...(" + data.length + "B)";
            return s;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("[").append(data.length).append("B hex] ");
        for (int i = 0; i < data.length && i < MAX_HEX; i++) {
            sb.append(String.format("%02x", data[i]));
            if ((i & 1) == 1) sb.append(' ');
        }
        if (data.length > MAX_HEX) sb.append("...");
        return sb.toString();
    }
}
