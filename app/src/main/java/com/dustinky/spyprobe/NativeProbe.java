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
    // v1.35 P1-2: hex 展示上限 256→64（大块非文本流量只留摘要，见 toReadable）
    private static final int MAX_HEX = 64;
    // v1.35 P1-2: 超过此字节的非文本数据不再展开 hex，只记 "[N B hex]" 摘要
    private static final int HEX_DUMP_MAX = 128;

    /** v1.35 P0-1b: 推送通道自排除——127.0.0.1:9900 是 SpyProbe 自己家日志推送端口，
     *  native send/recv 会捕获到推送 socket 数据（含全部历史日志的 JSON），必须跳过，
     *  否则推送体被当日志记录 → 递归爆炸（上次日志 944 条 9900 记录）。 */
    private static boolean isSelfPush(String socketInfo) {
        if (socketInfo == null) return false;
        return socketInfo.startsWith("127.0.0.1:9900")
                || socketInfo.startsWith("::ffff:127.0.0.1:9900")
                || socketInfo.startsWith("[::1]:9900")
                || socketInfo.startsWith("::1:9900");
    }

    private static volatile boolean inited = false;

    /** 由 ModuleMain 调用：加载 native 库并启用 hook */
    public static synchronized void init() {
        if (inited) return;
        // v1.31.5 P0-1: native 开关语义修正——native=false 时不装任何 native hook。
        // 背景：inline hook 直接改写 libc 函数机器码，只要装着就在影响目标 App（性能+崩溃风险）。
        //   此前 init() 无条件执行、开关只控制"是否记录"，用户关 native 后 shadowhook 照样
        //   inline hook libc 高频函数 → 91暗网(Flutter) 进主界面闪退、且关了 native 也闪退。
        // 现在：native=false 时跳过整个 native 层（不 loadLibrary 不 hook），Java 层抓包不受影响。
        if (!Config.get().nativeCapture) {
            LogStore.get().log(TAG, "native hook skipped: nativeCapture=false (native 层不装 hook；Java 层 SSL 绕过/OkHttp 等照常，重启目标 App 后生效)");
            return;
        }
        try {
            System.loadLibrary("native_hook");
            // v1.31.2 P0-1: initNativeHook 改为返回 boolean——v1.31.1 及以前无脑置 inited=true，
            // shadowhook_init ret=12 失败时仍打印 "native hook active"，误导排查。现在失败即返回 false。
            boolean ok = initNativeHook(true);
            if (ok) {
                inited = true;
                LogStore.get().log(TAG, "native hook active: libc send/recv/read/write + SSL_write/SSL_read (4 libs) + HTTP/2");
            } else {
                LogStore.get().log(TAG, "native hook init FAILED (shadowhook_init ret!=0) -> hooks disabled, active=false");
                // v1.31.2: 失败时尝试用 root 抓 shadowhook_tag（shadowhook 内部日志在系统 logcat，
                // LogStore 只能看到 native_log 桥的输出，看不到 shadowhook 库内部打印）——写入 LogStore 方便导出
                try {
                    if (com.dustinky.spyprobe.util.RootLogReader.INSTANCE.checkRoot()) {
                        String sh = com.dustinky.spyprobe.util.RootLogReader.INSTANCE.captureShadowHookLog();
                        if (sh != null && !sh.trim().isEmpty()) {
                            LogStore.get().log(TAG, "--- shadowhook_tag (logcat, root 抓取) ---");
                            for (String line : sh.split("\n")) {
                                if (!line.trim().isEmpty()) LogStore.get().log(TAG, line.trim());
                            }
                        } else {
                            LogStore.get().log(TAG, "shadowhook_tag logcat 无输出（shadowhook 未打印或缓冲已滚出）");
                        }
                    } else {
                        LogStore.get().log(TAG, "无 root 权限，未抓 shadowhook_tag；可在 root shell 执行: logcat -d -s shadowhook_tag:*");
                    }
                } catch (Throwable t2) {
                    LogStore.get().log(TAG, "shadowhook_tag 抓取异常: " + t2);
                }
            }
        } catch (Throwable t) {
            LogStore.get().log(TAG, "native hook init fail: " + t);
        }
    }

    public static boolean isActive() { return inited; }

    // ================= JNI native 方法（与 native_hook.cpp 对应）=================

    private static native boolean initNativeHook(boolean enableNativeHook);
    // v1.25 P2-10: 删除 feedH2Data/freeH2Conn 死代码（Java 声明 + C++ 实现从未被调用，
    //   native 层 HTTP/2 数据回调走 onH2DataChunk/onH2Request，Java→native 方向无调用者）

    // ================= 静态回调（native → Java，全部写 LogStore，不拦截）=================

    /** v1.30.4: native→Java 日志桥——shadowhook_init/hook 结果可见于 LogStore（任意 native 线程调用） */
    @SuppressWarnings("unused")
    private static void nativeLog(String msg) {
        if (msg != null && !msg.isEmpty()) {
            LogStore.get().log(TAG, "[native] " + msg);
        }
    }

    /**
     * v1.38 P0-3: native SSL keylog 回调（hooker ssl_log.js 借鉴）
     *
     * BoringSSL SSL_CTX_set_keylog_callback 输出：`CLIENT_RANDOM <64hex> <96hex master_secret>`
     * 配合抓包（native hex 或外部 pcap）可还原 TLS 会话明文——Wireshark 直接导入 keylog 文件。
     * 开关 Config.keylogCapture（默认关，防刷屏：每次 TLS 握手 1 行）。
     */
    @SuppressWarnings("unused")
    private static void nativeKeylog(String line) {
        try {
            if (!Config.get().keylogCapture) return;
            if (line != null && !line.isEmpty()) {
                LogStore.get().log(TAG, "[KeyLog] " + line);
            }
        } catch (Throwable ignored) {
        }
    }

    /** libc / SSL 数据：id=socket fd 或 ssl 指针；isWrite=true 上行；isSsl=true TLS 解密明文 */
    @SuppressWarnings("unused")
    private static boolean onNativeData(long id, boolean isWrite, ByteBuffer buf, String socketInfo, String stack, boolean isSsl) {
        try {
            // v1.15 P0-4: native 抓包开关（高频刷屏可关；关时不做任何记录/解析，只放行）
            if (!Config.get().nativeCapture) return false;
            if (buf == null) return false;
            // v1.35 P0-1b: 跳过自身日志推送（127.0.0.1:9900），根治递归污染
            if (isSelfPush(socketInfo)) return false;
            String dir = isWrite ? ">>>" : "<<<";
            String proto = isSsl ? "TLS" : "TCP";
            String loc = (socketInfo != null && !socketInfo.isEmpty()) ? socketInfo : ("#" + id);
            // v1.25 P1-6: 部分拷贝——大块传输（文件/视频）时 buf.remaining() 可达数 MB，
            // 全量拷贝 + toReadable 扫描会分配大数组/遍历，高频下 OOM 风险；只拷贝展示上限并记录总长
            int total = buf.remaining();
            int n = Math.min(total, MAX_TEXT);
            byte[] data = new byte[n];
            buf.get(data);
            LogStore.get().log(TAG, "[" + proto + " " + dir + " " + loc + (total > n ? " " + total + "B" : "") + "] " + toReadable(data, total));
            if (stack != null && !stack.isEmpty()) {
                // v1.16 P2-6: 只对小包记录调用栈（大块传输高频刷屏；短包=握手/协议帧，栈有诊断价值）
                if (data.length <= 64) {
                    LogStore.get().log(TAG, stack);
                }
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
            // v1.25 P1-6: 部分拷贝防 OOM（同 onNativeData）
            int total = buf.remaining();
            int n = Math.min(total, MAX_TEXT);
            byte[] data = new byte[n];
            buf.get(data);
            String dir = isRequest ? ">>>" : "<<<";
            LogStore.get().log(TAG, "[H2 DATA " + dir + " #" + streamId + (total > n ? " " + total + "B" : "") + "] " + toReadable(data, total));
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

    /** 可打印文本直接展示（截断），否则 hex 摘要；total=原始总字节（>data.length 时用于显示实际大小）
     *  v1.35 P1-2: 非文本且 > HEX_DUMP_MAX 字节 → 只记 "[N B hex]" 摘要不再展开（视频/图片流量刷屏根治） */
    private static String toReadable(byte[] data, int total) {
        if (data == null || data.length == 0) return "(empty)";
        boolean printable = true;
        for (int i = 0; i < data.length && i < 256; i++) {
            byte b = data[i];
            if (b == 0) { printable = false; break; }
            if (b < 0x09 || (b > 0x0d && b < 0x20)) { printable = false; break; }
        }
        if (printable) {
            String s = new String(data, StandardCharsets.UTF_8).trim();
            if (s.length() > MAX_TEXT) s = s.substring(0, MAX_TEXT) + "...(" + total + "B)";
            return s;
        }
        if (total > HEX_DUMP_MAX) {
            return "[" + total + "B hex] (非文本大块，hex 省略)";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("[").append(total).append("B hex] ");
        for (int i = 0; i < data.length && i < MAX_HEX; i++) {
            sb.append(String.format("%02x", data[i]));
            if ((i & 1) == 1) sb.append(' ');
        }
        if (total > MAX_HEX) sb.append("...");
        return sb.toString();
    }
}
