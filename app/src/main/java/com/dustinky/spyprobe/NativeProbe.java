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
    // v1.47 P2-12: 诊断计数改 AtomicInteger——多 native 线程并发 ++ 竞态（仅诊断留痕，低频无害但修正成本低）
    private static final java.util.concurrent.atomic.AtomicInteger diagPcapCount = new java.util.concurrent.atomic.AtomicInteger(0);  // v1.45.1 低频诊断

    /** 单次数据最大记录长度（超长截断，防刷爆 4096 环形缓冲） */
    private static final int MAX_TEXT = 2048;
    // v1.35 P1-2: hex 展示上限 256→64（大块非文本流量只留摘要，见 toReadable）
    private static final int MAX_HEX = 64;
    // v1.35 P1-2: 超过此字节的非文本数据不再展开 hex，只记 "[N B hex]" 摘要
    private static final int HEX_DUMP_MAX = 128;

    /** v1.35 P0-1b: 推送通道自排除——127.0.0.1:9900 是 SpyProbe 自己家日志推送端口，
     *  native send/recv 会捕获到推送 socket 数据（含全部历史日志的 JSON），必须跳过，
     *  否则推送体被当日志记录 → 递归爆炸（上次日志 944 条 9900 记录）。
     *  v1.51.2: 扩展为自家端点识别——9900-9910 回环端口（9900 数据面 + 9901 控制面 ping），
     *  src/dst 两端都查（双保险：native 层已过滤，Java 层兜底）。 */
    private static boolean isSelfInternal(String socketInfo) {
        if (socketInfo == null) return false;
        int arrow = socketInfo.indexOf("->");
        String src = (arrow >= 0) ? socketInfo.substring(0, arrow) : socketInfo;
        String dst = (arrow >= 0) ? socketInfo.substring(arrow + 2) : socketInfo;
        return isSelfEndpoint(src) || isSelfEndpoint(dst);
    }
    private static boolean isSelfEndpoint(String ep) {
        if (ep == null) return false;
        int colon = ep.lastIndexOf(':');
        if (colon < 0) return false;
        String ip = ep.substring(0, colon);
        if (!(ip.startsWith("127.") || ip.startsWith("::ffff:127.") || ip.startsWith("[::1]") || ip.startsWith("::1"))) return false;
        try {
            int port = Integer.parseInt(ep.substring(colon + 1));
            return port >= 9900 && port <= 9910;
        } catch (Throwable t) {
            return false;
        }
    }

    // v1.52: native TLS 明文 → 结构化 HttpEntry（ExoPlayer/Flutter 等不走 OkHttp 的流量）
    //  per-连接（ssl 指针）一个解析器；连接关闭时移除；超过上限清空兜底防膨胀
    private static final java.util.Map<Long, TlsHttpParser> tlsParsers = new java.util.HashMap<>();
    private static final int MAX_TLS_PARSERS = 64;

    // v1.59: 记录每个连接的 socketInfo（首次出现时记下，供 TlsHttpParser 建条目时带四元组）
    private static final java.util.Map<Long, String> tlsConnSock = new java.util.HashMap<>();

    // v1.59: native TLS 元数据（版本/SNI/ALPN/算法/证书 JSON）——per-conn 缓存，TlsHttpParser 建条目时关联
    private static final java.util.Map<Long, String> tlsMetaMap = new java.util.HashMap<>();

    /** native→Java：TLS 元数据回调（JSON 字符串，见 native_hook.cpp build_tls_meta_json） */
    @SuppressWarnings("unused")
    private static void onTlsMeta(long connId, String metaJson) {
        if (metaJson == null || metaJson.isEmpty()) return;
        synchronized (tlsMetaMap) {
            if (tlsMetaMap.size() > 128) tlsMetaMap.clear(); // 防膨胀
            tlsMetaMap.put(connId, metaJson);
        }
    }

    /** v1.59: 取连接 TLS 元数据并清理（TlsHttpParser 消费一次） */
    private static String takeTlsMeta(long connId) {
        synchronized (tlsMetaMap) {
            return tlsMetaMap.remove(connId);
        }
    }

    private static void tlsHttpFeed(long connId, boolean isWrite, byte[] data) {
        tlsHttpFeed(connId, isWrite, data, null);
    }

    /** v1.59: 携带 socketInfo（native onNativeData 已有四元组）+ TLS 元数据关联 */
    private static void tlsHttpFeed(long connId, boolean isWrite, byte[] data, String socketInfo) {
        if (data == null || data.length == 0) return;
        TlsHttpParser p;
        synchronized (tlsParsers) {
            if (socketInfo != null && !socketInfo.isEmpty()) {
                tlsConnSock.put(connId, socketInfo);
            } else {
                String cached = tlsConnSock.get(connId);
                if (cached != null) socketInfo = cached;
            }
            String meta = takeTlsMeta(connId);
            p = tlsParsers.get(connId);
            if (p == null) {
                if (tlsParsers.size() >= MAX_TLS_PARSERS) tlsParsers.clear(); // 极端场景兜底
                p = new TlsHttpParser(connId, socketInfo);
                tlsParsers.put(connId, p);
            }
            if (meta != null && !meta.isEmpty()) {
                p.setTlsMeta(meta);
            }
        }
        p.feed(isWrite, data, data.length);
    }

    private static boolean tlsHasStructured(long connId) {
        synchronized (tlsParsers) {
            TlsHttpParser p = tlsParsers.get(connId);
            return p != null && p.everParsed();
        }
    }

    /** v1.62【用户需求】: 该连接是否已判定为非 HTTP（抓到了但没分析出来）→ 日志打 UNKNOWN 标签 */
    private static boolean tlsIsUnknown(long connId) {
        synchronized (tlsParsers) {
            TlsHttpParser p = tlsParsers.get(connId);
            return p != null && p.isUnknown();
        }
    }

    private static long tlsLastRid(long connId) {
        synchronized (tlsParsers) {
            TlsHttpParser p = tlsParsers.get(connId);
            return p != null ? p.lastRid() : -1;
        }
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
        // v1.41 P0: pcap 独立于 nativeCapture——只开 pcap 导出时也装 native hook（pcap 数据源=native SSL hook）
        if (!Config.get().nativeCapture && !Config.get().pcapCapture) {
            DebugLog.get().logNoMirror("Native", "native hook skipped: nativeCapture=false && pcapCapture=false");
            return;
        }
        DebugLog.get().logNoMirror("Native", "native hook init: nativeCapture=" + Config.get().nativeCapture + " pcapCapture=" + Config.get().pcapCapture);
        try {
            System.loadLibrary("native_hook");
            // v1.31.2 P0-1: initNativeHook 改为返回 boolean——v1.31.1 及以前无脑置 inited=true，
            // shadowhook_init ret=12 失败时仍打印 "native hook active"，误导排查。现在失败即返回 false。
            boolean ok = initNativeHook(true);
            if (ok) {
                inited = true;
                DebugLog.get().logNoMirror("Native", "native hook active: libc send/recv/read/write + SSL_write/SSL_read (4 libs) + HTTP/2");
            } else {
                DebugLog.get().logNoMirror("Native", "native hook init FAILED (shadowhook_init ret!=0) -> hooks disabled, active=false");
                // v1.43: 删除 v1.31.2 的 shadowhook_tag root 抓取——v1.34 已把 shadowhook 换成 xhook，
                //   xhook 不打 shadowhook_tag 这个 logcat tag，该分支永远无输出，属死代码。
            }
        } catch (Throwable t) {
            DebugLog.get().logNoMirror("Native", "native hook init fail: " + t);
        }
    }

    public static boolean isActive() { return inited; }

    // ================= JNI native 方法（与 native_hook.cpp 对应）=================

    private static native boolean initNativeHook(boolean enableNativeHook);
    // v1.25 P2-10: 删除 feedH2Data/freeH2Conn 死代码（Java 声明 + C++ 实现从未被调用，
    //   native 层 HTTP/2 数据回调走 onH2DataChunk/onH2Request，Java→native 方向无调用者）

    // ================= 静态回调（native → Java，全部写 LogStore，不拦截）=================

    /** v1.30.4: native→Java 日志桥——shadowhook_init/hook 结果。
     *  v1.52.1: 归调试日志（自家运行日志不进抓包日志页；DebugLog 三保险可读） */
    @SuppressWarnings("unused")
    private static void nativeLog(String msg) {
        if (msg != null && !msg.isEmpty()) {
            DebugLog.get().logNoMirror("Native", "[native] " + msg);
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
            if (buf == null) return false;
            // v1.35 P0-1b: 跳过自身日志推送 + v1.51.2: 自家控制面 9901 ping（回环 9900-9910 全跳）
            if (isSelfInternal(socketInfo)) return false;
            // v1.45.1 诊断：每 200 次留痕一次——确认 onNativeData 在跑 / isSsl / pcapCapture 值
            if ((diagPcapCount.incrementAndGet() % 200) == 1) {
                try { DebugLog.get().logNoMirror("PcapFeed", "onNativeData ssl=" + isSsl + " pcap=" + Config.get().pcapCapture + " info=" + (socketInfo != null ? socketInfo : "null")); } catch (Throwable ig) { }
            }
            // v1.41 P0: pcap 独立于 nativeCapture——只开 pcap 导出时也采集 TLS 明文（pcap 数据源=native SSL hook）
            // v1.39 P0: pcap 导出——TLS 明文完整喂 PcapWriter（独立 duplicate 读取，不影响日志读取）
            if (isSsl && Config.get().pcapCapture) {
                try {
                    ByteBuffer dup = buf.duplicate();
                    int pcapTotal = dup.remaining();
                    int pcapN = Math.min(pcapTotal, 65536); // 单条上限 64KB（大块流量只留前段）
                    byte[] pcapData = new byte[pcapN];
                    dup.get(pcapData);
                    PcapWriter.get().feed(id, isWrite, pcapData, socketInfo);
                } catch (Throwable ignored) {
                }
            }
            // v1.41 P0: native 日志记录仍受 nativeCapture 控制（pcap 已在上方独立采集）
            if (!Config.get().nativeCapture) return false;

            // v1.52: TLS 明文 → 结构化 HttpEntry 解析（独立 duplicate 读全部，不影响下方展示读取）
            if (isSsl) {
                try {
                    ByteBuffer dup = buf.duplicate();
                    int tlsN = dup.remaining();
                    if (tlsN > 0) {
                        byte[] tlsData = new byte[tlsN];
                        dup.get(tlsData);
                        tlsHttpFeed(id, isWrite, tlsData, socketInfo);
                    }
                } catch (Throwable ignored) {
                }
            }

            String dir = isWrite ? ">>>" : "<<<";
            // v1.62【用户需求】: 未知协议标签——TLS 明文没解析出 HTTP（非 HTTP 协议：
            //   WebSocket 裸帧/DNS over TLS/自定义二进制等）→ [UNKNOWN] 标签，方便用户识别
            //   "抓到了但没分析出来"的数据。TCP 明文保持 TCP 标签（TCP 层不解析协议）。
            boolean unknownProto = isSsl && tlsIsUnknown(id);
            String proto = unknownProto ? "UNKNOWN" : (isSsl ? "TLS" : "TCP");
            String loc = (socketInfo != null && !socketInfo.isEmpty()) ? socketInfo : ("#" + id);

            // v1.52.1【用户 2026-08-11 拍板：抓包日志页 = 目标 App 数据，不是 SpyProbe 自己的日志】
            // 该连接 TLS 明文已被结构化解析（HttpEntry 已进 HttpStore，UI 卡片数据源独立于日志流）
            //   → 不再写任何摘要行。v1.52 的 "[TLS → REQ#N]" 摘要行在视频分片场景每块数据都刷一行，
            //     用户 1911 行日志里 619 行是这个噪音 → 删除（数据完整性不受影响，HttpEntry 全链路独立）。
            if (isSsl && tlsHasStructured(id)) {
                return false;
            }
            // v1.62: 已判定 UNKNOWN 的连接——首次判定打一行说明，之后只打 UNKNOWN 摘要
            //   （TlsHttpParser 已判定非 HTTP，后续数据不再喂解析器，这里直接打 UNKNOWN 标签行）
            //   unknown 连接同样跳过 pcap 之外的重复：数据本身无结构，标签行已说明"未知协议"

            // v1.25 P1-6: 部分拷贝——大块传输（文件/视频）时 buf.remaining() 可达数 MB，
            // 全量拷贝 + toReadable 扫描会分配大数组/遍历，高频下 OOM 风险；只拷贝展示上限并记录总长
            int total = buf.remaining();
            int n = Math.min(total, MAX_TEXT);
            byte[] data = new byte[n];
            buf.get(data);
            // v1.52.1: SSL 密文大块（TCP 层 443 端口的视频/图片二进制）不写日志——明文已由
            //   SSL hook + TlsHttpParser 结构化；密文 hex 摘要对用户零价值（此前 684 行刷屏）。
            //   保留：可读文本明文（HTTP 明文、DNS 响应等）+ 小包（<=HEX_DUMP_MAX，握手帧有诊断价值）
            if (!isSsl && total > HEX_DUMP_MAX && !isPrintable(data)) {
                return false;
            }
            // v1.54 P1: TLS 不可读帧（握手帧 ClientHello/ServerHello、密文块）零价值 → 过滤。
            //   v1.52.1 只拦了"已结构化"的连接；握手帧在结构化之前到达（isSsl 且不可打印）→
            //   v1.53 日志 3 行 "[TLS >>> ...] [126B hex] 1603..." 就是这个。可读明文（非 HTTP 的
            //   TLS 明文协议，如 DNS over TLS）仍保留摘要，不丢失诊断信息。
            if (isSsl && !isPrintable(data)) {
                return false;
            }
            LogStore.get().log(TAG, "[" + proto + " " + dir + " " + loc + (total > n ? " " + total + "B" : "") + "] " + toReadable(data, total));
            if (stack != null && !stack.isEmpty()) {
                // v1.16 P2-6: 只对小包记录调用栈（大块传输高频刷屏；短包=握手/协议帧，栈有诊断价值）
                // v1.39 P1: SSL 明文也记录（native 调用栈标注明文来源 so/函数），同样限小包
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
            // v1.58: H2 请求/响应结构化（此前纯文本）——元数据进 HttpEntry，UI 渲染 REQ# 卡片
            long key = h2Key(connId, streamId);
            if (!isResponse) {
                long rid = LogStore.get().nextHttpId(); // v1.62 P1-10: 独立 httpId
                String url = scheme + "://" + authority + path;
                String line = "[REQ#" + rid + "] >>> " + method + " " + url;
                if (reqHdr != null && !reqHdr.isEmpty()) {
                    line += "\n    " + reqHdr.replace("\n", "\n    ");
                }
                LogStore.get().log(TAG, line);
                HttpEntry he = new HttpEntry("H2", rid, System.currentTimeMillis(),
                        Thread.currentThread().getName(), method, url,
                        parseH2Headers(reqHdr), "none", "", 0,
                        StackUtil.getCompact(6), line);
                // v1.59: H2 协议/流ID/时间点
                long nowMs = System.currentTimeMillis();
                he.setConnMeta("HTTP/2", nowMs, 0, connId, streamId, "", 0, "", 0);
                H2_ENTRIES.put(key, he);
                if (H2_ENTRIES.size() > 256) {
                    // 防膨胀：极端情况下清空（最多丢几个未完成流，防内存泄漏优先）
                    H2_ENTRIES.clear();
                }
            } else {
                HttpEntry he = H2_ENTRIES.remove(key);
                String line;
                if (he != null) {
                    line = "[REQ#" + he.id + "] <<< " + statusCode + " " + path;
                    if (respHdr != null && !respHdr.isEmpty()) {
                        line += "\n    " + respHdr.replace("\n", "\n    ");
                    }
                    LogStore.get().log(TAG, line);
                    // v1.59: 响应头开始时刻（近似）
                    if (he.respStartMs == 0) he.respStartMs = System.currentTimeMillis();
                    // v1.62 P0: complete 时保留 onH2DataChunk 已追加的 body（此前传 "" 清空详情页 body）
                    he.complete(statusCode, "", parseH2Headers(respHdr),
                            HttpEntry.sniffBodyType(he.respHeaders.get("Content-Type"), he.respBody),
                            he.respBody, he.respBodyBytes, 0);
                    HttpStore.get().add(he);
                } else {
                    // 请求元数据没捕获到（先见响应）——轻量条目
                    long rid = LogStore.get().nextHttpId(); // v1.62 P1-10: 独立 httpId
                    line = "[REQ#" + rid + "] <<< " + statusCode + " " + path;
                    if (respHdr != null && !respHdr.isEmpty()) {
                        line += "\n    " + respHdr.replace("\n", "\n    ");
                    }
                    LogStore.get().log(TAG, line);
                    HttpEntry he2 = new HttpEntry("H2", rid, System.currentTimeMillis(),
                            Thread.currentThread().getName(), "", path,
                            new java.util.TreeMap<>(), "none", "", 0,
                            StackUtil.getCompact(6), line);
                    he2.complete(statusCode, "", parseH2Headers(respHdr), "text", "", 0, 0);
                    HttpStore.get().add(he2);
                }
            }
        } catch (Throwable ignored) {
        }
        return false; // 探测模式：不拦截
    }

    /** v1.58: H2 流 key（connId 高位移开 + streamId 低 20 位） */
    private static long h2Key(long connId, int streamId) {
        return (connId << 20) ^ (streamId & 0xFFFFF);
    }

    /** v1.58: H2 头块 "Key: value\n..." → TreeMap */
    private static java.util.Map<String, String> parseH2Headers(String hdr) {
        java.util.Map<String, String> out = new java.util.TreeMap<>();
        if (hdr == null) return out;
        try {
            for (String l : hdr.split("\n")) {
                int c = l.indexOf(':');
                if (c > 0) out.put(l.substring(0, c).trim(), l.substring(c + 1).trim());
            }
        } catch (Throwable t) { }
        return out;
    }

    /** H2 流状态（未完成请求 → HttpEntry），onH2Request/onH2DataChunk 共用 */
    private static final java.util.concurrent.ConcurrentHashMap<Long, HttpEntry> H2_ENTRIES =
            new java.util.concurrent.ConcurrentHashMap<>();

    /** HTTP/2 body 数据块（isRequest=true 上行 body）
     *  v1.62 P0: body 追加进 HttpEntry（此前只打文本日志，详情页 H2 body 全空） */
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
            // v1.62 P0: 追加到结构化条目（详情页 body 完整）
            long key = h2Key(connId, streamId);
            HttpEntry he = H2_ENTRIES.get(key);
            if (he != null) {
                String chunk = HttpEntry.printableChunk(data, n);
                if (isRequest) he.appendReqBody(chunk);
                else he.appendRespBody(chunk);
            }
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
            // v1.52: TLS 连接关闭 → 清理 per-连接 HTTP 解析器（防泄漏）
            // v1.61: 先 close() 收尾未完成条目（响应体可能没读完，诚实记录 respEndMs）
            if (isSsl) {
                synchronized (tlsParsers) {
                    TlsHttpParser p = tlsParsers.get(id);
                    if (p != null) {
                        try { p.close(); } catch (Throwable ignored) { }
                    }
                    tlsParsers.remove(id);
                    tlsConnSock.remove(id); // v1.59: 同步清理四元组缓存
                }
            }
            // v1.41 P0: pcap 独立于 nativeCapture——只开 pcap 时连接关闭也要 flush 会话
            // v1.39 P0: TLS 连接关闭 → pcap 会话记录推主进程
            if (isSsl && Config.get().pcapCapture) {
                try {
                    PcapWriter.get().onConnClosed(id);
                } catch (Throwable ignored) {
                }
            }
            // v1.41 P0: 连接关闭日志记录仍受 nativeCapture 控制（pcap 已在上方独立处理）
            if (!Config.get().nativeCapture) return;
            // v1.52.1: 连接关闭是 SpyProbe 自己的运行状态，不是目标 App 抓包数据 → 归调试日志
            //   （用户拍板：日志页 = 目标 App 数据；自家运行日志走 DebugLog）
            DebugLog.get().logNoMirror("Native", "[conn closed " + (isSsl ? "TLS" : "TCP") + " #" + id + "]");
        } catch (Throwable ignored) {
        }
    }

    // ================= 工具 =================

    /** v1.52.1: 是否为可打印文本（前 256 字节无 NUL/控制字符）——用于过滤 SSL 密文大块 */
    private static boolean isPrintable(byte[] data) {
        if (data == null || data.length == 0) return false;
        for (int i = 0; i < data.length && i < 256; i++) {
            byte b = data[i];
            if (b == 0) return false;
            if (b < 0x09 || (b > 0x0d && b < 0x20)) return false;
        }
        return true;
    }

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
