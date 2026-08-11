package com.dustinky.spyprobe;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.TreeMap;

/**
 * v1.52: native TLS 明文 → 结构化 HttpEntry 解析器
 *
 * 背景（用户 2026-08-11 真机日志实证）：
 *   目标 App 视频流量走 ExoPlayer（自带网络栈，不经 OkHttp）→ Java 层 NetProbe 抓不到
 *   [REQ#N] 结构化行 → v1.51 全屏详情页/卡片链路对 ExoPlayer 流量完全失效，用户看到
 *   满屏 native 层文本行（[SpyProbe.Native] [TLS >>>] GET /xxx HTTP/1.1␤...）。
 *   但 native SSL hook 的 TLS 明文里就是完整 HTTP/1.1 报文（方法/URL/头/状态/体）——
 *   把它解析成 HttpEntry，就能复用 v1.48+ 的 HttpStore → 主进程 → HttpRequestCard /
 *   HttpDetailPage 全链路。
 *
 * 解析规则：
 *   - write 方向 = 上行请求，read 方向 = 下行响应（HTTP/1.1 严格一请求一响应）
 *   - 请求行+头完整（\r\n\r\n）→ 建 HttpEntry（rid = LogStore.nextHttpId()）→ HttpStore.add
 *   - 响应行+头完整 → HttpEntry.complete()（status/msg/头/体）
 *   - 请求体取"与头同段到达"的前 {@link #BODY_MAX} 字节；v1.62: 有 Content-Length 时
 *     进入 WAIT_REQ_BODY 态收集分段 body（POST 上传不再丢）
 *   - 响应体取头后前 {@link #BODY_MAX} 字节（.ts 分片可能数百 KB，只留头，防 OOM）
 *   - keep-alive：一条连接顺序产出多个条目（状态机复位等待下一请求）
 *
 * 约束：
 *   - 只解析 HTTP/1.1 明文（HTTP/2 已有 onH2Request/onH2DataChunk 独立链路）
 *   - 单连接累积缓冲上限 {@link #CONN_BUF_MAX}，超限丢弃（防长连接内存膨胀）
 *   - 所有异常吞掉（native 回调绝不能崩目标进程）
 *   - v1.62 P1-6: feed 加 per-conn 锁——write/read 可能不同线程（SSL_write/SSL_read
 *     并发回调），此前"无锁单线程"假设不成立，reqBuf/respBuf 会损坏
 *
 * v1.62 UNKNOWN 判定：连接累积数据达到 {@link #UNKNOWN_BYTES_THRESHOLD} 仍未解析出
 *   任何 HTTP 头（既不是请求也不是响应）→ 判定为非 HTTP 协议（WebSocket 裸帧/DNS over
 *   TLS/自定义二进制协议等）→ isUnknown()=true → NativeProbe 打 [UNKNOWN] 标签，用户能
 *   从日志里看出"抓到了但没分析出来"的数据。
 */
public class TlsHttpParser {

    /** 单连接累积缓冲上限（头未完整时的防护上限） */
    private static final int CONN_BUF_MAX = 256 * 1024;
    /** body 保留上限（m3u8/enkey 足够；.ts 分片只取头） */
    private static final int BODY_MAX = 8 * 1024;
    /** v1.62 P2-23: body 上限可配置（Config.bodyLimit，默认 8KB，可调大看大 JSON/图片 base64） */
    private static final int BODY_MAX_DEFAULT = 8 * 1024;
    /** v1.62 UNKNOWN 判定阈值：累积这么多字节仍无 HTTP 头 → 非 HTTP 协议 */
    private static final long UNKNOWN_BYTES_THRESHOLD = 4 * 1024;

    private enum State { WAIT_REQ_LINE, WAIT_REQ_BODY, WAIT_RESP_LINE, WAIT_RESP_BODY }

    private final long connId; // ssl 指针（NativeProbe 回调的 id）
    // v1.59: 连接四元组（native socketInfo "srcIP:srcPort->dstIP:dstPort" 拆分，可能为空）
    private final String srcAddr;
    private final int srcPort;
    private final String dstAddr;
    private final int dstPort;
    private final ByteArrayOutputStream reqBuf = new ByteArrayOutputStream(1024);
    private final ByteArrayOutputStream respBuf = new ByteArrayOutputStream(1024);
    private State state = State.WAIT_REQ_LINE;

    // v1.61: 请求首字节到达时刻（修复请求耗时恒 0——此前 reqEndMs 被设成 time 同一时刻）
    private long reqStartMs = 0;
    // v1.62 P1-9: 请求体分段收集态字段（POST 上传 body 分段到达不再丢）
    private long reqContentLength = -1;   // 请求头 Content-Length（-1=未知）
    private int reqBodyAcc = 0;           // 已收集请求体字节数
    // v1.61: WAIT_RESP_BODY 态累积状态（响应体字节计数 / 期望长度 / chunked 标记）
    private int respBodyAcc = 0;
    private int respContentLength = -1;
    private boolean respChunked = false;

    /** 当前未完成条目（请求头完整→建，响应头完整→complete 置 null） */
    private HttpEntry current;
    /** 最近完成的条目 id（供日志摘要引用） */
    private long lastRid = -1;
    /** 是否解析出过结构化条目（native 原始 TLS 文本行据此降级为摘要） */
    private boolean everParsed = false;

    // v1.62 UNKNOWN 判定：累积 feed 字节 + 是否已判定非 HTTP
    private long fedBytes = 0;
    private boolean unknown = false;

    public TlsHttpParser(long connId) {
        this(connId, null);
    }

    /** v1.59: 支持携带 socketInfo（连接四元组） */
    public TlsHttpParser(long connId, String socketInfo) {
        this.connId = connId;
        String src = "", dst = "";
        if (socketInfo != null) {
            int arrow = socketInfo.indexOf("->");
            if (arrow >= 0) { src = socketInfo.substring(0, arrow); dst = socketInfo.substring(arrow + 2); }
            else src = socketInfo;
        }
        this.srcAddr = parseAddr(src);
        this.srcPort = parsePort(src);
        this.dstAddr = parseAddr(dst);
        this.dstPort = parsePort(dst);
    }

    private static String parseAddr(String ep) {
        if (ep == null || ep.isEmpty()) return "";
        int colon = ep.lastIndexOf(':');
        return colon > 0 ? ep.substring(0, colon) : ep;
    }

    private static int parsePort(String ep) {
        if (ep == null || ep.isEmpty()) return 0;
        int colon = ep.lastIndexOf(':');
        if (colon < 0 || colon == ep.length() - 1) return 0;
        try { return Integer.parseInt(ep.substring(colon + 1)); } catch (Throwable t) { return 0; }
    }

    // v1.59: TLS 元数据 JSON（native 提取：版本/SNI/ALPN/算法/证书）
    private String tlsMetaJson;

    /** v1.59: native 回调关联 TLS 元数据（建条目时应用） */
    public void setTlsMeta(String json) {
        this.tlsMetaJson = json;
    }

    /** v1.59: 把 TLS 元数据应用到 HttpEntry（TLS 板块 + 证书板块） */
    private void applyTlsMeta(HttpEntry e) {
        if (tlsMetaJson == null || tlsMetaJson.isEmpty()) return;
        try {
            org.json.JSONObject o = new org.json.JSONObject(tlsMetaJson);
            e.setTlsMeta(o.optString("v"), o.optString("sni"), o.optString("alpn"),
                    o.optString("cipher"), o.optString("ciphers"));
            org.json.JSONObject cert = o.optJSONObject("cert");
            if (cert != null) {
                e.setCertMeta(cert.optString("subject"), cert.optString("issuer"), cert.optString("serial"),
                        cert.optString("sha256"), cert.optString("notBefore"), cert.optString("notAfter"));
                // v1.61: 证书 DN 细分字段（小黄鸟式 Subject/Issuer 拆分）
                e.setCertMetaDetailed(
                        cert.optString("subjectCn"), cert.optString("subjectC"), cert.optString("subjectSt"),
                        cert.optString("subjectL"), cert.optString("subjectO"), cert.optString("subjectOu"),
                        cert.optString("issuerCn"), cert.optString("issuerC"), cert.optString("issuerO"));
            }
        } catch (Throwable t) { /* 元数据解析失败不影响主链路 */ }
    }

    public boolean everParsed() { return everParsed; }
    public long lastRid() { return current != null ? current.id : lastRid; }

    /** v1.62: 该连接是否已判定为非 HTTP（UNKNOWN 标签依据） */
    public boolean isUnknown() { return unknown; }

    /** v1.62: 累积字节 + UNKNOWN 判定——既没解析出请求也没解析出响应，累积超阈值即非 HTTP。
     *  注意：连接可能先发不可解析的垃圾（TLS 重协商等）再发 HTTP，但阈值 4KB 足够宽松，
     *  实际误判率极低；判定后 unknown 永久为 true（该连接后续数据都打 UNKNOWN 标签）。 */
    private void noteFed(int len) {
        fedBytes += len;
        if (!unknown && !everParsed && fedBytes >= UNKNOWN_BYTES_THRESHOLD) {
            unknown = true;
        }
    }

    /** 喂一段 TLS 明文（native SSL_read/SSL_write 回调的数据段）
     *  v1.62 P1-6: 整体加 per-conn 锁（write/read 可能不同线程） */
    public synchronized void feed(boolean isWrite, byte[] data, int len) {
        try {
            if (data == null || len <= 0) return;
            noteFed(len);
            if (isWrite) {
                if (state == State.WAIT_REQ_LINE) feedRequest(data, len);
                else if (state == State.WAIT_REQ_BODY) feedRequestBody(data, len);
                else if (state == State.WAIT_RESP_BODY) {
                    // v1.61: keep-alive 复用连接上，新请求开始 = 上一个响应必须已收完
                    //（.ts 分片无 Content-Length 或连接关闭前，靠新请求到来补 complete）
                    completeCurrent(System.currentTimeMillis());
                    feedRequest(data, len);
                }
            } else {
                if (state == State.WAIT_RESP_LINE) feedResponse(data, len);
                else if (state == State.WAIT_RESP_BODY) feedResponseBody(data, len);
            }
        } catch (Throwable ignored) {
            // native 回调绝不能抛异常
        }
    }

    /** v1.61: 连接关闭——补 complete 未完成条目（响应体可能未读完，诚实收尾） */
    public void close() {
        try {
            completeCurrent(System.currentTimeMillis());
        } catch (Throwable ignored) {
        }
    }

    /** v1.61: 收尾当前条目（记录 respEndMs + 更新耗时）；无 current 时仅复位状态
     *  v1.62 P2-12: done 后不再覆盖 durationMs（此前 close 时用 close 时刻重算，
     *  把早已 complete 的条目耗时拉长） */
    private void completeCurrent(long nowMs) {
        HttpEntry e = current;
        if (e != null) {
            if (e.respEndMs == 0) e.respEndMs = nowMs;
            if (!e.done) {
                e.done = true;
                e.durationMs = nowMs - e.time;
                lastRid = e.id;
            }
            current = null;
        }
        respBuf.reset();
        state = State.WAIT_REQ_LINE;
    }

    /** v1.62 P2-23: body 保留上限——Config.bodyLimit（单位 KB）可调大（默认 2KB），
     *  但不低于硬编码 8KB 默认（防用户调小后正文截断更狠）；UI 调大才能看到大 JSON 全文 */
    private static int bodyMax() {
        try {
            int v = Config.get().bodyLimit;
            if (v > 0 && v <= 1024) {
                int bytes = v * 1024;
                return Math.max(BODY_MAX_DEFAULT, bytes);
            }
        } catch (Throwable t) { }
        return BODY_MAX_DEFAULT;
    }

    /** 上行：累积请求字节，请求头完整时建条目 */
    private void feedRequest(byte[] data, int len) {
        // v1.61: 请求首字节到达时刻（reqBuf 空 = 本请求第一个包）
        if (reqBuf.size() == 0) reqStartMs = System.currentTimeMillis();
        reqBuf.write(data, 0, len);
        if (reqBuf.size() > CONN_BUF_MAX) { resetReq(); return; }
        byte[] buf = reqBuf.toByteArray();
        int[] headEnd = findHeadEnd(buf);
        if (headEnd == null) return; // 头未完整
        int headEndPos = headEnd[0];
        int delimLen = headEnd[1];

        // 请求体：只取与头同段到达的字节（GET 场景无体；POST body 后续经 feedRequestBody 收）
        int bodyLen = buf.length - (headEndPos + delimLen);
        String body = "";
        if (bodyLen > 0) {
            int n = Math.min(bodyLen, bodyMax());
            body = new String(buf, headEndPos + delimLen, n, StandardCharsets.UTF_8);
        }

        String head = new String(buf, 0, headEndPos, StandardCharsets.UTF_8);
        String[] lines = head.split("\\r?\\n");
        if (lines.length == 0 || lines[0].isEmpty()) { resetReq(); return; }
        String[] parts = lines[0].split(" ");
        if (parts.length < 2) { resetReq(); return; } // 不是 HTTP 请求行，丢弃

        String m = parts[0];
        if (!m.matches("[A-Z]+")) { resetReq(); return; } // 防二进制误判
        String target = parts[1];
        // v1.59: 请求行第 3 段 = 协议（HTTP/1.1 / HTTP/1.0）
        String proto = parts.length >= 3 ? parts[2] : "HTTP/1.1";

        // 请求头
        Map<String, String> reqHdrs = new TreeMap<>();
        for (int i = 1; i < lines.length; i++) {
            int c = lines[i].indexOf(':');
            if (c > 0) {
                reqHdrs.put(lines[i].substring(0, c).trim(), lines[i].substring(c + 1).trim());
            }
        }
        // v1.62 P1-7: URL scheme 硬编码 http:// → https://（TLS 明文解析器处理的必然是 HTTPS）
        //  URL 补全：请求行可能是 path（GET /api/x HTTP/1.1），拼 Host 头
        String fullUrl = target;
        if (!target.startsWith("http")) {
            String host = reqHdrs.get("Host");
            fullUrl = (host != null && !host.isEmpty()) ? "https://" + host + target : target;
        }

        long rid = LogStore.get().nextHttpId(); // v1.62 P1-10: 独立 httpId（防并发撞 id）
        long nowMs = System.currentTimeMillis();
        String logLine = "[REQ#" + rid + "] >>> " + m + " " + fullUrl;
        // v1.61: time = 请求首字节到达时刻（此前=请求头完整时刻 → 请求耗时恒 0）
        long entryTime = reqStartMs > 0 ? reqStartMs : nowMs;
        HttpEntry e = new HttpEntry("TLS", rid, entryTime,
                Thread.currentThread().getName(),
                m, fullUrl, reqHdrs,
                HttpEntry.sniffBodyType(reqHdrs.get("Content-Type"), body), body, bodyLen,
                "", logLine);
        // v1.59: 协议 + 请求头发送完成时刻 + 流ID + 连接四元组 + TLS 元数据/证书
        // v1.61: reqEndMs = 请求头完整时刻（请求耗时 = reqEndMs - time = 真实发送耗时）
        e.setConnMeta(proto, nowMs, 0, connId, 0, srcAddr, srcPort, dstAddr, dstPort);
        applyTlsMeta(e);
        current = e;
        everParsed = true;
        HttpStore.get().add(e);
        // 文本流保留 [REQ#N] 行（UI 卡片命中依赖）+ 供用户回看
        LogStore.get().log(NativeProbe.TAG, logLine);

        // v1.62 P1-9: 请求体分段收集——有 Content-Length 且未收完 → 进 WAIT_REQ_BODY 态
        //   （POST 上传/JSON body 分段到达的场景，body 不再丢）
        String cl = reqHdrs.get("Content-Length");
        long contentLength = -1;
        if (cl != null && !cl.trim().isEmpty()) {
            try { contentLength = Long.parseLong(cl.trim()); } catch (Throwable t) { contentLength = -1; }
        }
        reqBuf.reset();
        if (contentLength > bodyLen && contentLength <= CONN_BUF_MAX) {
            reqContentLength = contentLength;
            reqBodyAcc = bodyLen;
            state = State.WAIT_REQ_BODY;
        } else {
            reqContentLength = -1;
            reqBodyAcc = 0;
            state = State.WAIT_RESP_LINE;
        }
    }

    /** v1.62 P1-9: 上行请求体分段收集（有 Content-Length 时）——收集到完整后转 WAIT_RESP_LINE */
    private void feedRequestBody(byte[] data, int len) {
        HttpEntry e = current;
        if (e == null) { resetReq(); return; }
        reqBodyAcc += len;
        e.reqBodyBytes = reqBodyAcc;
        if (e.reqBody.length() < bodyMax()) {
            int need = bodyMax() - e.reqBody.length();
            int n = Math.min(len, need);
            try { e.reqBody = e.reqBody + new String(data, 0, n, StandardCharsets.UTF_8); } catch (Throwable t) { }
        }
        if (reqBodyAcc >= reqContentLength) {
            reqContentLength = -1;
            reqBodyAcc = 0;
            state = State.WAIT_RESP_LINE;
        }
    }

    /** 下行：累积响应字节，响应头完整时解析；body 未收完 → WAIT_RESP_BODY 继续计数 */
    private void feedResponse(byte[] data, int len) {
        // v1.61: 响应首字节到达时刻（真实，非头完整时刻）
        if (current != null && current.respStartMs == 0 && respBuf.size() == 0) {
            current.respStartMs = System.currentTimeMillis();
        }
        respBuf.write(data, 0, len);
        if (respBuf.size() > CONN_BUF_MAX) { resetResp(); return; }
        byte[] buf = respBuf.toByteArray();
        int[] headEnd = findHeadEnd(buf);
        if (headEnd == null) return; // 头未完整
        int headEndPos = headEnd[0];
        int delimLen = headEnd[1];

        String head = new String(buf, 0, headEndPos, StandardCharsets.UTF_8);
        String[] lines = head.split("\\r?\\n");
        int status = 0;
        String statusMsg = "";
        Map<String, String> respHdrs = new TreeMap<>();
        if (lines.length > 0 && lines[0].startsWith("HTTP/")) {
            String[] parts = lines[0].split(" ", 3);
            if (parts.length >= 2) {
                try { status = Integer.parseInt(parts[1]); } catch (Throwable t) { status = 0; }
            }
            if (parts.length >= 3) statusMsg = parts[2];
        }
        // v1.62 P1-8: 1xx 响应（100 Continue / 103 Early Hints）是中间响应——
        //   不能 complete 当前条目，否则真实 200 到达时 current=null → 响应丢失。
        //   跳过：清掉该段缓冲（1xx 通常无 body），继续等真实响应。
        if (status >= 100 && status < 200) {
            respBuf.reset();
            return;
        }
        for (int i = 1; i < lines.length; i++) {
            int c = lines[i].indexOf(':');
            if (c > 0) {
                respHdrs.put(lines[i].substring(0, c).trim(), lines[i].substring(c + 1).trim());
            }
        }

        // 响应体：头后同段字节（内容只留前 BODY_MAX；字节数全算——v1.61 修复 0B）
        int bodyInHead = buf.length - (headEndPos + delimLen);
        String body = "";
        if (bodyInHead > 0) {
            int n = Math.min(bodyInHead, bodyMax());
            body = new String(buf, headEndPos + delimLen, n, StandardCharsets.UTF_8);
        }

        HttpEntry e = current;
        if (e != null) {
            long nowMs = System.currentTimeMillis();
            // 流ID/四元组补全
            if (e.connId == 0) e.connId = connId;
            if (e.srcAddr.isEmpty()) e.srcAddr = srcAddr;
            if (e.srcPort == 0) e.srcPort = srcPort;
            if (e.dstAddr.isEmpty()) e.dstAddr = dstAddr;
            if (e.dstPort == 0) e.dstPort = dstPort;
            lastRid = e.id;
            LogStore.get().log(NativeProbe.TAG, "[REQ#" + e.id + "] <<< " + status + " " + statusMsg);

            // v1.61: 响应体长度策略（Content-Length / chunked / 未知）
            String te = respHdrs.get("Transfer-Encoding");
            String cl = respHdrs.get("Content-Length");
            boolean chunked = te != null && te.toLowerCase().contains("chunked");
            int contentLength = -1;
            if (!chunked && cl != null) {
                try { contentLength = Integer.parseInt(cl.trim()); } catch (Throwable t) { contentLength = -1; }
            }
            respChunked = chunked;
            respContentLength = contentLength;
            respBodyAcc = bodyInHead;
            e.respBodyBytes = bodyInHead;

            String bodyType = HttpEntry.sniffBodyType(respHdrs.get("Content-Type"), body);
            if (chunked) {
                // chunked：进入 WAIT_RESP_BODY 找结束标记
                e.setResponseHead(status, statusMsg, respHdrs, bodyType, body);
                state = State.WAIT_RESP_BODY;
            } else if (contentLength >= 0 && bodyInHead >= contentLength) {
                // body 已完整
                e.complete(status, statusMsg, respHdrs, bodyType, body, contentLength, nowMs - e.time);
                e.respEndMs = nowMs;
                finishResp();
            } else if (contentLength >= 0) {
                // body 未完：持续计数直到 Content-Length
                e.setResponseHead(status, statusMsg, respHdrs, bodyType, body);
                state = State.WAIT_RESP_BODY;
            } else {
                // 无 Content-Length（close-delimited / HTTP/1.0）：未知长度，
                // 按同段收尾（保持原行为），连接关闭时 close() 兜底
                e.complete(status, statusMsg, respHdrs, bodyType, body, bodyInHead, nowMs - e.time);
                e.respEndMs = nowMs;
                finishResp();
            }
        } else {
            finishResp();
        }
        respBuf.reset();
    }

    /** v1.61: WAIT_RESP_BODY 态——只计数 body 字节（不存内容防 OOM），直到完整/结束标记 */
    private void feedResponseBody(byte[] data, int len) {
        HttpEntry e = current;
        if (e == null) { finishResp(); return; }
        long nowMs = System.currentTimeMillis();
        respBodyAcc += len;
        e.respBodyBytes = respBodyAcc;
        if (respChunked) {
            // chunked 结束标记：最后 chunk "0\r\n\r\n"
            if (findChunkedEnd(data, len)) {
                e.complete(e.status, e.statusMsg, e.respHeaders, e.respBodyType,
                        e.respBody, respBodyAcc, nowMs - e.time);
                e.respEndMs = nowMs;
                finishResp();
            }
        } else if (respContentLength >= 0 && respBodyAcc >= respContentLength) {
            e.complete(e.status, e.statusMsg, e.respHeaders, e.respBodyType,
                    e.respBody, respContentLength, nowMs - e.time);
            e.respEndMs = nowMs;
            finishResp();
        }
        // respContentLength < 0（close-delimited）：等连接关闭 close() 兜底
    }

    /** v1.61: chunked 结束标记检测（"0\r\n\r\n"，容忍 trailing） */
    private static boolean findChunkedEnd(byte[] data, int len) {
        for (int i = 0; i + 4 < len; i++) {
            if (data[i] == '0' && data[i + 1] == '\r' && data[i + 2] == '\n'
                    && data[i + 3] == '\r' && data[i + 4] == '\n') {
                return true;
            }
        }
        return false;
    }

    /** v1.61: 收尾复位（current 已 complete 或丢弃） */
    private void finishResp() {
        respBuf.reset();
        respBodyAcc = 0;
        respContentLength = -1;
        respChunked = false;
        current = null;
        state = State.WAIT_REQ_LINE;
    }

    /** 找头结束位置（\r\n\r\n 优先，\n\n 容错）；返回 [pos, delimLen] 或 null */
    private static int[] findHeadEnd(byte[] buf) {
        for (int i = 0; i + 3 < buf.length; i++) {
            if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
                return new int[]{i, 4};
            }
        }
        for (int i = 0; i + 1 < buf.length; i++) {
            if (buf[i] == '\n' && buf[i + 1] == '\n') {
                return new int[]{i, 2};
            }
        }
        return null;
    }

    private void resetReq() {
        reqBuf.reset();
        reqContentLength = -1;
        reqBodyAcc = 0;
        state = State.WAIT_REQ_LINE;
    }
    private void resetResp() {
        respBuf.reset();
        respBodyAcc = 0;
        respContentLength = -1;
        respChunked = false;
        current = null;
        reqContentLength = -1;
        reqBodyAcc = 0;
        state = State.WAIT_REQ_LINE;
    }
}
