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
 *   - 请求行+头完整（\r\n\r\n）→ 建 HttpEntry（rid = LogStore.nextSeq()）→ HttpStore.add
 *   - 响应行+头完整 → HttpEntry.complete()（status/msg/头/体）
 *   - 请求体取"与头同段到达"的前 {@link #BODY_MAX} 字节（GET 场景无体；POST 若 body 分段
 *     到达则丢弃——视频站场景全 GET，可接受）
 *   - 响应体取头后前 {@link #BODY_MAX} 字节（.ts 分片可能数百 KB，只留头，防 OOM）
 *   - keep-alive：一条连接顺序产出多个条目（状态机复位等待下一请求）
 *
 * 约束：
 *   - 只解析 HTTP/1.1 明文（HTTP/2 已有 onH2Request/onH2DataChunk 独立链路）
 *   - 单连接累积缓冲上限 {@link #CONN_BUF_MAX}，超限丢弃（防长连接内存膨胀）
 *   - 所有异常吞掉（native 回调绝不能崩目标进程）
 *   - 无锁单线程调用（NativeProbe 侧持有 per-连接实例，不同连接不共享）
 */
public class TlsHttpParser {

    /** 单连接累积缓冲上限（头未完整时的防护上限） */
    private static final int CONN_BUF_MAX = 256 * 1024;
    /** body 保留上限（m3u8/enkey 足够；.ts 分片只取头） */
    private static final int BODY_MAX = 8 * 1024;

    private enum State { WAIT_REQ_LINE, WAIT_RESP_LINE }

    private final long connId; // ssl 指针（NativeProbe 回调的 id）
    private final ByteArrayOutputStream reqBuf = new ByteArrayOutputStream(1024);
    private final ByteArrayOutputStream respBuf = new ByteArrayOutputStream(1024);
    private State state = State.WAIT_REQ_LINE;

    /** 当前未完成条目（请求头完整→建，响应头完整→complete 置 null） */
    private HttpEntry current;
    /** 最近完成的条目 id（供日志摘要引用） */
    private long lastRid = -1;
    /** 是否解析出过结构化条目（native 原始 TLS 文本行据此降级为摘要） */
    private boolean everParsed = false;

    public TlsHttpParser(long connId) {
        this.connId = connId;
    }

    public boolean everParsed() { return everParsed; }
    public long lastRid() { return current != null ? current.id : lastRid; }

    /** 喂一段 TLS 明文（native SSL_read/SSL_write 回调的数据段） */
    public void feed(boolean isWrite, byte[] data, int len) {
        try {
            if (data == null || len <= 0) return;
            if (isWrite) {
                if (state == State.WAIT_REQ_LINE) feedRequest(data, len);
            } else {
                if (state == State.WAIT_RESP_LINE && current != null) feedResponse(data, len);
            }
        } catch (Throwable ignored) {
            // native 回调绝不能抛异常
        }
    }

    /** 上行：累积请求字节，请求头完整时建条目 */
    private void feedRequest(byte[] data, int len) {
        reqBuf.write(data, 0, len);
        if (reqBuf.size() > CONN_BUF_MAX) { resetReq(); return; }
        byte[] buf = reqBuf.toByteArray();
        int[] headEnd = findHeadEnd(buf);
        if (headEnd == null) return; // 头未完整
        int headEndPos = headEnd[0];
        int delimLen = headEnd[1];

        // 请求体：只取与头同段到达的字节（GET 场景无体）
        int bodyLen = buf.length - (headEndPos + delimLen);
        String body = "";
        if (bodyLen > 0) {
            int n = Math.min(bodyLen, BODY_MAX);
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

        // 请求头
        Map<String, String> reqHdrs = new TreeMap<>();
        for (int i = 1; i < lines.length; i++) {
            int c = lines[i].indexOf(':');
            if (c > 0) {
                reqHdrs.put(lines[i].substring(0, c).trim(), lines[i].substring(c + 1).trim());
            }
        }
        // URL 补全：请求行可能是 path（GET /api/x HTTP/1.1），拼 Host 头
        String fullUrl = target;
        if (!target.startsWith("http")) {
            String host = reqHdrs.get("Host");
            fullUrl = (host != null && !host.isEmpty()) ? "http://" + host + target : target;
        }

        long rid = LogStore.get().nextSeq();
        String logLine = "[REQ#" + rid + "] >>> " + m + " " + fullUrl;
        HttpEntry e = new HttpEntry("TLS", rid, System.currentTimeMillis(),
                Thread.currentThread().getName(),
                m, fullUrl, reqHdrs,
                HttpEntry.sniffBodyType(reqHdrs.get("Content-Type"), body), body, bodyLen,
                "", logLine);
        current = e;
        everParsed = true;
        HttpStore.get().add(e);
        // 文本流保留 [REQ#N] 行（UI 卡片命中依赖）+ 供用户回看
        LogStore.get().log(NativeProbe.TAG, logLine);

        reqBuf.reset();
        state = State.WAIT_RESP_LINE;
    }

    /** 下行：累积响应字节，响应头完整时 complete 条目 */
    private void feedResponse(byte[] data, int len) {
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
        for (int i = 1; i < lines.length; i++) {
            int c = lines[i].indexOf(':');
            if (c > 0) {
                respHdrs.put(lines[i].substring(0, c).trim(), lines[i].substring(c + 1).trim());
            }
        }

        // 响应体：头后前 BODY_MAX 字节（.ts 大分片只留头）
        int bodyLen = buf.length - (headEndPos + delimLen);
        String body = "";
        if (bodyLen > 0) {
            int n = Math.min(bodyLen, BODY_MAX);
            body = new String(buf, headEndPos + delimLen, n, StandardCharsets.UTF_8);
        }

        HttpEntry e = current;
        if (e != null) {
            long dur = System.currentTimeMillis() - e.time;
            e.complete(status, statusMsg, respHdrs,
                    HttpEntry.sniffBodyType(respHdrs.get("Content-Type"), body), body, bodyLen, dur);
            lastRid = e.id;
            LogStore.get().log(NativeProbe.TAG, "[REQ#" + e.id + "] <<< " + status + " " + statusMsg);
        }

        respBuf.reset();
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

    private void resetReq() { reqBuf.reset(); state = State.WAIT_REQ_LINE; }
    private void resetResp() { respBuf.reset(); current = null; state = State.WAIT_REQ_LINE; }
}
