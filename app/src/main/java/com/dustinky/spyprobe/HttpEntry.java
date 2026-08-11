package com.dustinky.spyprobe;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.Map;
import java.util.TreeMap;

/**
 * v1.48: 结构化 HTTP 请求/响应条目（小黄鸟式详情页数据源）
 *
 * 在 NetProbe 捕获 OkHttp / HttpURLConnection 请求时构建，替代"纯文本行"——
 * 每条请求一个完整对象：method / url / query / headers / body / status / respHeaders /
 * respBody / 耗时 / 发起线程 / 调用栈。
 *
 * 文本日志行照旧保留（兼容导出/老逻辑）；HttpEntry 单独存环形缓冲 + 推送主进程落盘，
 * UI 点请求行时优先展示结构化详情（HttpDetailScreen）。
 *
 * 设计约束：
 *   - body 按 Config.bodyLimit 截断（与文本行同源，防 OOM / 防推送体过大）
 *   - headers 统一 TreeMap（大小写不敏感排序展示）
 *   - 序列化为 JSON（推送主进程 / 落盘 http_entries/ 复用）
 */
public class HttpEntry {

    public static final String TAG = "SpyProbe.Http";

    /** 请求类型：OKHTTP / URL_CONN */
    public final String source;

    /** 与日志行 [REQ#N] 对应的 id（可点击日志行跳详情） */
    public final long id;

    /** 毫秒时间戳 */
    public final long time;

    /** 发起线程名 */
    public final String thread;

    public final String method;
    public final String url;

    /** query 参数（解析自 url 的 ? 部分，k→v 有序） */
    public final Map<String, String> query;

    /** 请求头（原始顺序，TreeMap 排序） */
    public final Map<String, String> reqHeaders;

    /** v1.62 P1-11: final → volatile（多源 merge 时 body 类型可被 TLS 层补全） */
    public volatile String reqBodyType;
    /** v1.62 P0: final → volatile（H2 请求 body 需流式追加） */
    public volatile String reqBody;
    public volatile int reqBodyBytes;

    /** 响应（未完成时 status=0） */
    public volatile int status;
    public volatile String statusMsg;
    public final Map<String, String> respHeaders;
    public volatile String respBodyType;
    public volatile String respBody;
    public volatile int respBodyBytes;

    /** 耗时毫秒（请求开始 → 响应完成） */
    public volatile long durationMs;

    /** 调用栈摘要（hook 层独有，定位谁发的请求） */
    public final String stack;

    /** 是否已收到响应（用于 UI 区分进行中/完成） */
    public volatile boolean done;

    /** 文本日志行（保留原始行，方便回看/导出） */
    public final String logLine;

    // ===== v1.59: 总览页对齐小黄鸟——元数据扩展（协议/时间点/流ID/连接四元组/TLS/证书）=====

    /** 协议：TLS 解析器从请求行拿真实值（HTTP/1.1 / HTTP/2）；OKHTTP 默认 HTTP/1.1 */
    public volatile String protocol = "HTTP/1.1";

    /** 请求开始时刻（毫秒）= 首字节到达；0=未知 */
    public volatile long reqStartMs = 0;
    /** 请求头发送完成时刻（毫秒）；0=未知 */
    public volatile long reqEndMs = 0;
    /** 响应头开始到达时刻（毫秒）；0=未知 */
    public volatile long respStartMs = 0;
    /** 响应体读完/连接关闭时刻（毫秒）；0=未知（v1.61 新增，修复响应耗时恒 0） */
    public volatile long respEndMs = 0;

    /** 连接 id（native ssl 指针 / H2 connId），流 #N 展示用；0=未知 */
    public volatile long connId = 0;
    /** HTTP/2 stream id；0=未知 */
    public volatile int streamId = 0;

    /** 连接四元组（native socketInfo 格式 srcIP:srcPort->dstIP:dstPort 拆分） */
    public volatile String srcAddr = "";
    public volatile int srcPort = 0;
    public volatile String dstAddr = "";
    public volatile int dstPort = 0;

    /** TLS 元数据（C 级 native 回调） */
    public volatile String tlsVersion = "";
    public volatile String sni = "";
    public volatile String alpn = "";
    public volatile String cipherSelected = "";
    public volatile String cipherList = "";

    /** 服务端证书（D 级 native 回调） */
    public volatile String certSubject = "";
    public volatile String certIssuer = "";
    public volatile String certSerial = "";
    public volatile String certSha256 = "";
    public volatile String certNotBefore = "";
    public volatile String certNotAfter = "";
    // v1.61: 证书 DN 细分字段（小黄鸟式 Subject/Issuer 拆 CN/国家/省/地区/组织/单位）
    public volatile String certSubjectCn = "";
    public volatile String certSubjectC = "";
    public volatile String certSubjectSt = "";
    public volatile String certSubjectL = "";
    public volatile String certSubjectO = "";
    public volatile String certSubjectOu = "";
    public volatile String certIssuerCn = "";
    public volatile String certIssuerC = "";
    public volatile String certIssuerO = "";

    public HttpEntry(String source, long id, long time, String thread,
                     String method, String url,
                     Map<String, String> reqHeaders, String reqBodyType, String reqBody, int reqBodyBytes,
                     String stack, String logLine) {
        this.source = source;
        this.id = id;
        this.time = time;
        this.thread = thread;
        this.method = method;
        this.url = url;
        this.query = parseQuery(url);
        this.reqHeaders = reqHeaders == null ? new TreeMap<>() : new TreeMap<>(reqHeaders);
        this.reqBodyType = reqBodyType;
        this.reqBody = reqBody;
        this.reqBodyBytes = reqBodyBytes;
        this.status = 0;
        this.statusMsg = "";
        this.respHeaders = new TreeMap<>();
        this.respBodyType = "text";
        this.respBody = "";
        this.respBodyBytes = 0;
        this.durationMs = 0;
        this.stack = stack;
        this.done = false;
        this.logLine = logLine;
    }

    /** v1.62 P0: H2 body 追加上限（详情页展示用，防 OOM；与 TlsHttpParser BODY 上限一致逻辑） */
    public static final int BODY_APPEND_MAX = 256 * 1024;

    /** v1.62 P0: 追加请求体（H2 DATA 块流式到达）——reqBody 改 volatile 支持追加 */
    public void appendReqBody(String chunk) {
        if (chunk == null || chunk.isEmpty()) return;
        try {
            if (reqBody.length() >= BODY_APPEND_MAX) { reqBodyBytes += chunk.length(); return; }
            int need = BODY_APPEND_MAX - reqBody.length();
            String part = chunk.length() > need ? chunk.substring(0, need) : chunk;
            this.reqBody = reqBody + part;
            this.reqBodyBytes += chunk.length();
        } catch (Throwable t) { }
    }

    /** v1.62 P0: 追加响应体（H2 DATA 块流式到达）——响应体已 volatile 可直接追加 */
    public void appendRespBody(String chunk) {
        if (chunk == null || chunk.isEmpty()) return;
        try {
            if (respBody.length() >= BODY_APPEND_MAX) { respBodyBytes += chunk.length(); return; }
            int need = BODY_APPEND_MAX - respBody.length();
            String part = chunk.length() > need ? chunk.substring(0, need) : chunk;
            this.respBody = respBody + part;
            this.respBodyBytes += chunk.length();
        } catch (Throwable t) { }
    }

    /** v1.62 P0: 请求体是否只取可打印文本（二进制 chunk 跳过，防乱码）——NativeProbe 跨类调用 */
    public static String printableChunk(byte[] data, int len) {
        if (data == null || len <= 0) return "";
        int check = Math.min(len, 64);
        for (int i = 0; i < check; i++) {
            byte b = data[i];
            if (b == 0) return "";
            if (b < 0x09 || (b > 0x0d && b < 0x20)) return "";
        }
        try { return new String(data, 0, len, java.nio.charset.StandardCharsets.UTF_8); }
        catch (Throwable t) { return ""; }
    }

    /** 响应到达时填充 */
    public void complete(int status, String statusMsg, Map<String, String> respHeaders,
                         String respBodyType, String respBody, int respBodyBytes, long durationMs) {
        this.status = status;
        this.statusMsg = statusMsg == null ? "" : statusMsg;
        if (respHeaders != null) this.respHeaders.putAll(respHeaders);
        this.respBodyType = respBodyType;
        this.respBody = respBody == null ? "" : respBody;
        this.respBodyBytes = respBodyBytes;
        this.durationMs = durationMs;
        this.done = true;
    }

    /** v1.61: 只记录响应头（body 仍在到达，done 保持 false；body 完成后再 complete） */
    public void setResponseHead(int status, String statusMsg, Map<String, String> respHeaders,
                                String respBodyType, String respBody) {
        this.status = status;
        this.statusMsg = statusMsg == null ? "" : statusMsg;
        if (respHeaders != null) this.respHeaders.putAll(respHeaders);
        this.respBodyType = respBodyType;
        this.respBody = respBody == null ? "" : respBody;
    }

    /** v1.59: 补充连接元数据（协议/时间点/流ID/四元组）——构建后由各数据源调用 */
    public void setConnMeta(String protocol, long reqEndMs, long respStartMs,
                            long connId, int streamId,
                            String srcAddr, int srcPort, String dstAddr, int dstPort) {
        if (protocol != null && !protocol.isEmpty()) this.protocol = protocol;
        if (reqEndMs > 0) this.reqEndMs = reqEndMs;
        if (respStartMs > 0) this.respStartMs = respStartMs;
        if (connId != 0) this.connId = connId;
        this.streamId = streamId;
        if (srcAddr != null) this.srcAddr = srcAddr;
        this.srcPort = srcPort;
        if (dstAddr != null) this.dstAddr = dstAddr;
        this.dstPort = dstPort;
    }

    /** v1.59: 补充 TLS 元数据（C 级 native） */
    public void setTlsMeta(String tlsVersion, String sni, String alpn,
                           String cipherSelected, String cipherList) {
        if (tlsVersion != null) this.tlsVersion = tlsVersion;
        if (sni != null) this.sni = sni;
        if (alpn != null) this.alpn = alpn;
        if (cipherSelected != null) this.cipherSelected = cipherSelected;
        if (cipherList != null) this.cipherList = cipherList;
    }

    /** v1.59: 补充服务端证书（D 级 native）；v1.61: +DN 细分字段 */
    public void setCertMeta(String subject, String issuer, String serial,
                            String sha256, String notBefore, String notAfter) {
        if (subject != null) this.certSubject = subject;
        if (issuer != null) this.certIssuer = issuer;
        if (serial != null) this.certSerial = serial;
        if (sha256 != null) this.certSha256 = sha256;
        if (notBefore != null) this.certNotBefore = notBefore;
        if (notAfter != null) this.certNotAfter = notAfter;
    }

    /** v1.61: 证书 DN 细分字段（Subject CN/国家/省/地区/组织/单位 + Issuer CN/国家/组织） */
    public void setCertMetaDetailed(String subjectCn, String subjectC, String subjectSt, String subjectL,
                                    String subjectO, String subjectOu,
                                    String issuerCn, String issuerC, String issuerO) {
        if (subjectCn != null) this.certSubjectCn = subjectCn;
        if (subjectC != null) this.certSubjectC = subjectC;
        if (subjectSt != null) this.certSubjectSt = subjectSt;
        if (subjectL != null) this.certSubjectL = subjectL;
        if (subjectO != null) this.certSubjectO = subjectO;
        if (subjectOu != null) this.certSubjectOu = subjectOu;
        if (issuerCn != null) this.certIssuerCn = issuerCn;
        if (issuerC != null) this.certIssuerC = issuerC;
        if (issuerO != null) this.certIssuerO = issuerO;
    }

    /** 从 url 的 ? 部分解析 query 参数（保留原始顺序，重复 key 后者覆盖）
     *  v1.62 P2-21: key/value URL decode（此前 %20/%3A 等编码原样显示） */
    private static Map<String, String> parseQuery(String url) {
        Map<String, String> out = new java.util.LinkedHashMap<>();
        if (url == null) return out;
        int q = url.indexOf('?');
        if (q < 0 || q == url.length() - 1) return out;
        String[] pairs = url.substring(q + 1).split("&");
        for (String p : pairs) {
            if (p.isEmpty()) continue;
            int eq = p.indexOf('=');
            if (eq < 0) {
                out.put(percentDecode(p), "");
            } else {
                out.put(percentDecode(p.substring(0, eq)), percentDecode(p.substring(eq + 1)));
            }
        }
        return out;
    }

    /** URL 百分号解码（+ → 空格）；解码失败返回原串 */
    private static String percentDecode(String s) {
        if (s == null || s.isEmpty()) return s;
        try {
            return java.net.URLDecoder.decode(s, "UTF-8");
        } catch (Throwable t) {
            return s;
        }
    }

    /** 序列化为 JSON（推送主进程 / 落盘） */
    public JSONObject toJson() {        JSONObject o = new JSONObject();
        try {
            o.put("source", source);
            o.put("id", id);
            o.put("time", time);
            o.put("thread", thread);
            o.put("method", method);
            o.put("url", url);
            o.put("query", toJsonObject(query));
            o.put("reqHeaders", toJsonObject(reqHeaders));
            o.put("reqBodyType", reqBodyType);
            o.put("reqBody", reqBody);
            o.put("reqBodyBytes", reqBodyBytes);
            o.put("status", status);
            o.put("statusMsg", statusMsg);
            o.put("respHeaders", toJsonObject(respHeaders));
            o.put("respBodyType", respBodyType);
            o.put("respBody", respBody);
            o.put("respBodyBytes", respBodyBytes);
            o.put("durationMs", durationMs);
            o.put("stack", stack);
            o.put("done", done);
            o.put("logLine", logLine);
            // v1.59: 元数据扩展
            o.put("protocol", protocol);
            o.put("reqStartMs", reqStartMs);
            o.put("reqEndMs", reqEndMs);
            o.put("respStartMs", respStartMs);
            o.put("respEndMs", respEndMs);
            o.put("connId", connId);
            o.put("streamId", streamId);
            o.put("srcAddr", srcAddr);
            o.put("srcPort", srcPort);
            o.put("dstAddr", dstAddr);
            o.put("dstPort", dstPort);
            o.put("tlsVersion", tlsVersion);
            o.put("sni", sni);
            o.put("alpn", alpn);
            o.put("cipherSelected", cipherSelected);
            o.put("cipherList", cipherList);
            o.put("certSubject", certSubject);
            o.put("certIssuer", certIssuer);
            o.put("certSerial", certSerial);
            o.put("certSha256", certSha256);
            o.put("certNotBefore", certNotBefore);
            o.put("certNotAfter", certNotAfter);
            // v1.61: 证书 DN 细分
            o.put("certSubjectCn", certSubjectCn);
            o.put("certSubjectC", certSubjectC);
            o.put("certSubjectSt", certSubjectSt);
            o.put("certSubjectL", certSubjectL);
            o.put("certSubjectO", certSubjectO);
            o.put("certSubjectOu", certSubjectOu);
            o.put("certIssuerCn", certIssuerCn);
            o.put("certIssuerC", certIssuerC);
            o.put("certIssuerO", certIssuerO);
        } catch (Throwable t) {
            // 序列化失败不应影响主流程
        }
        return o;
    }

    private static JSONObject toJsonObject(Map<String, String> m) {
        JSONObject o = new JSONObject();
        if (m == null) return o;
        for (Map.Entry<String, String> e : m.entrySet()) {
            try { o.put(e.getKey(), e.getValue() == null ? "" : e.getValue()); }
            catch (Throwable ignored) { }
        }
        return o;
    }

    /** 从 JSON 反序列化（主进程接收推送 / 历史文件读取） */
    public static HttpEntry fromJson(JSONObject o) {
        try {
            String source = o.optString("source", "OKHTTP");
            long id = o.optLong("id", 0);
            long time = o.optLong("time", System.currentTimeMillis());
            String thread = o.optString("thread", "");
            String method = o.optString("method", "");
            String url = o.optString("url", "");
            java.util.Map<String, String> reqHdrs = fromJsonObject(o.optJSONObject("reqHeaders"));
            String reqBodyType = o.optString("reqBodyType", "none");
            String reqBody = o.optString("reqBody", "");
            int reqBodyBytes = o.optInt("reqBodyBytes", 0);
            String stack = o.optString("stack", "");
            String logLine = o.optString("logLine", "");
            HttpEntry e = new HttpEntry(source, id, time, thread, method, url,
                    reqHdrs, reqBodyType, reqBody, reqBodyBytes, stack, logLine);
            e.status = o.optInt("status", 0);
            e.statusMsg = o.optString("statusMsg", "");
            java.util.Map<String, String> rspHdrs = fromJsonObject(o.optJSONObject("respHeaders"));
            e.respHeaders.putAll(rspHdrs);
            e.respBodyType = o.optString("respBodyType", "text");
            e.respBody = o.optString("respBody", "");
            e.respBodyBytes = o.optInt("respBodyBytes", 0);
            e.durationMs = o.optLong("durationMs", 0);
            e.done = o.optBoolean("done", false);
            // v1.59: 元数据扩展（旧历史无字段 → optX 默认值兼容）
            e.protocol = o.optString("protocol", "HTTP/1.1");
            e.reqStartMs = o.optLong("reqStartMs", 0);
            e.reqEndMs = o.optLong("reqEndMs", 0);
            e.respStartMs = o.optLong("respStartMs", 0);
            e.respEndMs = o.optLong("respEndMs", 0);
            e.connId = o.optLong("connId", 0);
            e.streamId = o.optInt("streamId", 0);
            e.srcAddr = o.optString("srcAddr", "");
            e.srcPort = o.optInt("srcPort", 0);
            e.dstAddr = o.optString("dstAddr", "");
            e.dstPort = o.optInt("dstPort", 0);
            e.tlsVersion = o.optString("tlsVersion", "");
            e.sni = o.optString("sni", "");
            e.alpn = o.optString("alpn", "");
            e.cipherSelected = o.optString("cipherSelected", "");
            e.cipherList = o.optString("cipherList", "");
            e.certSubject = o.optString("certSubject", "");
            e.certIssuer = o.optString("certIssuer", "");
            e.certSerial = o.optString("certSerial", "");
            e.certSha256 = o.optString("certSha256", "");
            e.certNotBefore = o.optString("certNotBefore", "");
            e.certNotAfter = o.optString("certNotAfter", "");
            // v1.61: 证书 DN 细分（旧历史无字段 → 空串兼容）
            e.certSubjectCn = o.optString("certSubjectCn", "");
            e.certSubjectC = o.optString("certSubjectC", "");
            e.certSubjectSt = o.optString("certSubjectSt", "");
            e.certSubjectL = o.optString("certSubjectL", "");
            e.certSubjectO = o.optString("certSubjectO", "");
            e.certSubjectOu = o.optString("certSubjectOu", "");
            e.certIssuerCn = o.optString("certIssuerCn", "");
            e.certIssuerC = o.optString("certIssuerC", "");
            e.certIssuerO = o.optString("certIssuerO", "");
            return e;
        } catch (Throwable t) {
            return null;
        }
    }

    private static java.util.Map<String, String> fromJsonObject(JSONObject o) {
        java.util.Map<String, String> m = new TreeMap<>();
        if (o == null) return m;
        java.util.Iterator<String> it = o.keys();
        while (it.hasNext()) {
            String k = it.next();
            try { m.put(k, o.optString(k, "")); } catch (Throwable ignored) { }
        }
        return m;
    }

    /** 完整 HTTP 报文（原始视图用）——v1.62 P2-20: 协议用真实字段（H2 不再硬编码 HTTP/1.1） */
    public String rawRequest() {
        StringBuilder sb = new StringBuilder();
        String p = protocol == null || protocol.isEmpty() ? "HTTP/1.1" : protocol;
        sb.append(method).append(' ').append(url).append(' ').append(p).append("\r\n");
        for (Map.Entry<String, String> e : reqHeaders.entrySet()) {
            sb.append(e.getKey()).append(": ").append(e.getValue()).append("\r\n");
        }
        if (reqBody != null && !reqBody.isEmpty() && !"none".equals(reqBodyType)) {
            sb.append("\r\n").append(reqBody);
        }
        return sb.toString();
    }

    public String rawResponse() {
        if (!done) return "（响应未完成）";
        StringBuilder sb = new StringBuilder();
        String p = protocol == null || protocol.isEmpty() ? "HTTP/1.1" : protocol;
        sb.append(p).append(' ').append(status).append(' ').append(statusMsg).append("\r\n");
        for (Map.Entry<String, String> e : respHeaders.entrySet()) {
            sb.append(e.getKey()).append(": ").append(e.getValue()).append("\r\n");
        }
        if (respBody != null && !respBody.isEmpty()) {
            sb.append("\r\n").append(respBody);
        }
        return sb.toString();
    }

    /** 内容类型嗅探：json / form / text / binary */
    public static String sniffBodyType(String contentType, String body) {
        if (contentType != null) {
            String ct = contentType.toLowerCase();
            if (ct.contains("json")) return "json";
            if (ct.contains("x-www-form-urlencoded")) return "form";
            if (ct.contains("xml")) return "xml";
            if (ct.contains("html")) return "html";
            if (ct.contains("text/")) return "text";
            if (ct.contains("octet-stream") || ct.contains("image/") || ct.contains("audio/") || ct.contains("video/")) return "binary";
        }
        if (body == null || body.isEmpty()) return "text";
        // 无 Content-Type 时按内容嗅探
        String t = body.trim();
        if (t.startsWith("{") || t.startsWith("[")) return "json";
        if (t.startsWith("<")) return "xml";
        if (t.matches("(?s).*[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F].*")) return "binary";
        return "text";
    }
}
