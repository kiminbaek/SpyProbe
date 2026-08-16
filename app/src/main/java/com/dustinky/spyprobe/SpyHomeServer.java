package com.dustinky.spyprobe;

/*
 * v1.32: 主进程数据面 server（127.0.0.1:9900）
 *
 * 【架构修正】数据全部放 SpyProbe 自己家，不再污染目标 App data：
 *   - 目标进程把日志推回这里（POST /api/push_logs）→ 主进程 LogPersister 写自己 files/spyprobe_logs/
 *   - 目标进程启动时从这里拉配置（GET /api/config）→ 权威配置源 = SpyProbe 自己家
 *   - UI（主进程）直接读自己内存/文件，不依赖目标进程在线
 *
 * 控制面（scan/hook/rules/clear 等）仍走目标进程 SpyServer:9901，两者分工。
 */

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import org.json.JSONArray;
import org.json.JSONObject;

public class SpyHomeServer {

    static final String TAG = "SpyProbe.Home";
    static final int PORT = 9900;
    static final int MAX_BODY = 4 << 20; // v1.46.2: 4MB——pcap_chunk 单会话最大 2MB（PcapWriter.MAX_SESSION），1MB 上限会截断 2MB chunk 丢一半数据

    // v1.38 P2-9: 服务启动时间戳（/api/status uptime 用）
    private static final long START_TS = System.currentTimeMillis();

    private volatile ServerSocket serverSocket;
    private volatile Thread acceptThread;
    // v1.33: 会话识别——目标进程每启动一次 session 都不同；变化时 LogPersister 开新会话文件
    private volatile String lastSession = "";

    private static final SpyHomeServer INSTANCE = new SpyHomeServer();
    public static SpyHomeServer get() { return INSTANCE; }

    public synchronized void start() {
        if (acceptThread != null && acceptThread.isAlive()) return;
        acceptThread = new Thread(this::acceptLoop, "SpyProbe-HomeServer");
        acceptThread.setDaemon(true);
        acceptThread.start();
    }

    /**
     * v1.36 P2-19: bind 失败/accept 连续异常不再退出——9900 被占或瞬时异常时每 2s 重试，
     *   server 永久存活（旧实现 bind 失败直接 return、accept 连错 10 次 break，server 永久死）
     */
    private void acceptLoop() {
        while (!Thread.currentThread().isInterrupted()) {
            try {
                if (serverSocket == null || serverSocket.isClosed()) {
                    serverSocket = new ServerSocket();
                    serverSocket.setReuseAddress(true);
                    serverSocket.bind(new InetSocketAddress("127.0.0.1", PORT), 16);
                    DebugLog.get().log("Home", "listening 127.0.0.1:" + PORT);
                }
                Socket s = serverSocket.accept();
                Thread t = new Thread(() -> handle(s), "SpyProbe-HomeConn");
                t.setDaemon(true);
                t.start();
            } catch (Throwable t) {
                DebugLog.get().log("Home", "accept err: " + t);
                try { if (serverSocket != null) serverSocket.close(); } catch (Throwable t2) { }
                serverSocket = null;
                try { Thread.sleep(2000); } catch (InterruptedException ie) { break; }
            }
        }
    }

    private void handle(Socket s) {
        try (Socket sock = s;
             InputStream in = sock.getInputStream();
             OutputStream out = sock.getOutputStream()) {

            // v1.39: 改用原始流手读 header 行——旧实现 BufferedReader 会缓冲 body 字节，
            //   pcap_chunk 二进制 body（含任意字节）经字符流会损坏。header 行读完再按路径分派。
            String reqLine = readHeaderLine(in);
            if (reqLine == null) return;
            String[] parts = reqLine.split(" ");
            if (parts.length < 2) return;
            String method = parts[0];
            String path = parts[1];

            int contentLength = 0;
            // v1.37 P0-5: 请求鉴权 token（目标进程推送带 X-Spy-Token）
            String reqToken = "";
            String line;
            while (!(line = readHeaderLine(in)).isEmpty()) {
                String lower = line.toLowerCase();
                if (lower.startsWith("content-length:")) {
                    try {
                        contentLength = Integer.parseInt(line.substring(15).trim());
                    } catch (NumberFormatException e) { contentLength = 0; }
                    if (contentLength > MAX_BODY) contentLength = MAX_BODY;
                } else if (lower.startsWith("x-spy-token:")) {
                    reqToken = line.substring(line.indexOf(':') + 1).trim();
                }
            }

            // v1.37 P0-5: 写操作鉴权——主进程已生成 token 时，push_logs/config POST 必须带匹配 token
            if (!TokenStore.homeToken().isEmpty()
                    && ("POST".equals(method) || path.startsWith("/api/push_logs"))) {
                String expected = TokenStore.homeToken();
                if (!expected.equals(reqToken)) {
                    // 401：token 缺失/不匹配（防其他 App 伪造日志/配置）
                    String resp = "{\"ok\":false,\"err\":\"unauthorized\"}";
                    writeBytes(out, resp.getBytes(StandardCharsets.UTF_8), "401 Unauthorized", "application/json; charset=utf-8");
                    return;
                }
            }

            // v1.39 P0: pcap_chunk 二进制 body（pcap 记录字节，无全局头）→ 主进程落盘
            if (path.startsWith("/api/pcap_chunk")) {
                byte[] body = readFully(in, contentLength);
                if (body != null && body.length > 0) {
                    PcapStore.get().append(body);
                    DebugLog.get().log("Pcap", "chunk +" + body.length + "B (total=" + PcapStore.get().currentSize() + "B)");
                }
                writeBytes(out, "{\"ok\":true}".getBytes(StandardCharsets.UTF_8), "200 OK", "application/json; charset=utf-8");
                return;
            }

            // 普通文本请求：从 InputStream 继续读 body
            String body = "";
            if (contentLength > 0) {
                byte[] raw = readFully(in, contentLength);
                if (raw != null) body = new String(raw, StandardCharsets.UTF_8);
            }

            String resp = route(method, path, body);
            DebugLog.get().log("Home", method + " " + path + " -> " + resp.length() + "B");
            writeBytes(out, resp.getBytes(StandardCharsets.UTF_8), "200 OK", "application/json; charset=utf-8");
        } catch (Throwable t) {
            DebugLog.get().log("Home", "conn err: " + t);
        }
    }

    /** 读一行 header（直到 \r\n），返回不含 \r\n 的字符串；流结束返回 null */
    private String readHeaderLine(InputStream in) throws Exception {
        java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream(128);
        int b;
        while ((b = in.read()) != -1) {
            if (b == '\n') break;
            if (b != '\r') buf.write(b);
        }
        if (buf.size() == 0 && b == -1) return null;
        return new String(buf.toByteArray(), StandardCharsets.UTF_8);
    }

    /** 读满 n 字节（防半包）；n<=0 返回空数组 */
    private byte[] readFully(InputStream in, int n) throws Exception {
        if (n <= 0) return new byte[0];
        byte[] buf = new byte[n];
        int got = 0;
        while (got < n) {
            int k = in.read(buf, got, n - got);
            if (k < 0) break;
            got += k;
        }
        if (got == 0) return new byte[0];
        if (got == n) return buf;
        byte[] out = new byte[got];
        System.arraycopy(buf, 0, out, 0, got);
        return out;
    }

    private void writeBytes(OutputStream out, byte[] data, String status, String contentType) throws Exception {
        StringBuilder head = new StringBuilder();
        head.append("HTTP/1.1 ").append(status).append("\r\n");
        head.append("Content-Type: ").append(contentType).append("\r\n");
        head.append("Content-Length: ").append(data.length).append("\r\n");
        head.append("Connection: close\r\n\r\n");
        out.write(head.toString().getBytes(StandardCharsets.UTF_8));
        out.write(data);
        out.flush();
    }

    private String route(String method, String path, String body) {
        try {
            String p = path.contains("?") ? path.substring(0, path.indexOf('?')) : path;

            switch (p) {
                case "/api/export": {
                    // v1.41: 自己家导出（UI 实时分享不依赖目标进程在线）
                    // 最近 3000 条（同 9901 逻辑，防超大拼接）
                    StringBuilder sb = new StringBuilder();
                    java.util.List<LogStore.Entry> all = LogStore.get().all();
                    int from = Math.max(0, all.size() - 3000);
                    for (int i = from; i < all.size(); i++) {
                        LogStore.Entry e = all.get(i);
                        sb.append(com.dustinky.spyprobe.util.ShareLogUtil.INSTANCE.formatLine(e.time, e.tag, e.msg)).append('\n');
                    }
                    JSONObject o = new JSONObject();
                    o.put("ok", true);
                    o.put("text", sb.toString());
                    return o.toString();
                }
                case "/api/ping": {
                    JSONObject o = new JSONObject();
                    o.put("ok", true);
                    o.put("role", "home");
                    o.put("v", BuildConfig.VERSION_NAME);
                    return o.toString();
                }
                case "/api/token": {
                    // v1.44.1: 目标进程 HTTP 拉 token（根治 libxposed getRemotePreferences/
                    //   openRemoteFile 跨进程读在真机上静默返回空——v1.21 坑 v1.40.1 未真正修好）。
                    //   本机回环 127.0.0.1:9900，仅本机 App 可访问；目标进程能收到 401 就说明
                    //   9900 活着 → 这里一定拿得到 token → 重试必成功。
                    //   无 token 时返回 empty（老主进程/未初始化，主进程不校验则目标进程可不带）。
                    JSONObject o = new JSONObject();
                    o.put("ok", true);
                    o.put("token", TokenStore.homeToken());
                    return o.toString();
                }
                case "/api/push_http": {
                    // v1.48: 目标进程推送结构化 HTTP 条目 → 主进程内存 HttpStore（UI 详情页查询）
                    JSONObject root = new JSONObject(body == null ? "{}" : body);
                    JSONArray arr = root.optJSONArray("entries");
                    int n = 0;
                    if (arr != null) {
                        for (int i = 0; i < arr.length(); i++) {
                            try {
                                JSONObject e = arr.getJSONObject(i);
                                HttpEntry he = HttpEntry.fromJson(e);
                                if (he != null) { HomeHttpStore.get().add(he); n++; }
                            } catch (Throwable t) { }
                        }
                    }
                    JSONObject o = new JSONObject();
                    o.put("ok", true);
                    o.put("accepted", n);
                    return o.toString();
                }
                case "/api/target_uid": {
                    // v2.0.0 hook-revival: MITM 摘除（v1.74 卡死事故终止），uid 上报仅留痕
                    try {
                        JSONObject root = new JSONObject(body == null ? "{}" : body);
                        int uid = root.optInt("uid", 0);
                        if (uid > 0) {
                            DebugLog.get().log("Home", "target uid: " + uid + " (MITM removed)");
                        }
                    } catch (Throwable t) {
                        DebugLog.get().log("Home", "target_uid err: " + t);
                    }
                    return "{\"ok\":true}";
                }
                case "/api/push_crash": {
                    // v1.53: 目标进程崩溃 → CrashCatcher 推回主进程落盘（调试日志导出自动附带）
                    CrashCatcher.saveFromTarget(body == null ? "(null)" : body);
                    return "{\"ok\":true}";
                }
                case "/api/push_event": {
                    // v1.55: 目标进程推送通用结构化事件 → 主进程 HomeEventStore（UI 卡片/分析查询）
                    JSONObject root = new JSONObject(body == null ? "{}" : body);
                    JSONArray arr = root.optJSONArray("entries");
                    int n = 0;
                    if (arr != null) {
                        for (int i = 0; i < arr.length(); i++) {
                            try {
                                JSONObject e = arr.getJSONObject(i);
                                SpyEvent ev = SpyEvent.fromJson(e);
                                if (ev != null) { HomeEventStore.get().add(ev); n++; }
                            } catch (Throwable t) { }
                        }
                    }
                    JSONObject o = new JSONObject();
                    o.put("ok", true);
                    o.put("accepted", n);
                    return o.toString();
                }
                case "/api/push_logs": {
                    // 目标进程批量推送日志 → 主进程 LogStore（LogPersister 落自己家）
                    JSONObject root = new JSONObject(body == null ? "{}" : body);
                    JSONArray arr = root.optJSONArray("entries");
                    // v1.33: 会话识别——目标进程每启动一次 session 都不同 → 开新会话文件（按次数记）
                    String sess = root.optString("session", "");
                    if (!sess.isEmpty() && !sess.equals(lastSession)) {
                        lastSession = sess;
                        LogPersister.get().startSession();
                        // v1.39 P0: 会话切换 → pcap 归档（新会话新建 current.pcap）
                        PcapStore.get().onSessionStart();
                        DebugLog.get().log("Home", "new session " + (sess.length() > 8 ? sess.substring(0, 8) : sess));
                    }
                    int n = 0;
                    if (arr != null) {
                        for (int i = 0; i < arr.length(); i++) {
                            try {
                                JSONObject e = arr.getJSONObject(i);
                                // v1.36 P2-13: 用原始时间落盘（旧实现走 log() 重新格式化，
                                //   推送延迟会漂移时间）；seq 仍由主进程分配（跨会话全局唯一）
                                LogStore.get().logAt(e.optString("t", ""), e.optString("tag", "?"), e.optString("m", ""));
                                n++;
                            } catch (Throwable t) { }
                        }
                    }
                    JSONObject o = new JSONObject();
                    o.put("ok", true);
                    o.put("accepted", n);
                    return o.toString();
                }
                // v1.38 P2-9: hooker webserver 思路——探测结果 HTTP 化补充
                case "/api/status": {
                    // 实时状态：版本/运行时长/日志条数/最近 seq/最后一条时间
                    JSONObject o = new JSONObject();
                    o.put("ok", true);
                    o.put("v", BuildConfig.VERSION_NAME);
                    o.put("uptimeMs", System.currentTimeMillis() - START_TS);
                    o.put("logCount", LogStore.get().size());
                    o.put("lastSeq", LogStore.get().lastSeq());
                    java.util.List<LogStore.Entry> all = LogStore.get().all();
                    o.put("lastTime", all.isEmpty() ? "" : all.get(all.size() - 1).time);
                    return o.toString();
                }
                case "/api/logs": {
                    // v1.41: 支持 since 增量（UI 实时轮询自己家用）；格式与 9901 对齐（logs+next）
                    // 兼容旧参数 limit/tag：limit 取最近 N 条，tag 过滤
                    long since = 0;
                    int limit = -1;
                    String tagFilter = "";
                    String q = path.contains("?") ? path.substring(path.indexOf('?') + 1) : "";
                    for (String kv : q.split("&")) {
                        String[] pair = kv.split("=");
                        if (pair.length != 2) continue;
                        if ("since".equals(pair[0])) {
                            try { since = Long.parseLong(pair[1]); } catch (Throwable t) { since = 0; }
                        } else if ("limit".equals(pair[0])) {
                            try { limit = Math.max(1, Math.min(Integer.parseInt(pair[1]), 2000)); } catch (Throwable t) { }
                        } else if ("tag".equals(pair[0])) {
                            // v1.47 P2-8: URL 解码（UI 端 Uri.encode 编码了中文/特殊字符，与 9901 /api/classes filter 同款）
                            try { tagFilter = java.net.URLDecoder.decode(pair[1], "UTF-8"); } catch (Throwable t) { tagFilter = pair[1]; }
                        }
                    }
                    java.util.List<LogStore.Entry> all = LogStore.get().all();
                    JSONArray arr = new JSONArray();
                    long firstSeq = 0; // v1.50 P0-2: since 模式下返回的第一条 seq（UI 检测环形淘汰缺口）
                    if (since > 0) {
                        // since 模式：返回 seq > since 的全部（增量）
                        for (LogStore.Entry e : all) {
                            if (e.seq <= since) continue;
                            if (!tagFilter.isEmpty() && !e.tag.contains(tagFilter)) continue;
                            if (firstSeq == 0) firstSeq = e.seq;
                            JSONObject eo = new JSONObject();
                            eo.put("seq", e.seq);
                            eo.put("time", e.time);
                            eo.put("tag", e.tag);
                            eo.put("msg", e.msg);
                            arr.put(eo);
                        }
                    } else {
                        // 兼容模式：最近 N 条（默认 200）
                        if (limit < 0) limit = 200;
                        int from = Math.max(0, all.size() - limit);
                        for (int i = from; i < all.size(); i++) {
                            LogStore.Entry e = all.get(i);
                            if (!tagFilter.isEmpty() && !e.tag.contains(tagFilter)) continue;
                            JSONObject eo = new JSONObject();
                            eo.put("seq", e.seq);
                            eo.put("time", e.time);
                            eo.put("tag", e.tag);
                            eo.put("msg", e.msg);
                            arr.put(eo);
                        }
                    }
                    JSONObject o = new JSONObject();
                    o.put("ok", true);
                    o.put("count", arr.length());
                    o.put("total", all.size());
                    o.put("logs", arr);
                    o.put("next", LogStore.get().lastSeq());
                    o.put("first", firstSeq); // v1.50 P0-2: 0=兼容模式/无数据；>0=since 模式首条 seq
                    return o.toString();
                }
                case "/api/clear": {
                    // v1.50 P0-1: 实时清空——主进程 LogStore + HomeHttpStore 内存。
                    // 9901 目标进程 /api/clear 只清目标进程侧；不清 9900 则 UI 清完 since=0
                    // 下次轮询又把旧日志全拉回来（"清完立刻重新出现"）。
                    LogStore.get().clear();
                    HomeHttpStore.get().clearMem();
                    HomeEventStore.get().clearMem(); // v1.55: 通用事件同步清
                    DebugLog.get().log("Home", "clear home log+http+event store");
                    JSONObject o = new JSONObject();
                    o.put("ok", true);
                    return o.toString();
                }
                case "/api/config": {
                    if ("POST".equals(method)) {
                        // 目标进程/UI 上报配置 → 应用 + 持久化主进程家
                        if (body != null && !body.isEmpty()) {
                            Config.get().applyJson(body);
                            Config.get().saveConfig(Config.get().homeCfgFile());
                            // v2.0.0 hook-revival: MITM 已摘除，配置仅持久化
                        }
                        JSONObject o = new JSONObject();
                        o.put("ok", true);
                        return o.toString();
                    }
                    // GET：返回主进程权威配置（目标进程启动时拉）
                    return Config.get().toJson().toString();
                }
                default:
                    JSONObject o = new JSONObject();
                    o.put("ok", false);
                    o.put("err", "unknown path " + p);
                    return o.toString();
            }
        } catch (Throwable t) {
            try {
                JSONObject o = new JSONObject();
                o.put("ok", false);
                o.put("err", String.valueOf(t));
                return o.toString();
            } catch (Throwable t2) {
                return "{\"ok\":false,\"err\":\"json err\"}";
            }
        }
    }
}
