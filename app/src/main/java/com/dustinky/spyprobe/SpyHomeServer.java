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
    static final int MAX_BODY = 1 << 20; // 请求体上限 1MB

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
             OutputStream out = sock.getOutputStream();
             BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {

            String reqLine = r.readLine();
            if (reqLine == null) return;
            String[] parts = reqLine.split(" ");
            if (parts.length < 2) return;
            String method = parts[0];
            String path = parts[1];

            int contentLength = 0;
            // v1.37 P0-5: 请求鉴权 token（目标进程推送带 X-Spy-Token）
            String reqToken = "";
            String line;
            while ((line = r.readLine()) != null && !line.isEmpty()) {
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
            String body = "";
            if (contentLength > 0) {
                char[] buf = new char[contentLength];
                int n = 0;
                while (n < contentLength) {
                    int k = r.read(buf, n, contentLength - n);
                    if (k < 0) break;
                    n += k;
                }
                body = new String(buf, 0, n);
            }

            // v1.37 P0-5: 写操作鉴权——主进程已生成 token 时，push_logs/config POST 必须带匹配 token
            String resp;
            if (!TokenStore.homeToken().isEmpty()
                    && ("POST".equals(method) || path.startsWith("/api/push_logs"))) {
                String expected = TokenStore.homeToken();
                if (!expected.equals(reqToken)) {
                    // 401：token 缺失/不匹配（防其他 App 伪造日志/配置）
                    resp = "{\"ok\":false,\"err\":\"unauthorized\"}";
                    try (Socket s2 = sock) {
                        java.io.OutputStream o2 = s2.getOutputStream();
                        byte[] d = resp.getBytes(StandardCharsets.UTF_8);
                        StringBuilder h = new StringBuilder();
                        h.append("HTTP/1.1 401 Unauthorized\r\n");
                        h.append("Content-Type: application/json; charset=utf-8\r\n");
                        h.append("Content-Length: ").append(d.length).append("\r\n");
                        h.append("Connection: close\r\n\r\n");
                        o2.write(h.toString().getBytes(StandardCharsets.UTF_8));
                        o2.write(d);
                        o2.flush();
                    } catch (Throwable t2) { }
                    return;
                }
            }
            resp = route(method, path, body);
            DebugLog.get().log("Home", method + " " + path + " -> " + resp.length() + "B");
            byte[] data = resp.getBytes(StandardCharsets.UTF_8);
            StringBuilder head = new StringBuilder();
            head.append("HTTP/1.1 200 OK\r\n");
            head.append("Content-Type: application/json; charset=utf-8\r\n");
            head.append("Content-Length: ").append(data.length).append("\r\n");
            head.append("Connection: close\r\n\r\n");
            out.write(head.toString().getBytes(StandardCharsets.UTF_8));
            out.write(data);
            out.flush();
        } catch (Throwable t) {
            DebugLog.get().log("Home", "conn err: " + t);
        }
    }

    private String route(String method, String path, String body) {
        try {
            String p = path.contains("?") ? path.substring(0, path.indexOf('?')) : path;

            switch (p) {
                case "/api/ping": {
                    JSONObject o = new JSONObject();
                    o.put("ok", true);
                    o.put("role", "home");
                    o.put("v", BuildConfig.VERSION_NAME);
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
                case "/api/config": {
                    if ("POST".equals(method)) {
                        // 目标进程/UI 上报配置 → 应用 + 持久化主进程家
                        if (body != null && !body.isEmpty()) {
                            Config.get().applyJson(body);
                            Config.get().saveConfig(Config.get().homeCfgFile());
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
