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

    private static final SpyHomeServer INSTANCE = new SpyHomeServer();
    public static SpyHomeServer get() { return INSTANCE; }

    public synchronized void start() {
        if (acceptThread != null && acceptThread.isAlive()) return;
        acceptThread = new Thread(this::acceptLoop, "SpyProbe-HomeServer");
        acceptThread.setDaemon(true);
        acceptThread.start();
    }

    private void acceptLoop() {
        try {
            serverSocket = new ServerSocket();
            serverSocket.setReuseAddress(true);
            serverSocket.bind(new InetSocketAddress("127.0.0.1", PORT), 16);
        } catch (Throwable t) {
            DebugLog.get().log("Home", "bind FAIL 127.0.0.1:" + PORT + " : " + t);
            return;
        }
        DebugLog.get().log("Home", "listening 127.0.0.1:" + PORT);
        int failCount = 0;
        while (!Thread.currentThread().isInterrupted()) {
            try {
                Socket s = serverSocket.accept();
                failCount = 0;
                Thread t = new Thread(() -> handle(s), "SpyProbe-HomeConn");
                t.setDaemon(true);
                t.start();
            } catch (Throwable t) {
                if (++failCount >= 10) break;
                try { Thread.sleep(200); } catch (InterruptedException ie) { break; }
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
            String line;
            while ((line = r.readLine()) != null && !line.isEmpty()) {
                String lower = line.toLowerCase();
                if (lower.startsWith("content-length:")) {
                    try {
                        contentLength = Integer.parseInt(line.substring(15).trim());
                    } catch (NumberFormatException e) { contentLength = 0; }
                    if (contentLength > MAX_BODY) contentLength = MAX_BODY;
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

            String resp = route(method, path, body);
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
                    int n = 0;
                    if (arr != null) {
                        for (int i = 0; i < arr.length(); i++) {
                            try {
                                JSONObject e = arr.getJSONObject(i);
                                LogStore.get().log(e.optString("tag", "?"), e.optString("m", ""));
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
