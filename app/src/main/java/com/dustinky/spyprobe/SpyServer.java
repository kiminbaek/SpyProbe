package com.dustinky.spyprobe;

import android.util.Log;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.json.JSONArray;
import org.json.JSONObject;

import io.github.libxposed.api.XposedInterface;

/**
 * 目标进程内的本地 HTTP server（127.0.0.1:9901）
 * UI 通过它拉取日志、下发配置、探测方法。
 *
 * 路由：
 *   GET  /api/ping                -> {"ok":true,"pkg":...}
 *   GET  /api/logs?since=N        -> {"next":N,"logs":[...]}
 *   GET  /api/logs/all            -> 全量日志（文本）
 *   GET  /api/export              -> 全量日志文本（UI 导出用）
 *   POST /api/config              -> {"sslBypass":..,"okhttp":..,"url":..,"bodyLimit":..}
 *   GET  /api/config              -> 当前配置
 *   POST /api/scan                -> {"class":"com.xxx.Cls"} 枚举方法+字段
 *   POST /api/hook                -> {"class":..,"method":..,"params":..} 动态 hook
 *   POST /api/unhook              -> {"class":..,"method":..,"params":..} 卸载 hook
 *   GET  /api/hooks               -> 当前已 hook 列表
 *   POST /api/clear               -> 清空日志
 */
public class SpyServer {

    static final String TAG = "SpyProbe.Srv";
    static final int PORT = 9901;
    static final int MAX_BODY = 1 << 20; // 请求体上限 1MB

    private final NetProbe net;
    private final MethodProbe mth;
    private final ClassLoadProbe clsProbe;
    private final String pkg;
    private final android.content.SharedPreferences rulesPrefs; // v1.6: 规则持久化
    private final DexKitProbe dexKit; // v1.9: DexKit（导出 dex / 字符串反查）
    private volatile ServerSocket serverSocket;
    private volatile Thread acceptThread;
    private volatile int actualPort = PORT; // v1.3: 实际绑定端口（多进程 app 时可能偏移）

    public SpyServer(NetProbe net, MethodProbe mth, ClassLoadProbe clsProbe, String pkg,
                     android.content.SharedPreferences rulesPrefs, DexKitProbe dexKit) {
        this.net = net;
        this.mth = mth;
        this.clsProbe = clsProbe;
        this.pkg = pkg;
        this.rulesPrefs = rulesPrefs;
        this.dexKit = dexKit; // v1.9
    }

    public void start() {
        // v1.3: 多进程 app / 多目标勾选时 9901 可能被占用 → 依次尝试 9901-9910
        for (int attempt = 0; attempt < 10; attempt++) {
            int p = PORT + attempt;
            try {
                serverSocket = new ServerSocket(p, 50, InetAddress.getByName("127.0.0.1"));
                actualPort = p;
                acceptThread = new Thread(this::acceptLoop, "SpyProbe-Server");
                acceptThread.setDaemon(true);
                acceptThread.start();
                LogStore.get().log(TAG, "server started on 127.0.0.1:" + p + " pkg=" + pkg);
                return;
            } catch (Throwable t) {
                LogStore.get().log(TAG, "port " + p + " busy, try next");
            }
        }
        LogStore.get().log(TAG, "server start fail: all ports 9901-9910 busy");
    }

    private void acceptLoop() {
        int failCount = 0;
        while (!Thread.currentThread().isInterrupted()) {
            try {
                Socket s = serverSocket.accept();
                failCount = 0;
                Thread t = new Thread(() -> handle(s), "SpyProbe-Conn");
                t.setDaemon(true);
                t.start();
            } catch (Throwable t) {
                // v1.3: accept 异常不直接死，连续 10 次才退出（防止偶发失败 kill server）
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

            // 读 headers 找 Content-Length（P1-13: 限制 1MB 防 OOM）
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
            LogStore.get().log(TAG, "conn err: " + t);
        }
    }

    private String route(String method, String path, String body) throws Exception {
        try {
            // 去掉 query 取路径
            String p = path.contains("?") ? path.substring(0, path.indexOf('?')) : path;
            String query = path.contains("?") ? path.substring(path.indexOf('?') + 1) : "";

            switch (p) {
                case "/api/ping": {
                    JSONObject o = new JSONObject();
                    o.put("ok", true);
                    o.put("pkg", pkg);
                    o.put("port", actualPort);
                    o.put("logCount", LogStore.get().size());
                    o.put("classCount", clsProbe.size());
                    // v1.2: app 版本信息（版本判断/加固识别用）ActivityThread 是 @hide，反射获取
                    try {
                        Class<?> at = Class.forName("android.app.ActivityThread");
                        Object app = at.getMethod("currentApplication").invoke(null);
                        if (app != null) {
                            Object pm = app.getClass().getMethod("getPackageManager").invoke(app);
                            if (pm != null) {
                                android.content.pm.PackageInfo pi = ((android.content.pm.PackageManager) pm).getPackageInfo(pkg, 0);
                                o.put("versionName", pi.versionName);
                                o.put("versionCode", pi.versionCode);
                                if (android.os.Build.VERSION.SDK_INT >= 28) {
                                    o.put("targetSdk", pi.applicationInfo.targetSdkVersion);
                                }
                            }
                        }
                    } catch (Throwable t) { }
                    return o.toString();
                }
                case "/api/logs": {
                    long since = 0;
                    for (String kv : query.split("&")) {
                        if (kv.startsWith("since=")) {
                            // v1.7: 非法 since 值不 500，回退 0
                            try {
                                since = Long.parseLong(kv.substring(6));
                            } catch (Throwable t) {
                                since = 0;
                            }
                        }
                    }
                    List<LogStore.Entry> logs = LogStore.get().since(since);
                    JSONArray arr = new JSONArray();
                    for (LogStore.Entry e : logs) {
                        JSONObject o = new JSONObject();
                        o.put("seq", e.seq);
                        o.put("time", e.time);
                        o.put("tag", e.tag);
                        o.put("msg", e.msg);
                        arr.put(o);
                    }
                    JSONObject o = new JSONObject();
                    o.put("ok", true);
                    o.put("next", LogStore.get().lastSeq());
                    o.put("logs", arr);
                    return o.toString();
                }
                case "/api/logs/all":
                case "/api/export": {
                    StringBuilder sb = new StringBuilder();
                    for (LogStore.Entry e : LogStore.get().all()) {
                        sb.append(e.time).append(" [").append(e.tag).append("] ").append(e.msg).append('\n');
                    }
                    JSONObject o = new JSONObject();
                    o.put("ok", true);
                    o.put("text", sb.toString());
                    return o.toString();
                }
                case "/api/config": {
                    if ("POST".equals(method)) {
                        JSONObject c = new JSONObject(body);
                        Config cfg = Config.get();
                        if (c.has("sslBypass")) cfg.sslBypass = c.getBoolean("sslBypass");
                        if (c.has("okhttp")) cfg.okhttpCapture = c.getBoolean("okhttp");
                        if (c.has("url")) cfg.urlCapture = c.getBoolean("url");
                        if (c.has("dns")) cfg.dnsCapture = c.getBoolean("dns");
                        if (c.has("tcp")) cfg.tcpCapture = c.getBoolean("tcp");
                        if (c.has("classes")) cfg.classCapture = c.getBoolean("classes");
                        if (c.has("classFilter")) cfg.classFilter = c.optString("classFilter", "");
                        if (c.has("classLogAll")) cfg.classLogAll = c.getBoolean("classLogAll");
                        if (c.has("bodyLimit")) cfg.bodyLimit = Math.max(0, Math.min(1 << 20, c.getInt("bodyLimit")));
                        // v1.12: 日志环形缓冲容量可配置（100-20000）
                        if (c.has("logLimit")) cfg.logLimit = Math.max(100, Math.min(20000, c.getInt("logLimit")));
                        if (c.has("webView")) cfg.webViewCapture = c.getBoolean("webView");
                        if (c.has("prefs")) cfg.prefsCapture = c.getBoolean("prefs");
                        if (c.has("sqlite")) cfg.sqliteCapture = c.getBoolean("sqlite");
                        if (c.has("urlBuild")) cfg.urlBuildCapture = c.getBoolean("urlBuild");
                        if (c.has("logcat")) cfg.logcatCapture = c.getBoolean("logcat");
                        if (c.has("crypto")) cfg.cryptoCapture = c.getBoolean("crypto");
                        if (c.has("activity")) cfg.activityCapture = c.getBoolean("activity");
                        if (c.has("json")) cfg.jsonCapture = c.getBoolean("json");
                        if (c.has("detailMode")) cfg.detailMode = c.getBoolean("detailMode"); // v1.6
                        // v1.9: 环境检测 / TLS / 连接点 / Cronet 开关
                        if (c.has("env")) cfg.envCapture = c.getBoolean("env");
                        if (c.has("tls")) cfg.tlsCapture = c.getBoolean("tls");
                        if (c.has("connect")) cfg.connectCapture = c.getBoolean("connect");
                        if (c.has("cronet")) cfg.cronetCapture = c.getBoolean("cronet");
                        // v1.13: 反检测开关（隐藏 root/Xposed，防目标 App 检测）
                        if (c.has("antiRoot")) cfg.antiRoot = c.getBoolean("antiRoot");
                        if (c.has("antiXposed")) cfg.antiXposed = c.getBoolean("antiXposed");
                        LogStore.get().log(TAG, "config updated: " + body);
                    }
                    JSONObject o = new JSONObject();
                    o.put("ok", true);
                    o.put("sslBypass", Config.get().sslBypass);
                    o.put("okhttp", Config.get().okhttpCapture);
                    o.put("url", Config.get().urlCapture);
                    o.put("dns", Config.get().dnsCapture);
                    o.put("tcp", Config.get().tcpCapture);
                    o.put("classes", Config.get().classCapture);
                    o.put("classFilter", Config.get().classFilter);
                    o.put("classLogAll", Config.get().classLogAll);
                    o.put("bodyLimit", Config.get().bodyLimit);
                    o.put("logLimit", Config.get().logLimit); // v1.12
                    o.put("webView", Config.get().webViewCapture);
                    o.put("prefs", Config.get().prefsCapture);
                    o.put("sqlite", Config.get().sqliteCapture);
                    o.put("urlBuild", Config.get().urlBuildCapture);
                    o.put("logcat", Config.get().logcatCapture);
                    o.put("crypto", Config.get().cryptoCapture);
                    o.put("activity", Config.get().activityCapture);
                    o.put("json", Config.get().jsonCapture);
                    o.put("detailMode", Config.get().detailMode); // v1.6
                    o.put("env", Config.get().envCapture);       // v1.9
                    o.put("tls", Config.get().tlsCapture);
                    o.put("connect", Config.get().connectCapture);
                    o.put("cronet", Config.get().cronetCapture);
                    o.put("antiRoot", Config.get().antiRoot);     // v1.13
                    o.put("antiXposed", Config.get().antiXposed); // v1.13
                    return o.toString();
                }
                case "/api/classes": {
                    // ?filter= 关键字过滤；?logall=true 刷屏输出
                    // v1.6: filter 做 URL 解码（UI 端 Uri.encode 编码了中文/特殊字符）
                    String filter = "";
                    boolean logAll = false;
                    for (String kv : query.split("&")) {
                        if (kv.startsWith("filter=")) {
                            try {
                                filter = URLDecoder.decode(kv.substring(7), "UTF-8");
                            } catch (Throwable t) {
                                filter = kv.substring(7);
                            }
                        }
                        if (kv.startsWith("logall=true")) logAll = true;
                    }
                    if (!filter.isEmpty() || logAll) {
                        Config cfg = Config.get();
                        cfg.classFilter = filter;
                        cfg.classLogAll = logAll;
                        LogStore.get().log(TAG, "classFilter=" + filter + " logAll=" + logAll);
                    }
                    return clsProbe.list(filter);
                }
                case "/api/scan": {
                    JSONObject c = new JSONObject(body);
                    String cls = c.optString("class", "");
                    return mth.scanClass(cls);
                }
                case "/api/hook": {
                    JSONObject c = new JSONObject(body);
                    String cls = c.optString("class", "");
                    String methodName = c.optString("method", "");
                    String params = c.optString("params", "");
                    // P1-4: hook 成功后写入 Config.hooks（ModuleMain re-hook 依赖它）
                    String resp = mth.hookMethod(cls, methodName, params);
                    JSONObject r = new JSONObject(resp);
                    if (r.optBoolean("ok", false) && r.optInt("hooked", 0) > 0) {
                        Config.HookSpec spec = new Config.HookSpec(cls, methodName, params);
                        Config.get().addHook(spec);
                        // v1.6: 持久化规则（进程重启自动重挂）
                        if (rulesPrefs != null) Config.get().saveRules(rulesPrefs);
                    }
                    return resp;
                }
                case "/api/unhook": {
                    JSONObject c = new JSONObject(body);
                    String cls = c.optString("class", "");
                    String methodName = c.optString("method", "");
                    String params = c.optString("params", "");
                    // 从 Config.hooks 移除（下次 re-hook 不再挂），并尽力 unhook 内存句柄
                    boolean removed = Config.get().removeHook(cls, methodName, params);
                    int unhooked = 0;
                    try {
                        JSONObject ur = new JSONObject(mth.unhookMethod(cls, methodName, params));
                        unhooked = ur.optInt("unhooked", 0);
                    } catch (Throwable t) { }
                    // v1.6: 持久化（卸载后规则同步落盘）
                    if (rulesPrefs != null) Config.get().saveRules(rulesPrefs);
                    JSONObject o = new JSONObject();
                    o.put("ok", true);
                    o.put("removedFromConfig", removed);
                    o.put("unhooked", unhooked);
                    LogStore.get().log(TAG, "[unhook] " + cls + "." + methodName + " cfg=" + removed + " handles=" + unhooked);
                    return o.toString();
                }
                case "/api/hooks": {
                    JSONArray arr = new JSONArray();
                    for (Config.HookSpec spec : Config.get().hooks) {
                        if (!spec.enabled) continue;
                        JSONObject o = new JSONObject();
                        o.put("class", spec.className);
                        o.put("method", spec.methodName);
                        o.put("params", spec.paramTypes);
                        arr.put(o);
                    }
                    JSONObject o = new JSONObject();
                    o.put("ok", true);
                    o.put("hooks", arr);
                    return o.toString();
                }
                case "/api/hijack": {
                    // v1.13: POST {"class","method","params","mode","value","paramValue","fieldName","fieldType","fieldValue"}
                    // mode: 0=返回值 1=参数值 2=拦截执行 3=静态变量 4=记录参数 5=记录返回 6=记录两者
                    // value 为 JSON null 则取消（匹配 class#method(params)+mode）
                    JSONObject c = new JSONObject(body);
                    String cls = c.optString("class", "");
                    String methodName = c.optString("method", "");
                    String params = c.optString("params", "");
                    if (c.isNull("value")) {
                        boolean removed = Config.get().removeHijack(cls, methodName, params);
                        LogStore.get().log(TAG, "[hijack] removed " + cls + "." + methodName + " removed=" + removed);
                        if (rulesPrefs != null) Config.get().saveRules(rulesPrefs); // v1.6
                        JSONObject ro = new JSONObject();
                        ro.put("ok", true);
                        ro.put("removed", removed);
                        return ro.toString();
                    }
                    int mode = c.optInt("mode", Config.MODE_RETURN);
                    String value = c.optString("value", "");
                    String paramValue = c.optString("paramValue", "");
                    String fieldName = c.optString("fieldName", "");
                    String fieldType = c.optString("fieldType", "");
                    String fieldValue = c.optString("fieldValue", "");
                    Config.get().addRule(cls, methodName, params, mode, value, paramValue, fieldName, fieldType, fieldValue);
                    LogStore.get().log(TAG, "[hijack] " + cls + "." + methodName + "(" + params + ") mode=" + mode
                            + " value=" + value + " pv=" + paramValue + " f=" + fieldName + ":" + fieldType + "=" + fieldValue);
                    if (rulesPrefs != null) Config.get().saveRules(rulesPrefs); // v1.6
                    JSONObject o = new JSONObject();
                    o.put("ok", true);
                    o.put("class", cls);
                    o.put("method", methodName);
                    o.put("mode", mode);
                    o.put("value", value);
                    return o.toString();
                }
                case "/api/hijacks": {
                    JSONArray arr = new JSONArray();
                    for (Config.HijackRule h : Config.get().hijacks) {
                        JSONObject o = new JSONObject();
                        o.put("class", h.className);
                        o.put("method", h.methodName);
                        o.put("params", h.paramTypes);
                        o.put("mode", h.mode);
                        o.put("value", h.returnValue);
                        o.put("paramValue", h.paramValue);
                        o.put("fieldName", h.fieldName);
                        o.put("fieldType", h.fieldType);
                        o.put("fieldValue", h.fieldValue);
                        arr.put(o);
                    }
                    JSONObject o = new JSONObject();
                    o.put("ok", true);
                    o.put("hijacks", arr);
                    return o.toString();
                }
                case "/api/dexdump": { // v1.9: 导出全部 dex
                    String r = dexKit != null ? dexKit.dumpDex() : "{\"ok\":false,\"error\":\"dexkit null\"}";
                    return r;
                }
                case "/api/stringfind": { // v1.9: 字符串反查方法
                    JSONObject c = new JSONObject(body);
                    String str = c.optString("str", "");
                    String r = dexKit != null ? dexKit.findMethods(str) : "{\"ok\":false,\"error\":\"dexkit null\"}";
                    return r;
                }
                case "/api/dexclose": { // v1.9: 释放 DexKit bridge
                    if (dexKit != null) dexKit.close();
                    JSONObject o = new JSONObject();
                    o.put("ok", true);
                    return o.toString();
                }
                case "/api/clear": {
                    LogStore.get().clear();
                    JSONObject o = new JSONObject();
                    o.put("ok", true);
                    return o.toString();
                }
                default: {
                    JSONObject o = new JSONObject();
                    o.put("ok", false);
                    o.put("error", "unknown path: " + p);
                    return o.toString();
                }
            }
        } catch (Throwable t) {
            JSONObject o = new JSONObject();
            o.put("ok", false);
            o.put("error", t.toString());
            return o.toString();
        }
    }
}
