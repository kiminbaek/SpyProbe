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
 *   GET  /api/history/days        -> 历史日期列表
 *   GET  /api/history?day=Y-M-D&max=N -> 某天历史日志
 *   POST /api/history/clear       -> {"day":..|null} 清空历史（null=全清）
 *   GET  /api/debuglog            -> 目标进程 DebugLog 文本
 *   GET  /api/classes?filter=..   -> 类加载记录（ClassLoadProbe）
 *   POST /api/config              -> {"sslBypass":..,"okhttp":..,"url":..,"bodyLimit":..}
 *   GET  /api/config              -> 当前配置
 *   POST /api/scan                -> {"class":"com.xxx.Cls"} 枚举方法+字段
 *   POST /api/hook                -> {"class":..,"method":..,"params":..} 动态 hook
 *   POST /api/unhook              -> {"class":..,"method":..,"params":..} 卸载 hook
 *   GET  /api/hooks               -> 当前已 hook 列表
 *   POST /api/hijack              -> 方法返回劫持
 *   GET  /api/hijacks             -> 劫持列表
 *   POST /api/dexdump             -> 导出 DEX
 *   POST /api/stringfind          -> {"s":..} 字符串反查
 *   POST /api/dexclose            -> 释放 DexKit
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
    private final String expectedToken; // v1.47 P1-3: 9901 控制面鉴权（与 9900 同 token；空=兼容老主进程/未初始化不校验）
    private final java.io.File cfgFile; // v1.22: 抓包开关持久化文件（目标 App data 目录）
    private final java.io.File rulesFile; // v1.25 P2-9: 规则持久化文件（与 cfgFile 同目录，零 IPC）
    private final DexKitProbe dexKit; // v1.9: DexKit（导出 dex / 字符串反查）
    private volatile ServerSocket serverSocket;
    private volatile Thread acceptThread;
    private volatile int actualPort = PORT; // v1.3: 实际绑定端口（多进程 app 时可能偏移）
    // v1.31.1 P3-4: /api/ping 版本信息缓存（避免每连接反射 getPackageInfo；首次成功后缓存）
    private volatile String cachedVersionName = null;
    private volatile int cachedVersionCode = -1;
    private volatile int cachedTargetSdk = -1;

    public SpyServer(NetProbe net, MethodProbe mth, ClassLoadProbe clsProbe, String pkg,
                     DexKitProbe dexKit, java.io.File cfgFile, String expectedToken) {
        this.net = net;
        this.mth = mth;
        this.clsProbe = clsProbe;
        this.pkg = pkg;
        this.dexKit = dexKit; // v1.9
        this.cfgFile = cfgFile; // v1.22
        this.expectedToken = expectedToken == null ? "" : expectedToken; // v1.47 P1-3
        // v1.25 P2-9: 规则文件与抓包开关同目录（files/spyprobe_rules.json）
        this.rulesFile = (cfgFile != null && cfgFile.getParentFile() != null)
                ? new java.io.File(cfgFile.getParentFile(), "spyprobe_rules.json") : null;
    }

    public void start() {
        // v1.3: 多进程 app / 多目标勾选时 9901 可能被占用 → 依次尝试 9901-9910
        // v1.30.2: 每次绑定尝试都写 DebugLog（端口被占/绑定失败原因直接可见）
        for (int attempt = 0; attempt < 10; attempt++) {
            int p = PORT + attempt;
            try {
                serverSocket = new ServerSocket(p, 50, InetAddress.getByName("127.0.0.1"));
                actualPort = p;
                acceptThread = new Thread(this::acceptLoop, "SpyProbe-Server");
                acceptThread.setDaemon(true);
                acceptThread.start();
                LogStore.get().log(TAG, "server started on 127.0.0.1:" + p + " pkg=" + pkg);
                DebugLog.get().logNoMirror("Srv", "start OK 127.0.0.1:" + p + " pkg=" + pkg);
                return;
            } catch (Throwable t) {
                LogStore.get().log(TAG, "port " + p + " busy, try next");
                DebugLog.get().logNoMirror("Srv", "port " + p + " bind fail: " + t);
            }
        }
        LogStore.get().log(TAG, "server start fail: all ports 9901-9910 busy");
        DebugLog.get().logNoMirror("Srv", "start FAIL: all ports 9901-9910 busy");
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
        // v1.36 P2-9: 去掉冗余 `Socket sock = s`（同一对象重复引用，直接用 s）
        try (InputStream in = s.getInputStream();
             OutputStream out = s.getOutputStream();
             BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {

            String reqLine = r.readLine();
            if (reqLine == null) return;
            String[] parts = reqLine.split(" ");
            if (parts.length < 2) return;
            String method = parts[0];
            String path = parts[1];
            long t0 = System.currentTimeMillis(); // v1.30.2: 请求耗时统计

            // 读 headers 找 Content-Length（P1-13: 限制 1MB 防 OOM）+ X-Spy-Token（v1.47 P1-3 鉴权）
            int contentLength = 0;
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

            // v1.47 P1-3: 9901 控制面鉴权——expectedToken 非空（目标进程已拿到主进程 token）时全部路由校验，
            //   不匹配返回 401（防本机任意 App 枚举 9901-9910 篡改 hook/导出 dex）。
            //   兼容：主进程 UI 未开（9900 不在线）→ remoteToken 拿不到 → expectedToken 空 → 不校验（与 9900 同策略）
            if (!expectedToken.isEmpty() && !expectedToken.equals(reqToken)) {
                DebugLog.get().logNoMirror("Srv", method + " " + path + " -> 401 unauthorized (token mismatch)");
                byte[] deny = "{\"ok\":false,\"err\":\"unauthorized\"}".getBytes(StandardCharsets.UTF_8);
                StringBuilder hd = new StringBuilder();
                hd.append("HTTP/1.1 401 Unauthorized\r\n");
                hd.append("Content-Type: application/json; charset=utf-8\r\n");
                hd.append("Content-Length: ").append(deny.length).append("\r\n");
                hd.append("Connection: close\r\n\r\n");
                out.write(hd.toString().getBytes(StandardCharsets.UTF_8));
                out.write(deny);
                out.flush();
                return;
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
            // v1.30.2: 每个 API 请求都写 DebugLog（方法/路径/耗时/响应大小/是否 ok），定位前端问题最直接
            // v1.51.1: 改 logNoMirror——9901 控制面是 SpyProbe 自家心跳/控制通道（主进程每 500ms ping 一次），
            //   镜像进 LogStore 会产生 [Dbg] [Srv] GET /api/ping 刷屏污染业务日志流。logNoMirror 仍落 DebugLog 文件可排障。
            long ms = System.currentTimeMillis() - t0;
            boolean okFlag = resp.contains("\"ok\":true");
            DebugLog.get().logNoMirror("Srv", method + " " + path + " -> " + resp.length() + "B " + ms + "ms ok=" + okFlag
                    + (okFlag ? "" : " resp=" + resp.substring(0, Math.min(resp.length(), 300))));
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

            // v1.47 P2-7: 写操作强制 POST（GET 浏览器直访/误触也会触发副作用）。
            //   /api/config 已按 method 区分读写；/api/history/clear、/api/replay/clear 已单独校验（保留）
            switch (p) {
                case "/api/flush_pcap":
                case "/api/scan":
                case "/api/hook":
                case "/api/unhook":
                case "/api/hijack":
                case "/api/dexdump":
                case "/api/dexclose":
                case "/api/replay":
                case "/api/clear":
                    if (!"POST".equals(method)) {
                        JSONObject o = new JSONObject();
                        o.put("ok", false);
                        o.put("error", "method not allowed, use POST");
                        return o.toString();
                    }
                    break;
                default:
                    break;
            }

            switch (p) {
                // v1.39 P0: 目标进程把活跃 pcap 会话 flush 到主进程（UI「导出 pcap」先调这个，在线时兜底）
                case "/api/flush_pcap": {
                    PcapWriter.get().flushAll();
                    JSONObject o = new JSONObject();
                    o.put("ok", true);
                    return o.toString();
                }
                case "/api/ping": {                    JSONObject o = new JSONObject();
                    o.put("ok", true);
                    o.put("pkg", pkg);
                    o.put("port", actualPort);
                    o.put("logCount", LogStore.get().size());
                    o.put("classCount", clsProbe.size());
                    // v1.2: app 版本信息（版本判断/加固识别用）ActivityThread 是 @hide，反射获取
                    // v1.31.1 P3-4: 缓存版本信息（高频轮询下避免每连接反射 getPackageInfo）
                    if (cachedVersionName == null) {
                        try {
                            Class<?> at = Class.forName("android.app.ActivityThread");
                            Object app = at.getMethod("currentApplication").invoke(null);
                            if (app != null) {
                                Object pm = app.getClass().getMethod("getPackageManager").invoke(app);
                                if (pm != null) {
                                    android.content.pm.PackageInfo pi = ((android.content.pm.PackageManager) pm).getPackageInfo(pkg, 0);
                                    cachedVersionName = pi.versionName;
                                    cachedVersionCode = pi.versionCode;
                                    if (android.os.Build.VERSION.SDK_INT >= 28) {
                                        cachedTargetSdk = pi.applicationInfo.targetSdkVersion;
                                    }
                                }
                            }
                        } catch (Throwable t) { }
                    }
                    if (cachedVersionName != null) {
                        o.put("versionName", cachedVersionName);
                        o.put("versionCode", cachedVersionCode);
                        if (cachedTargetSdk >= 0) o.put("targetSdk", cachedTargetSdk);
                    }
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
                    // v1.27: ?day=YYYY-MM-DD 导出历史某天（不带 day = 内存全量，兼容旧版）
                    // v1.35 P2-1: 统一 formatLine（tag 右对齐 + msg 单行）
                    String day = getQueryParam(query, "day", "");
                    StringBuilder sb = new StringBuilder();
                    if (!day.isEmpty()) {
                        // v1.28 P1: 历史导出同样限制条数（readDay 环形截断保留最新 5000），防止超大日志 OOM/超时
                        List<LogPersister.Entry> all = LogPersister.get().readDay(day, 5000);
                        for (LogPersister.Entry e : all) {
                            sb.append(com.dustinky.spyprobe.util.ShareLogUtil.INSTANCE.formatLine(e.time, e.tag, e.msg)).append('\n');
                        }
                    } else {
                        // v1.26 P0-3: 导出限制最近 3000 条（日志含 body 可能极大，全量拼接超时/OOM）
                        List<LogStore.Entry> all = LogStore.get().all();
                        int from = Math.max(0, all.size() - 3000);
                        for (int i = from; i < all.size(); i++) {
                            LogStore.Entry e = all.get(i);
                            sb.append(com.dustinky.spyprobe.util.ShareLogUtil.INSTANCE.formatLine(e.time, e.tag, e.msg)).append('\n');
                        }
                    }
                    JSONObject o = new JSONObject();
                    o.put("ok", true);
                    o.put("text", sb.toString());
                    return o.toString();
                }
                // v1.29: 独立调试日志（排查"历史无记录/导出失败/重启丢日志"）
                case "/api/debuglog": {
                    JSONObject o = new JSONObject();
                    o.put("ok", true);
                    o.put("init", LogPersister.get().isInitialized());
                    o.put("dir", LogPersister.get().dirPath());
                    o.put("text", DebugLog.get().dump());
                    return o.toString();
                }
                // v1.27: 历史日志（落盘文件）
                case "/api/history/days": {
                    JSONObject o = new JSONObject();
                    o.put("ok", true);
                    JSONArray arr = new JSONArray();
                    for (String d : LogPersister.get().days()) arr.put(d);
                    o.put("days", arr);
                    return o.toString();
                }
                case "/api/history": {
                    String day = getQueryParam(query, "day", "");
                    // v1.31.1 P3-3: max 加下限 clamp（手输 max=0 会读全部文件）
                    int max = Math.max(1, parseIntSafe(getQueryParam(query, "max", "5000"), 5000));
                    List<LogPersister.Entry> entries = LogPersister.get().readDay(day, max);
                    JSONArray arr = new JSONArray();
                    for (LogPersister.Entry e : entries) {
                        JSONObject j = new JSONObject();
                        j.put("seq", e.seq);
                        j.put("t", e.time);
                        j.put("tag", e.tag);
                        j.put("m", e.msg);
                        arr.put(j);
                    }
                    JSONObject o = new JSONObject();
                    o.put("ok", true);
                    o.put("day", day);
                    o.put("logs", arr);
                    return o.toString();
                }
                case "/api/history/clear": {
                    // POST /api/history/clear?day=YYYY-MM-DD（不带 day = 清全部历史）
                    // v1.28 P2: GET 浏览器直接访问也会触发删除，强制校验 POST
                    if (!"POST".equals(method)) {
                        JSONObject o = new JSONObject();
                        o.put("ok", false);
                        o.put("error", "method not allowed");
                        return o.toString();
                    }
                    String day = getQueryParam(query, "day", "");
                    LogPersister.get().clear(day.isEmpty() ? null : day);
                    JSONObject o = new JSONObject();
                    o.put("ok", true);
                    return o.toString();
                }
                case "/api/config": {
                    // v1.42 P2-5: 统一走 Config.toJsonObject/applyJson（单一事实来源 32 字段）——
                    //   旧实现手工逐字段 if/put，keystore/webViewDebug/keylog/pcap 4 个新字段漏同步。
                    if ("POST".equals(method)) {
                        Config cfg = Config.get();
                        if (body != null && !body.isEmpty()) {
                            cfg.applyJson(body);
                            LogStore.get().log(TAG, "config updated: " + body);
                            // v1.22: 开关持久化到目标 App data 目录文件（零 IPC）；v1.21 远程偏好实测失效已弃用
                            cfg.saveConfig(cfgFile);
                        }
                    }
                    return Config.get().toJson().toString();
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
                    // v1.28 P1: params 缺省(null)=全部重载；""=无参精确；签名串=精确（此前空串恒被当全部重载）
                    String params = c.has("params") ? c.optString("params", "") : null;
                    // P1-4: hook 成功后写入 Config.hooks（ModuleMain re-hook 依赖它）
                    String resp = mth.hookMethod(cls, methodName, params);
                    JSONObject r = new JSONObject(resp);
                    if (r.optBoolean("ok", false) && r.optInt("hooked", 0) > 0) {
                        Config.HookSpec spec = new Config.HookSpec(cls, methodName, params);
                        Config.get().addHook(spec);
                        // v1.6: 持久化规则（进程重启自动重挂）
                        if (rulesFile != null) Config.get().saveRules(rulesFile);
                    }
                    return resp;
                }
                case "/api/unhook": {
                    JSONObject c = new JSONObject(body);
                    String cls = c.optString("class", "");
                    String methodName = c.optString("method", "");
                    // v1.28 P1: 同上语义；卸载时空串仍按通配全部重载（unhookHandles 内部 null/空=通配）
                    String params = c.has("params") ? c.optString("params", "") : null;
                    // v1.16 P0-1: 先真正 unhook 内存句柄拿真实计数，再清 Config.hooks 记录
                    // （此前 removeHook 先跑把 map 清空，unhookMethod 恒返回 0）
                    int unhooked = 0;
                    try {
                        JSONObject ur = new JSONObject(mth.unhookMethod(cls, methodName, params));
                        unhooked = ur.optInt("unhooked", 0);
                    } catch (Throwable t) { }
                    boolean removed = Config.get().removeHook(cls, methodName, params);

                    // v1.6: 持久化（卸载后规则同步落盘）
                    if (rulesFile != null) Config.get().saveRules(rulesFile);
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
                        if (rulesFile != null) Config.get().saveRules(rulesFile); // v1.6
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
                    if (rulesFile != null) Config.get().saveRules(rulesFile); // v1.6
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
                case "/api/classfind": { // v1.38 P2-8: 类名模糊搜索 → 自动生成 hook 清单
                    JSONObject c = new JSONObject(body);
                    String pat = c.optString("pattern", "");
                    String r = dexKit != null ? dexKit.findClassMethods(pat) : "{\"ok\":false,\"error\":\"dexkit null\"}";
                    return r;
                }
                case "/api/dexclose": { // v1.9: 释放 DexKit bridge
                    if (dexKit != null) dexKit.close();
                    JSONObject o = new JSONObject();
                    o.put("ok", true);
                    return o.toString();
                }
                // v1.40 P1: 请求重放（OkHttpLogger-Frida/poker 借鉴）—— newCall hook 缓存的请求
                case "/api/replay/history": {
                    return OkHttpReplay.get().listJson();
                }
                case "/api/replay": {
                    // POST /api/replay?index=N（index 缺省取 0？NO——强制要求 index，防误重放）
                    if (!"POST".equals(method)) {
                        JSONObject o = new JSONObject();
                        o.put("ok", false);
                        o.put("error", "method not allowed");
                        return o.toString();
                    }
                    long idx = parseIntSafe(getQueryParam(query, "index", "-1"), -1);
                    if (idx < 0) {
                        JSONObject o = new JSONObject();
                        o.put("ok", false);
                        o.put("error", "index required (POST /api/replay?index=N)");
                        return o.toString();
                    }
                    OkHttpReplay.get().replay(idx);
                    JSONObject o = new JSONObject();
                    o.put("ok", true);
                    o.put("id", idx);
                    return o.toString();
                }
                case "/api/replay/clear": {
                    if (!"POST".equals(method)) {
                        JSONObject o = new JSONObject();
                        o.put("ok", false);
                        o.put("error", "method not allowed");
                        return o.toString();
                    }
                    OkHttpReplay.get().clear();
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

    // v1.27: query 参数解析（URL 解码）
    private static String getQueryParam(String query, String key, String def) {
        if (query == null || query.isEmpty()) return def;
        for (String kv : query.split("&")) {
            int eq = kv.indexOf('=');
            if (eq > 0 && kv.substring(0, eq).equals(key)) {
                try {
                    return URLDecoder.decode(kv.substring(eq + 1), "UTF-8");
                } catch (Throwable t) {
                    return kv.substring(eq + 1);
                }
            }
        }
        return def;
    }

    private static int parseIntSafe(String s, int def) {
        try { return Integer.parseInt(s); } catch (Throwable t) { return def; }
    }
}
