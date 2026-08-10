package com.dustinky.spyprobe;

import org.json.JSONArray;
import org.json.JSONObject;

import java.lang.reflect.Method;
import java.util.Iterator;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * v1.40 P1: OkHttp 请求重放（OkHttpLogger-Frida / poker 借鉴）
 *
 * 在 OkHttpClient.newCall(Request) 处拦截，缓存每个请求的 call.clone()（clone 可重复执行，
 * 原 call 只能执行一次）+ 摘要（method/url/body 前 200 字符）。用户可从 UI「请求重放」
 * 页选择一条重放，重放在新线程执行 call.clone().execute()，结果写回日志流。
 *
 * 设计约束（poker 同款限制）：
 *   - GET / 无 body 请求重放 100% 可靠（clone 的 Request 完整复用）
 *   - POST 等含 body 请求：okhttp RequestBody 是 one-shot（writeTo 只能调一次），
 *     clone 的 call 共享原 RequestBody，第二次 writeTo 会抛异常/空 body——
 *     重放结果以实际日志为准，body 失败会记录 [Replay] FAIL 提示
 *   - 缓存上限 50 条环形（防内存膨胀）
 */
public class OkHttpReplay {

    static final String TAG = "SpyProbe.Replay";

    private static final int MAX = 50;
    private static final int MAX_URL = 200;
    private static final int MAX_BODY_SUMMARY = 200;

    public static class Entry {
        public final long id;
        public final long time;
        public final String method;
        public final String url;
        public final String bodySummary;
        public final Object call; // call.clone() 缓存（可重复执行）

        Entry(long id, long time, String method, String url, String bodySummary, Object call) {
            this.id = id;
            this.time = time;
            this.method = method;
            this.url = url;
            this.bodySummary = bodySummary;
            this.call = call;
        }
    }

    private static final OkHttpReplay INSTANCE = new OkHttpReplay();
    public static OkHttpReplay get() { return INSTANCE; }

    private final CopyOnWriteArrayList<Entry> entries = new CopyOnWriteArrayList<>();
    private long nextId = 1;

    private OkHttpReplay() { }

    /**
     * newCall hook 回调：缓存可重放 call + 摘要。
     * @param call   OkHttpClient.newCall 返回的 Call（App 将执行，这里只 clone 缓存）
     * @param req    Request 参数（可为 null）
     * @param logReq true = 同时打印请求日志（P0 混淆场景：RealInterceptorChain 链 hook 失败，
     *               这里作为请求记录兜底）；false = 仅缓存（正常场景，链 hook 已记录，避免双记录）
     */
    public void onNewCall(Object call, Object req, boolean logReq) {
        String method = "?";
        String url = "?";
        String body = "";
        try {
            if (req != null) {
                Method m = req.getClass().getMethod("method");
                Method u = req.getClass().getMethod("url");
                Object mv = m.invoke(req);
                Object uv = u.invoke(req);
                if (mv != null) method = mv.toString();
                if (uv != null) url = uv.toString();
                // body 摘要（防 one-shot 被读坏，只取前 200 字符）
                try {
                    Method b = req.getClass().getMethod("body");
                    Object bodyObj = b.invoke(req);
                    if (bodyObj != null) {
                        Method bufM = bodyObj.getClass().getMethod("buffer");
                        Object buf = bufM.invoke(bodyObj);
                        if (buf != null) {
                            Method utf8 = buf.getClass().getMethod("utf8");
                            Object s = utf8.invoke(buf);
                            if (s != null) {
                                String bs = s.toString();
                                if (bs.length() > MAX_BODY_SUMMARY) {
                                    bs = bs.substring(0, MAX_BODY_SUMMARY) + "...(" + bs.length() + "B)";
                                }
                                body = bs;
                            }
                        }
                    }
                } catch (Throwable t) { /* one-shot body 已消费/无 body */ }
            }
        } catch (Throwable t) {
            DebugLog.get().log("Replay", "onNewCall parse fail: " + t);
        }
        if (url.length() > MAX_URL) url = url.substring(0, MAX_URL) + "...";

        // 缓存 clone（clone 失败 = 该 call 不支持克隆，跳过缓存）
        Object clone = null;
        try {
            Method cloneM = call.getClass().getMethod("clone");
            clone = cloneM.invoke(call);
        } catch (Throwable t) {
            DebugLog.get().log("Replay", "clone fail: " + t);
        }

        final Entry e = new Entry(nextId++, System.currentTimeMillis(), method, url, body, clone);
        entries.add(e);
        while (entries.size() > MAX) entries.remove(0);

        if (logReq) {
            StringBuilder sb = new StringBuilder();
            sb.append("[Replay#").append(e.id).append("] >>> ").append(method).append(" ").append(url);
            if (!body.isEmpty()) {
                sb.append("\n    reqBody: ").append(body.replace("\n", "\n    "));
            }
            LogStore.get().log(TAG, sb.toString());
        }
    }

    /** 缓存列表 JSON（UI 展示） */
    public String listJson() {
        try {
            JSONObject o = new JSONObject();
            o.put("ok", true);
            o.put("count", entries.size());
            JSONArray arr = new JSONArray();
            for (Entry e : entries) {
                JSONObject j = new JSONObject();
                j.put("id", e.id);
                j.put("time", e.time);
                j.put("method", e.method);
                j.put("url", e.url);
                j.put("body", e.bodySummary);
                arr.put(j);
            }
            o.put("items", arr);
            return o.toString();
        } catch (Throwable t) {
            return "{\"ok\":false,\"error\":\"" + t + "\"}";
        }
    }

    /** 重放第 id 条（新线程执行，结果写日志流） */
    public void replay(final long id) {
        Entry target = null;
        for (Entry e : entries) {
            if (e.id == id) { target = e; break; }
        }
        if (target == null) {
            LogStore.get().log(TAG, "[Replay#" + id + "] !!! 未找到缓存请求（可能已被清空/环形淘汰）");
            return;
        }
        if (target.call == null) {
            LogStore.get().log(TAG, "[Replay#" + id + "] !!! 该请求不可重放（clone 失败，可能 body 已被消费）");
            return;
        }
        final Entry e = target;
        Thread th = new Thread(() -> {
            long t0 = System.currentTimeMillis();
            LogStore.get().log(TAG, "[Replay#" + e.id + "] 重放开始: " + e.method + " " + e.url + " (call.clone().execute)");
            try {
                Object clone = e.call;
                // 再次 clone：缓存条目是"可重放的模板"，每次重放再 clone 一次，避免同一模板二次执行
                Method cloneM = clone.getClass().getMethod("clone");
                Object fresh = cloneM.invoke(clone);
                Method exec = fresh.getClass().getMethod("execute");
                Object resp = exec.invoke(fresh);
                StringBuilder sb = new StringBuilder();
                sb.append("[Replay#").append(e.id).append("] <<< 完成 ").append((System.currentTimeMillis() - t0)).append("ms");
                try {
                    if (resp != null) {
                        Method codeM = resp.getClass().getMethod("code");
                        Method msgM = resp.getClass().getMethod("message");
                        Object code = codeM.invoke(resp);
                        Object msg = msgM.invoke(resp);
                        sb.append(" ").append(code).append(" ").append(msg);
                        // 响应 body 摘要（peekBody 不消费流）
                        try {
                            Method peek = resp.getClass().getMethod("peekBody", long.class);
                            Object pbody = peek.invoke(resp, 512L);
                            if (pbody != null) {
                                Method strM = pbody.getClass().getMethod("string");
                                Object s = strM.invoke(pbody);
                                if (s != null) {
                                    String bs = s.toString();
                                    if (bs.length() > 256) bs = bs.substring(0, 256) + "...(" + bs.length() + "B)";
                                    sb.append("\n    body: ").append(bs.replace("\n", "\n    "));
                                }
                            }
                        } catch (Throwable t2) { }
                    }
                } catch (Throwable t2) {
                    sb.append(" resp-parse: ").append(t2);
                }
                LogStore.get().log(TAG, sb.toString());
            } catch (Throwable t) {
                LogStore.get().log(TAG, "[Replay#" + e.id + "] !!! 重放失败: " + t);
                DebugLog.get().log("Replay", "replay fail id=" + e.id + ": " + t);
            }
        }, "SpyProbe-Replay-" + id);
        th.setDaemon(true);
        th.start();
    }

    public void clear() {
        entries.clear();
        LogStore.get().log(TAG, "重放缓存已清空");
    }

    /** 供日志清理：清空（内部用） */
    public int size() { return entries.size(); }

    /** 迭代器导出（调试用） */
    public Iterator<Entry> iterator() { return entries.iterator(); }
}
