package com.dustinky.spyprobe;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/**
 * v1.48: 结构化 HTTP 条目环形缓冲（目标进程内）
 *
 * NetProbe 捕获 OkHttp/HttpURLConnection 请求时写入；UI 点请求行时按 id 查询。
 * 上限 {@link #MAX} 条环形淘汰（防内存膨胀，与 OkHttpReplay 同思路）。
 * 与日志推送同链路：批量推送主进程落盘（http_entries/），主进程历史页可读。
 *
 * 线程安全：写多读少，lock 保护 + AtomicLong id。
 */
public class HttpStore {

    private static final int MAX = 100;

    private static final HttpStore INSTANCE = new HttpStore();
    public static HttpStore get() { return INSTANCE; }

    private final java.util.List<HttpEntry> entries = new ArrayList<>();
    private final Object lock = new Object();
    private final java.util.concurrent.atomic.AtomicLong nextId = new java.util.concurrent.atomic.AtomicLong(1);

    private boolean pushHome = false;
    private String pushToken = "";
    private java.util.function.Supplier<String> pushTokenProvider = null;

    private HttpStore() { }

    /** 启用推送（与 LogStore 同构：目标进程把结构化条目推回主进程） */
    public void enablePush(String token, java.util.function.Supplier<String> tokenProvider) {
        synchronized (lock) {
            if (pushHome) return;
            this.pushToken = token == null ? "" : token;
            this.pushTokenProvider = tokenProvider;
            pushHome = true;
        }
        Thread t = new Thread(this::pushLoop, "SpyProbe-PushHttp");
        t.setDaemon(true);
        t.start();
    }

    public long nextId() { return nextId.getAndIncrement(); }

    /** 新请求入队（返回分配 id） */
    public long add(HttpEntry e) {
        synchronized (lock) {
            entries.add(e);
            while (entries.size() > MAX) entries.remove(0);
            return e.id;
        }
    }

    /** 按 id 查（未找到返回 null） */
    public HttpEntry find(long id) {
        synchronized (lock) {
            for (HttpEntry e : entries) {
                if (e.id == id) return e;
            }
            return null;
        }
    }

    /** 全部（供推送批量取出） */
    public List<HttpEntry> snapshot() {
        synchronized (lock) {
            return new ArrayList<>(entries);
        }
    }

    public int size() {
        synchronized (lock) { return entries.size(); }
    }

    /** 推送循环：有更新条目 → 批量推主进程（与 LogStore.pushLoop 同构） */
    private void pushLoop() {
        // v1.50 P1-3: count 游标 → id 游标——环形淘汰 remove(0) 后列表前移，
        //   count 游标 subList(lastCount, size) 会漏推中间条目；id 全局唯一单调（LogStore seq），
        //   淘汰不影响 id 游标语义。
        long lastPushedId = 0;
        long backoffMs = 0; // v1.50 P2-12: 失败指数退避（9900 未起时不再每 2s 重推同批刷 DebugLog）
        while (true) {
            try {
                Thread.sleep(2000);
                if (!pushHome) continue;
                List<HttpEntry> snap;
                synchronized (lock) {
                    snap = new ArrayList<>(entries);
                }
                List<HttpEntry> fresh = new ArrayList<>();
                for (HttpEntry e : snap) {
                    if (e.id > lastPushedId) fresh.add(e);
                }
                if (fresh.isEmpty()) {
                    backoffMs = 0;
                    continue;
                }
                // push 成功才推进游标——失败（9900 未起/网络异常）时该批保留待重试
                if (pushBatch(fresh)) {
                    lastPushedId = fresh.get(fresh.size() - 1).id;
                    backoffMs = 0;
                } else {
                    long next = backoffMs == 0 ? 1000 : Math.min(backoffMs * 2, 30000);
                    backoffMs = next;
                    try { Thread.sleep(next); } catch (InterruptedException ie) { return; }
                }
            } catch (InterruptedException ie) {
                return;
            } catch (Throwable t) {
                DebugLog.get().logNoMirror("HttpStore", "pushLoop err: " + t);
            }
        }
    }

    /** 批量推送；返回是否成功（200 才算成功） */
    private boolean pushBatch(List<HttpEntry> batch) {
        try {
            JSONObject payload = new JSONObject();
            JSONArray arr = new JSONArray();
            for (HttpEntry e : batch) arr.put(e.toJson());
            payload.put("entries", arr);
            String body = payload.toString();

            String host = "127.0.0.1:9900";
            StringBuilder head = new StringBuilder();
            head.append("POST /api/push_http HTTP/1.1\r\n");
            head.append("Host: ").append(host).append("\r\n");
            head.append("Content-Type: application/json\r\n");
            head.append("Content-Length: ").append(body.getBytes("UTF-8").length).append("\r\n");
            if (pushTokenProvider != null && (pushToken == null || pushToken.isEmpty())) {
                String t = pushTokenProvider.get();
                if (t != null) pushToken = t;
            }
            if (!pushToken.isEmpty()) head.append("X-Spy-Token: ").append(pushToken).append("\r\n");
            head.append("\r\n");

            java.net.Socket sock = new java.net.Socket();
            sock.connect(new java.net.InetSocketAddress("127.0.0.1", 9900), 3000);
            sock.setSoTimeout(5000);
            java.io.OutputStream os = sock.getOutputStream();
            os.write(head.toString().getBytes("UTF-8"));
            os.write(body.getBytes("UTF-8"));
            os.flush();
            java.io.InputStream is = sock.getInputStream();
            byte[] buf = new byte[4096];
            int n = is.read(buf);
            String statusLine = n > 0 ? new String(buf, 0, Math.min(n, 80), "UTF-8") : "";
            sock.close();
            boolean ok = statusLine.contains("200");
            // v1.53.1: 成功也留痕（低频，2s 一次）——真机验证 REQ# 卡片链路是否打通
            if (ok) {
                DebugLog.get().logNoMirror("HttpStore", "push OK " + batch.size() + " entries");
            } else {
                DebugLog.get().logNoMirror("HttpStore", "push " + batch.size() + " -> " + statusLine.replace("\r\n", " "));
            }
            return ok;
        } catch (Throwable t) {
            DebugLog.get().logNoMirror("HttpStore", "push FAIL: " + t);
            return false;
        }
    }
}
