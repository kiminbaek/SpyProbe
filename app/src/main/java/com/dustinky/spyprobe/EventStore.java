package com.dustinky.spyprobe;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/**
 * v1.55: 通用结构化事件环形缓冲（目标进程内）
 *
 * 各 Probe（SQLite/Json/Crypto/Net/Env/Url）捕获时调用 {@link #add} 写结构化事件；
 * 日志行同时嵌入 [EVT#id] 标记（UI 靠它关联渲染卡片）。
 * 与 HttpStore 同构：环形上限 {@link #MAX} 防膨胀，批量推送主进程 9900 /api/push_event 落盘。
 *
 * 线程安全：写多读少，lock 保护 + AtomicLong id。
 */
public class EventStore {

    private static final int MAX = 500;

    private static final EventStore INSTANCE = new EventStore();
    public static EventStore get() { return INSTANCE; }

    private final List<SpyEvent> events = new ArrayList<>();
    private final Object lock = new Object();
    private final java.util.concurrent.atomic.AtomicLong nextId = new java.util.concurrent.atomic.AtomicLong(1);

    private boolean pushHome = false;
    private String pushToken = "";
    private java.util.function.Supplier<String> pushTokenProvider = null;

    private EventStore() { }

    /** 启用推送（与 HttpStore.enablePush 同构：目标进程把结构化事件推回主进程） */
    public void enablePush(String token, java.util.function.Supplier<String> tokenProvider) {
        synchronized (lock) {
            if (pushHome) return;
            this.pushToken = token == null ? "" : token;
            this.pushTokenProvider = tokenProvider;
            pushHome = true;
        }
        Thread t = new Thread(this::pushLoop, "SpyProbe-PushEvent");
        t.setDaemon(true);
        t.start();
    }

    public long nextId() { return nextId.getAndIncrement(); }

    /** 新事件入队（返回分配 id；日志行 [EVT#id] 用它） */
    public long add(SpyEvent e) {
        synchronized (lock) {
            events.add(e);
            while (events.size() > MAX) events.remove(0);
            return e.id;
        }
    }

    /** 按 id 查（未找到返回 null） */
    public SpyEvent find(long id) {
        synchronized (lock) {
            for (SpyEvent e : events) {
                if (e.id == id) return e;
            }
            return null;
        }
    }

    /** 全部（供推送批量取出） */
    public List<SpyEvent> snapshot() {
        synchronized (lock) {
            return new ArrayList<>(events);
        }
    }

    public int size() {
        synchronized (lock) { return events.size(); }
    }

    /** 推送循环：有更新事件 → 批量推主进程（id 游标，与 HttpStore.pushLoop 同构） */
    private void pushLoop() {
        long lastPushedId = 0;
        long backoffMs = 0;
        while (true) {
            try {
                Thread.sleep(2000);
                if (!pushHome) continue;
                List<SpyEvent> snap;
                synchronized (lock) {
                    snap = new ArrayList<>(events);
                }
                List<SpyEvent> fresh = new ArrayList<>();
                for (SpyEvent e : snap) {
                    if (e.id > lastPushedId) fresh.add(e);
                }
                if (fresh.isEmpty()) {
                    backoffMs = 0;
                    continue;
                }
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
                DebugLog.get().logNoMirror("EventStore", "pushLoop err: " + t);
            }
        }
    }

    /** 批量推送；返回是否成功（200 才算成功） */
    private boolean pushBatch(List<SpyEvent> batch) {
        try {
            JSONObject payload = new JSONObject();
            JSONArray arr = new JSONArray();
            for (SpyEvent e : batch) arr.put(e.toJson());
            payload.put("entries", arr);
            String body = payload.toString();

            String host = "127.0.0.1:9900";
            StringBuilder head = new StringBuilder();
            head.append("POST /api/push_event HTTP/1.1\r\n");
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
            if (!ok) {
                DebugLog.get().logNoMirror("EventStore", "push " + batch.size() + " -> " + statusLine.replace("\r\n", " "));
            }
            return ok;
        } catch (Throwable t) {
            DebugLog.get().logNoMirror("EventStore", "push FAIL: " + t);
            return false;
        }
    }
}
