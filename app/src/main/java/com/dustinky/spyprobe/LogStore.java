package com.dustinky.spyprobe;

import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Date;
import java.util.Deque;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * 环形缓冲日志（hook 进程内，线程安全）
 * 供 SpyServer 增量拉取；超容量自动淘汰最旧。
 *
 * v1.6: 底层 ArrayList → ArrayDeque（淘汰最旧 remove(0) O(n) → pollFirst O(1)，
 * 高刷屏场景下 Log 写入不再随容量线性退化）。
 * v1.12: 容量可配置（Config.logLimit，默认 4096，范围 100-20000 由 SpyServer 限制）。
 */
public class LogStore {

    private final Deque<Entry> entries = new ArrayDeque<>();
    private long seq = 0;
    // v1.15 P2-8: SimpleDateFormat 非线程安全 → ThreadLocal（避免每次 log 重建 + 高并发格式化竞争）
    private static final ThreadLocal<SimpleDateFormat> FMT = new ThreadLocal<SimpleDateFormat>() {
        @Override
        protected SimpleDateFormat initialValue() {
            return new SimpleDateFormat("HH:mm:ss.SSS", Locale.US);
        }
    };

    public static class Entry {
        public final long seq;
        public final String time;
        public final String tag;
        public final String msg;

        Entry(long seq, String time, String tag, String msg) {
            this.seq = seq;
            this.time = time;
            this.tag = tag;
            this.msg = msg;
        }
    }

    private static final LogStore INSTANCE = new LogStore();
    public static LogStore get() { return INSTANCE; }

    // ===== v1.32: 推送主进程（SpyProbe 自己家）=====
    // 目标进程日志不落目标 App data，而是批量推回主进程 :9900 —— 主进程 LogPersister 写自己 files。
    // 仅目标进程启用（ModuleMain.enablePushHome）；主进程（UI）自身是接收端，不启用。
    private volatile boolean pushHome = false;
    private static final String HOME_URL = "http://127.0.0.1:9900/api/push_logs";
    private static final int PUSH_QUEUE_CAP = 4096;
    private static final int PUSH_BATCH = 50;
    private final ArrayBlockingQueue<String> pushQueue = new ArrayBlockingQueue<>(PUSH_QUEUE_CAP);

    public void enablePushHome() {
        if (pushHome) return;
        pushHome = true;
        Thread t = new Thread(this::pushLoop, "SpyProbe-PushHome");
        t.setDaemon(true);
        t.start();
    }

    private void pushLoop() {
        List<String> batch = new ArrayList<>();
        while (true) {
            try {
                String line = pushQueue.poll(200, TimeUnit.MILLISECONDS);
                if (line != null) {
                    batch.add(line);
                    if (batch.size() >= PUSH_BATCH) {
                        flushPush(batch);
                        batch = new ArrayList<>();
                    }
                } else if (!batch.isEmpty()) {
                    flushPush(batch);
                    batch = new ArrayList<>();
                }
            } catch (Throwable t) {
                batch.clear();
            }
        }
    }

    private void flushPush(List<String> batch) {
        try {
            StringBuilder sb = new StringBuilder("{\"entries\":[");
            for (int i = 0; i < batch.size(); i++) {
                if (i > 0) sb.append(',');
                sb.append(batch.get(i));
            }
            sb.append("]}");
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection)
                    new java.net.URL(HOME_URL).openConnection();
            conn.setConnectTimeout(500);
            conn.setReadTimeout(1000);
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            byte[] data = sb.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            conn.setRequestProperty("Content-Length", String.valueOf(data.length));
            try (java.io.OutputStream os = conn.getOutputStream()) {
                os.write(data);
            }
            conn.getInputStream().close();
            conn.disconnect();
        } catch (Throwable t) {
            // 主进程不在线/推送失败：静默丢弃（内存缓冲仍在，UI 连目标进程时可见）
        }
    }

    private static String esc(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        return sb.toString();
    }

    public synchronized void log(String tag, String msg) {
        String t = FMT.get().format(new Date());
        entries.addLast(new Entry(++seq, t, tag, msg));
        // v1.27: 同步异步落盘（JSONL 按天文件，进程死/升级不丢）
        LogPersister.get().log(seq, tag, msg);
        // v1.32: 目标进程日志推回主进程（SpyProbe 自己家）；主进程自身不启用
        if (pushHome) {
            String line = "{\"t\":\"" + esc(t) + "\",\"tag\":\"" + esc(tag) + "\",\"m\":\"" + esc(msg) + "\"}";
            if (!pushQueue.offer(line)) {
                pushQueue.poll();
                pushQueue.offer(line);
            }
        }
        // v1.12: 容量动态可配置（Config.logLimit）
        int limit = Config.get().logLimit;
        while (entries.size() > limit) entries.pollFirst();
    }

    /** 返回 seq > since 的条目 */
    public synchronized List<Entry> since(long since) {
        List<Entry> out = new ArrayList<>();
        for (Entry e : entries) {
            if (e.seq > since) out.add(e);
        }
        return out;
    }

    public synchronized long lastSeq() {
        return seq;
    }

    public synchronized List<Entry> all() {
        return new ArrayList<>(entries);
    }

    public synchronized void clear() {
        entries.clear();
    }

    public synchronized int size() {
        return entries.size();
    }
}
