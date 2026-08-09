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
    // v1.33: 会话标识——每次目标进程启动生成，随推送带给主进程；
    //   主进程看到 session 变化 → LogPersister.startSession() → 新会话文件（按次数记，不按天混）
    private final String sessionId = java.util.UUID.randomUUID().toString();

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

    // v1.35 P0-1: 推送改纯 Socket 直写 HTTP，不经过 HttpURLConnection ——
    //   旧实现用 HttpURLConnection POST 127.0.0.1:9900，被自己的 NetProbe HUC hook +
    //   native send/recv hook 捕获 → 推送体（含全部历史日志）被当新日志记录 → 递归爆炸
    //   （上次日志 944/1258 条是 127.0.0.1:9900 推送记录）。
    //   改纯 Socket：Java 层无任何 hook 点捕获；native 层在 NativeProbe.onNativeData
    //   按 127.0.0.1:9900 显式跳过（双保险）。
    private void flushPush(List<String> batch) {
        try {
            StringBuilder sb = new StringBuilder("{\"session\":\"").append(sessionId).append("\",\"entries\":[");
            for (int i = 0; i < batch.size(); i++) {
                if (i > 0) sb.append(',');
                sb.append(batch.get(i));
            }
            sb.append("]}");
            byte[] data = sb.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            java.net.Socket sock = new java.net.Socket();
            sock.setTcpNoDelay(true);
            sock.connect(new java.net.InetSocketAddress("127.0.0.1", 9900), 500);
            // 手写最小 HTTP POST（Content-Length 固定，无 chunked）
            StringBuilder head = new StringBuilder();
            head.append("POST /api/push_logs HTTP/1.1\r\n")
                .append("Host: 127.0.0.1:9900\r\n")
                .append("Content-Type: application/json; charset=utf-8\r\n")
                .append("Content-Length: ").append(data.length).append("\r\n")
                .append("Connection: close\r\n\r\n");
            java.io.OutputStream os = sock.getOutputStream();
            os.write(head.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
            os.write(data);
            os.flush();
            // 读响应直到关闭（Connection: close），避免对端 write 失败
            java.io.InputStream is = sock.getInputStream();
            byte[] tmp = new byte[256];
            long deadline = System.currentTimeMillis() + 1000;
            while (System.currentTimeMillis() < deadline && is.read(tmp) != -1) { }
            try { is.close(); } catch (Throwable t2) { }
            try { os.close(); } catch (Throwable t2) { }
            try { sock.close(); } catch (Throwable t2) { }
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

    // v1.35 P0-2: 单行化——所有日志 msg 在入口统一把换行折叠成 ␤（U+2424）。
    //   旧实现 msg 内嵌 \n（OkHttp 头/body 多行缩进、native stack 多行）→ 导出 txt
    //   一行日志跨多行，grep 行号全乱。折叠后保证"一行一条"，导出/UI/grep 都干净。
    private static String foldLine(String s) {
        if (s == null) return "";
        if (s.indexOf('\n') < 0 && s.indexOf('\r') < 0) return s;
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\n' || c == '\r') sb.append('\u2424');
            else sb.append(c);
        }
        return sb.toString();
    }

    /** v1.35 P1-3: 请求关联 ID——返回下一条即将分配的 seq（供 OkHttp 请求/响应行关联，不消费） */
    public synchronized long nextSeq() {
        return seq + 1;
    }

    public synchronized void log(String tag, String msg) {
        // v1.35 P0-2: 单行化入口（211 处调用全覆盖）
        String folded = foldLine(msg);
        String t = FMT.get().format(new Date());
        entries.addLast(new Entry(++seq, t, tag, folded));
        // v1.27: 同步异步落盘（JSONL 按天文件，进程死/升级不丢）
        LogPersister.get().log(seq, tag, folded);
        // v1.32: 目标进程日志推回主进程（SpyProbe 自己家）；主进程自身不启用
        if (pushHome) {
            String line = "{\"t\":\"" + esc(t) + "\",\"tag\":\"" + esc(tag) + "\",\"m\":\"" + esc(folded) + "\"}";
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
