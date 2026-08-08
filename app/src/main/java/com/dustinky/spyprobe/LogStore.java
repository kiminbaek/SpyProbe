package com.dustinky.spyprobe;

import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Date;
import java.util.Deque;
import java.util.List;
import java.util.Locale;

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
    private final SimpleDateFormat fmt = new SimpleDateFormat("HH:mm:ss.SSS", Locale.US);

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

    public synchronized void log(String tag, String msg) {
        String t = fmt.format(new Date());
        entries.addLast(new Entry(++seq, t, tag, msg));
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
