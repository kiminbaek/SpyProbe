package com.dustinky.spyprobe;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * 环形缓冲日志（hook 进程内，线程安全）
 * 供 SpyServer 增量拉取；超容量自动淘汰最旧。
 */
public class LogStore {

    private static final int MAX_ENTRIES = 4096;
    private final List<Entry> entries = new ArrayList<>();
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
        entries.add(new Entry(++seq, t, tag, msg));
        while (entries.size() > MAX_ENTRIES) entries.remove(0);
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
