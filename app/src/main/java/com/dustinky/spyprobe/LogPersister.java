package com.dustinky.spyprobe;

/*
 * SpyProbe —— 通用逆向探测 / 抓包工作台
 * Copyright (c) 2026 kiminbaek（原作者）
 * 许可证：SpyProbe 自定义许可证（不可商用，二次开发需注明原作者版权）
 * 详见项目根 LICENSE / README.md：https://github.com/kiminbaek/SpyProbe
 */

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * v1.27: 日志异步落盘（解决"日志纯内存、进程死/升级就丢"的核心缺陷）
 *
 * - JSONL 格式：每行一条 {"seq":..,"t":"HH:mm:ss.SSS","tag":"..","m":".."}，UTF-8
 * - 按天分文件：spyprobe_logs_<yyyy-MM-dd>_<n>.log，单文件 5MB 滚动到 _1/_2/...
 * - 异步写：ArrayBlockingQueue 队列 + 单写线程，不阻塞 hook 线程
 * - 保留策略：默认保留最近 7 天文件，超期自动清理（防占盘）
 *
 * 进程内唯一实例（LogPersister.get()），由 ModuleMain.onPackageReady 用
 * ActivityThread.currentApplication().getFilesDir() 初始化。
 */
public class LogPersister {

    private static final LogPersister INSTANCE = new LogPersister();
    public static LogPersister get() { return INSTANCE; }

    private static final String PREFIX = "spyprobe_logs_";
    private static final long MAX_FILE = 5L * 1024 * 1024; // 单文件 5MB
    private static final int KEEP_DAYS = 7;                // 保留 7 天
    private static final int QUEUE_CAP = 8192;             // 队列上限，满丢最旧

    private final SimpleDateFormat DAY_FMT = new SimpleDateFormat("yyyy-MM-dd", Locale.US);
    // v1.28 P1: log() 被多个 hook 线程并发调用，共享 SimpleDateFormat 数据竞争 → ThreadLocal（LogStore 同款）
    private static final ThreadLocal<SimpleDateFormat> TIME_FMT = new ThreadLocal<SimpleDateFormat>() {
        @Override
        protected SimpleDateFormat initialValue() {
            return new SimpleDateFormat("HH:mm:ss.SSS", Locale.US);
        }
    };
    private final ArrayBlockingQueue<String> queue = new ArrayBlockingQueue<>(QUEUE_CAP);

    private volatile File dir = null;
    private volatile boolean enabled = true;
    // v1.28 P1: 清空历史后通知写线程重开文件——否则写线程继续写已删除的 inode（新日志丢失直到滚动/跨天）
    private volatile boolean resetRequested = false;

    /** 初始化（幂等）：由目标 App 进程启动时调用 */
    public synchronized void init(File appFilesDir) {
        if (dir != null) return;
        dir = new File(appFilesDir, "spyprobe_logs");
        if (!dir.mkdirs() && !dir.isDirectory()) {
            LogStore.get().log("SpyProbe.Persist", "mkdir fail: " + dir.getAbsolutePath());
        }
        Thread w = new Thread(this::run, "SpyProbe-Persist");
        w.setDaemon(true);
        w.start();
        cleanupOld();
    }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean e) { enabled = e; }

    /** hook 线程调用（非阻塞）：入队失败丢最旧一条 */
    public void log(long seq, String tag, String msg) {
        if (!enabled || dir == null) return;
        String line = "{\"seq\":" + seq
                + ",\"t\":\"" + esc(TIME_FMT.get().format(new Date()))
                + "\",\"tag\":\"" + esc(tag)
                + "\",\"m\":\"" + esc(msg) + "\"}";
        if (!queue.offer(line)) {
            queue.poll();
            queue.offer(line);
        }
    }

    // ---------- 写线程 ----------
    private void run() {
        BufferedWriter bw = null;
        String day = null;
        int part = 0;
        File f = null;
        while (true) {
            try {
                // v1.28 P1: 清空历史后写线程重开文件（旧 inode 已被删，继续写会丢新日志）
                if (resetRequested) {
                    resetRequested = false;
                    if (bw != null) { try { bw.flush(); bw.close(); } catch (Throwable t3) { } }
                    bw = null;
                    day = null;
                    continue;
                }
                String line = queue.poll(500, TimeUnit.MILLISECONDS);
                if (line == null) {
                    if (bw != null) bw.flush();
                    continue;
                }
                String d = DAY_FMT.format(new Date());
                if (!d.equals(day)) {
                    if (bw != null) { bw.flush(); bw.close(); }
                    day = d;
                    part = nextPart(day);
                    f = fileOf(day, part);
                    bw = open(f);
                    // v1.27: 跨天时顺带清理过期历史（长期运行场景）
                    cleanupOld();
                }
                bw.write(line);
                bw.newLine();
                if (f.length() > MAX_FILE) {
                    bw.flush();
                    bw.close();
                    part++;
                    f = fileOf(day, part);
                    bw = open(f);
                }
            } catch (InterruptedException ie) {
                break;
            } catch (Throwable t) {
                // 写盘失败绝不阻塞主流程：关掉当前 writer，下次重开
                try { if (bw != null) bw.close(); } catch (Throwable t2) { }
                bw = null;
                day = null;
            }
        }
        try { if (bw != null) bw.flush(); bw.close(); } catch (Throwable t) { }
    }

    private BufferedWriter open(File f) throws Exception {
        return new BufferedWriter(new OutputStreamWriter(new FileOutputStream(f, true), StandardCharsets.UTF_8));
    }

    /** 当天已存在的分片最大编号 + 1（继续追加） */
    private int nextPart(String day) {
        File[] fs = listDayFiles(day);
        int max = -1;
        if (fs != null) {
            for (File x : fs) {
                String n = x.getName();
                int idx = n.lastIndexOf('_');
                if (idx > 0) {
                    try {
                        int p = Integer.parseInt(n.substring(idx + 1, n.length() - 4));
                        if (p > max) max = p;
                    } catch (Throwable t) { }
                }
            }
        }
        return max + 1;
    }

    private File fileOf(String day, int part) {
        return new File(dir, PREFIX + day + "_" + part + ".log");
    }

    private File[] listDayFiles(String day) {
        if (dir == null) return null;
        final String prefix = PREFIX + day + "_";
        File[] fs = dir.listFiles((d, name) -> name.startsWith(prefix) && name.endsWith(".log"));
        return fs;
    }

    private void cleanupOld() {
        if (dir == null) return;
        long cutoff = System.currentTimeMillis() - (long) KEEP_DAYS * 24 * 3600 * 1000;
        File[] fs = dir.listFiles((d, name) -> name.startsWith(PREFIX) && name.endsWith(".log"));
        if (fs == null) return;
        for (File f : fs) {
            if (f.lastModified() < cutoff) {
                try { f.delete(); } catch (Throwable t) { }
            }
        }
    }

    // ---------- 供 SpyServer API 读取 ----------
    public static class Entry {
        public final long seq;
        public final String time;
        public final String tag;
        public final String msg;
        Entry(long seq, String time, String tag, String msg) {
            this.seq = seq; this.time = time; this.tag = tag; this.msg = msg;
        }
    }

    /** 可用的历史日期（按文件扫描，倒序：新日期在前） */
    public List<String> days() {
        if (dir == null) return Collections.emptyList();
        File[] fs = dir.listFiles((d, name) -> name.startsWith(PREFIX) && name.endsWith(".log"));
        if (fs == null) return Collections.emptyList();
        java.util.Set<String> set = new java.util.TreeSet<>(Collections.reverseOrder());
        for (File f : fs) {
            String n = f.getName();
            // spyprobe_logs_2026-08-09_0.log -> 2026-08-09
            if (n.length() > PREFIX.length() + 11) {
                set.add(n.substring(PREFIX.length(), PREFIX.length() + 10));
            }
        }
        return new ArrayList<>(set);
    }

    /** 读某天日志（多分片合并按 seq 排序），max>0 时环形保留最新 max 条（避免百万行内存峰值） */
    public List<Entry> readDay(String day, int max) {
        if (dir == null) return Collections.emptyList();
        File[] fs = listDayFiles(day);
        if (fs == null) return Collections.emptyList();
        List<Entry> out = new ArrayList<>();
        java.util.ArrayDeque<Entry> ring = (max > 0) ? new java.util.ArrayDeque<>(Math.min(max, 4096)) : null;
        for (File f : fs) {
            try (BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null) {
                    if (line.trim().isEmpty()) continue;
                    Entry e = parseLine(line);
                    if (e != null) {
                        if (ring != null) {
                            if (ring.size() >= max) ring.removeFirst();
                            ring.addLast(e);
                        } else {
                            out.add(e);
                        }
                    }
                }
            } catch (Throwable t) { }
        }
        if (ring != null) out = new ArrayList<>(ring);
        out.sort(Comparator.comparingLong(a -> a.seq));
        if (max > 0 && out.size() > max) {
            return new ArrayList<>(out.subList(out.size() - max, out.size()));
        }
        return out;
    }

    /** 删除某天；day==null 删除全部历史 */
    public void clear(String day) {
        if (dir == null) return;
        File[] fs = (day == null)
                ? dir.listFiles((d, name) -> name.startsWith(PREFIX) && name.endsWith(".log"))
                : listDayFiles(day);
        if (fs == null) return;
        for (File f : fs) { try { f.delete(); } catch (Throwable t) { } }
        // v1.28 P1: 若正在写的文件被删，通知写线程重开新文件
        resetRequested = true;
    }

    private Entry parseLine(String line) {
        try {
            long seq = -1; String t = "", tag = "", m = "";
            // 极简 JSON 解析（避免引入 org.json 到每行，性能优先）
            int p = 0;
            while (p < line.length()) {
                int q = line.indexOf('"', p);
                if (q < 0 || q + 1 >= line.length()) break;
                String key = line.substring(q + 1, line.indexOf('"', q + 1));
                int colon = line.indexOf(':', line.indexOf('"', q + 1) + 1);
                if (colon < 0) break;
                int vs = colon + 1;
                while (vs < line.length() && (line.charAt(vs) == ' ' || line.charAt(vs) == '\t')) vs++;
                if (vs >= line.length()) break;
                String val;
                if (line.charAt(vs) == '"') {
                    int end = vs + 1;
                    StringBuilder sb = new StringBuilder();
                    while (end < line.length()) {
                        char c = line.charAt(end);
                        if (c == '\\' && end + 1 < line.length()) {
                            char n = line.charAt(end + 1);
                            switch (n) {
                                case 'n': sb.append('\n'); end += 2; break;
                                case 'r': sb.append('\r'); end += 2; break;
                                case 't': sb.append('\t'); end += 2; break;
                                case '\\': sb.append('\\'); end += 2; break;
                                case '"': sb.append('"'); end += 2; break;
                                case 'u': {
                                    // v1.28 P1: 控制字符 esc 为反斜杠uXXXX 形式，之前未解析 → 乱码
                                    if (end + 5 < line.length()) {
                                        try {
                                            int cp = Integer.parseInt(line.substring(end + 2, end + 6), 16);
                                            sb.append((char) cp);
                                            end += 6;
                                        } catch (Throwable t3) {
                                            sb.append('u'); end += 2;
                                        }
                                    } else {
                                        sb.append('u'); end += 2;
                                    }
                                    break;
                                }
                                default: sb.append(n); end += 2;
                            }
                        } else if (c == '"') { end++; break; }
                        else { sb.append(c); end++; }
                    }
                    val = sb.toString();
                    p = end;
                } else {
                    int end = vs;
                    while (end < line.length() && line.charAt(end) != ',' && line.charAt(end) != '}') end++;
                    val = line.substring(vs, end).trim();
                    p = end;
                }
                switch (key) {
                    case "seq": try { seq = Long.parseLong(val); } catch (Throwable t2) { } break;
                    case "t": t = val; break;
                    case "tag": tag = val; break;
                    case "m": m = val; break;
                }
            }
            return new Entry(seq, t, tag, m);
        } catch (Throwable t) {
            return null;
        }
    }

    private String esc(String s) {
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
                    if (c < 0x20) { sb.append("\\u").append(String.format(Locale.US, "%04x", (int) c)); }
                    else sb.append(c);
            }
        }
        return sb.toString();
    }
}
