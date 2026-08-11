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
    private final ArrayBlockingQueue<String> queue = new ArrayBlockingQueue<>(QUEUE_CAP);

    private volatile File dir = null;
    private volatile boolean enabled = true;
    // v1.28 P1: 清空历史后通知写线程重开文件——否则写线程继续写已删除的 inode（新日志丢失直到滚动/跨天）
    private volatile boolean resetRequested = false;
    // v1.33: 会话滚动——目标进程每启动一次（新 sessionId 推送）开新文件
    // v1.50 P1-5: 文件名升级为 spyprobe_logs_<date>_<session>_<part>.log——
    //   session=会话号（每次目标进程启动 +1），part=5MB 滚动序号（同一会话超 5MB 滚动）。
    //   旧实现 _<n> 同时承担两个语义，>5MB 大会话被拆成多个"会话"（HomeLogReader 假分裂）。
    private volatile boolean sessionRollRequested = false;
    // v1.47 P1-8: 会话元数据（sessions.json）——写线程维护每个文件 count/first/last，
    //   HomeLogReader.sessions() 直接读元数据，避免历史页每次全量扫描每个日志文件（大文件/多会话卡顿）
    private static final String META_NAME = "sessions.json";
    private static final int META_INTERVAL = 100; // 每 100 行落盘一次元数据（写盘频率与日志频率解耦）

    /** 会话卡片元数据：文件名 -> {count, first, last} */
    public static class SessionMeta {
        public final int count;
        public final String first;
        public final String last;
        SessionMeta(int count, String first, String last) {
            this.count = count; this.first = first; this.last = last;
        }
    }

    /** 读取会话元数据（写线程维护的 sessions.json）；文件不存在返回空 map */
    public java.util.Map<String, SessionMeta> loadMeta() {
        java.util.Map<String, SessionMeta> m = new java.util.HashMap<>();
        if (dir == null) return m;
        File mf = new File(dir, META_NAME);
        if (!mf.exists()) return m;
        try {
            String txt = new String(readAll(mf), StandardCharsets.UTF_8);
            org.json.JSONObject o = new org.json.JSONObject(txt);
            java.util.Iterator<String> it = o.keys();
            while (it.hasNext()) {
                String name = it.next();
                org.json.JSONObject e = o.optJSONObject(name);
                if (e != null) {
                    m.put(name, new SessionMeta(e.optInt("count", 0),
                            e.optString("first", ""), e.optString("last", "")));
                }
            }
        } catch (Throwable t) {
            DebugLog.get().log("Persist", "loadMeta FAIL: " + t);
        }
        return m;
    }

    private byte[] readAll(File f) throws Exception {
        try (FileInputStream in = new FileInputStream(f)) {
            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
            return bos.toByteArray();
        }
    }

    /** 更新并落盘当前文件元数据（写线程调用） */
    private void saveMeta(File f, int count, String first, String last) {
        if (dir == null || f == null) return;
        try {
            File mf = new File(dir, META_NAME);
            org.json.JSONObject o;
            if (mf.exists()) {
                try {
                    o = new org.json.JSONObject(new String(readAll(mf), StandardCharsets.UTF_8));
                } catch (Throwable t) { o = new org.json.JSONObject(); }
            } else {
                o = new org.json.JSONObject();
            }
            org.json.JSONObject e = new org.json.JSONObject();
            e.put("count", count);
            e.put("first", first == null ? "" : first);
            e.put("last", last == null ? "" : last);
            o.put(f.getName(), e);
            File tmp = new File(mf.getAbsolutePath() + ".tmp");
            try (FileOutputStream out = new FileOutputStream(tmp)) {
                out.write(o.toString().getBytes(StandardCharsets.UTF_8));
            }
            if (!tmp.renameTo(mf)) {
                try (FileOutputStream out2 = new FileOutputStream(mf)) {
                    out2.write(o.toString().getBytes(StandardCharsets.UTF_8));
                }
            }
        } catch (Throwable t) {
            // 元数据写失败不影响日志主流程
            DebugLog.get().log("Persist", "saveMeta FAIL: " + t);
        }
    }

    /** 从 JSONL 行提取 t 字段（极轻量，元数据 first/last 用） */
    private String lineTime(String line) {
        int i = line.indexOf("\"t\":\"");
        if (i < 0) return "";
        int j = line.indexOf('"', i + 5);
        if (j < 0) return "";
        return line.substring(i + 5, j);
    }

    /** 初始化（幂等）：由目标 App 进程启动时调用 */
    public synchronized void init(File appFilesDir) {
        if (dir != null) return;
        // v1.29.1: LogPersister 拿到有效 filesDir 时同步给 DebugLog 落盘——
        // 否则 DebugLog.init 只在早期(null)调过一次，file 永远 null，调试日志永不落盘
        DebugLog.get().init(appFilesDir);
        dir = new File(appFilesDir, "spyprobe_logs");
        if (!dir.mkdirs() && !dir.isDirectory()) {
            LogStore.get().log("SpyProbe.Persist", "mkdir fail: " + dir.getAbsolutePath());
            DebugLog.get().log("Persist", "mkdir FAIL: " + dir.getAbsolutePath());
        } else {
            DebugLog.get().log("Persist", "mkdir OK: " + dir.getAbsolutePath());
        }
        Thread w = new Thread(this::run, "SpyProbe-Persist");
        w.setDaemon(true);
        w.start();
        cleanupOld();
    }

    public boolean isInitialized() { return dir != null; }
    public String dirPath() { return dir != null ? dir.getAbsolutePath() : "(null)"; }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean e) { enabled = e; }

    /** v1.33: 新会话开始（目标进程重启/重新推送）——写线程下次开新文件，会话号 = 当天最大+1 */
    public void startSession() {
        sessionRollRequested = true;
    }

    /** hook 线程调用（非阻塞）：入队失败丢最旧一条
     *  v1.36 P2-8: 时间由调用方传入（LogStore.log 已格式化）——旧实现内部重新 format(new Date())，
     *  与 LogStore 的 t 可能差 1ms 且重复格式化；push_logs 路径还能保留目标进程的原始时间 */
    public void logAt(long seq, String time, String tag, String msg) {
        if (!enabled || dir == null) return;
        String line = "{\"seq\":" + seq
                + ",\"t\":\"" + esc(time)
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
        int session = 0; // v1.50 P1-5: 会话号（每次目标进程启动 +1）
        int part = 0;    // 5MB 滚动序号（同一会话内）
        File f = null;
        int metaCount = 0;        // 当前文件已写行数（元数据用）
        String metaFirst = "";    // 当前文件首行 t
        String metaLast = "";     // 当前文件末行 t
        while (true) {
            try {
                // v1.28 P1: 清空历史后写线程重开文件（旧 inode 已被删，继续写会丢新日志）
                // v1.33: 会话滚动（startSession）同样走这里重开文件
                if (resetRequested || sessionRollRequested) {
                    resetRequested = false;
                    sessionRollRequested = false;
                    if (bw != null) {
                        try { bw.flush(); } catch (Throwable t3) { }
                        // v1.47 P1-8: 关闭前把当前文件元数据落盘（含已写入条数）
                        if (f != null && metaCount > 0) saveMeta(f, metaCount, metaFirst, metaLast);
                        try { bw.close(); } catch (Throwable t3) { }
                    }
                    bw = null;
                    day = null;
                    metaCount = 0;
                    metaFirst = "";
                    metaLast = "";
                    continue;
                }
                String line = queue.poll(500, TimeUnit.MILLISECONDS);
                if (line == null) {
                    if (bw != null) {
                        bw.flush();
                        // v1.47 P1-8: 空闲 flush 时同步元数据（实时性更好，UI 条数更准）
                        if (f != null && metaCount > 0) saveMeta(f, metaCount, metaFirst, metaLast);
                        // v1.50 P1-7: 写线程自检——当前文件被外部删除（清空单个会话等）后重开，
                        //   否则新日志写进已删除的 inode（目录项没了，文件"消失"直到跨天/会话滚动）
                        if (f != null && !f.exists()) {
                            DebugLog.get().log("Persist", "file deleted externally, reopen");
                            try { bw.close(); } catch (Throwable t) { }
                            bw = null;
                            day = null;
                            metaCount = 0;
                            metaFirst = "";
                            metaLast = "";
                        }
                    }
                    continue;
                }
                String d = DAY_FMT.format(new Date());
                if (!d.equals(day)) {
                    if (bw != null) {
                        bw.flush();
                        if (f != null && metaCount > 0) saveMeta(f, metaCount, metaFirst, metaLast);
                        bw.close();
                    }
                    day = d;
                    session = nextSession(day);
                    part = 0;
                    f = fileOf(day, session, part);
                    bw = open(f);
                    metaCount = 0;
                    metaFirst = "";
                    metaLast = "";
                    // v1.30.2: 写线程打开文件 DebugLog（能看到实际落盘文件名）
                    DebugLog.get().log("Persist", "open " + f.getName());
                    // v1.27: 跨天时顺带清理过期历史（长期运行场景）
                    cleanupOld();
                }
                bw.write(line);
                bw.newLine();
                // v1.47 P1-8: 维护当前文件元数据（count/first/last），每 META_INTERVAL 行落盘一次
                metaCount++;
                String lt = lineTime(line);
                if (metaFirst.isEmpty() && !lt.isEmpty()) metaFirst = lt;
                if (!lt.isEmpty()) metaLast = lt;
                if (metaCount % META_INTERVAL == 0 && f != null) {
                    saveMeta(f, metaCount, metaFirst, metaLast);
                }
                if (f.length() > MAX_FILE) {
                    bw.flush();
                    if (f != null && metaCount > 0) saveMeta(f, metaCount, metaFirst, metaLast);
                    bw.close();
                    part++; // v1.50 P1-5: 同会话内 5MB 滚动（不换会话号）
                    f = fileOf(day, session, part);
                    bw = open(f);
                    metaCount = 0;
                    metaFirst = "";
                    metaLast = "";
                    DebugLog.get().log("Persist", "rolled -> " + f.getName());
                }
            } catch (InterruptedException ie) {
                break;
            } catch (Throwable t) {
                // 写盘失败绝不阻塞主流程：关掉当前 writer，下次重开
                DebugLog.get().log("Persist", "write thread error: " + t);
                try { if (bw != null) bw.close(); } catch (Throwable t2) { }
                bw = null;
                day = null;
                metaCount = 0;
                metaFirst = "";
                metaLast = "";
            }
        }
        try { if (bw != null) bw.flush(); bw.close(); } catch (Throwable t) { }
    }

    private BufferedWriter open(File f) throws Exception {
        return new BufferedWriter(new OutputStreamWriter(new FileOutputStream(f, true), StandardCharsets.UTF_8));
    }

    /** v1.50 P1-5: 当天已存在的最大会话号 + 1（新会话开新文件 _<s>_<p>.log；兼容老单段 _<n>） */
    private int nextSession(String day) {
        File[] fs = listDayFiles(day);
        int max = -1;
        if (fs != null) {
            for (File x : fs) {
                int s = parseSession(x.getName());
                if (s > max) max = s;
            }
        }
        return max + 1;
    }

    /** 从文件名解析会话号：spyprobe_logs_<date>_<s>_<p>.log 或老格式 _<s>.log 都取第二段 */
    private int parseSession(String name) {
        try {
            int dateEnd = PREFIX.length() + 10;
            if (name.length() <= dateEnd + 2) return -1;
            String rest = name.substring(dateEnd + 1, name.length() - 4); // 去掉 "<date>_" 和 ".log"
            int u = rest.indexOf('_');
            String s = u > 0 ? rest.substring(0, u) : rest;
            return Integer.parseInt(s.trim());
        } catch (Throwable t) { return -1; }
    }

    private File fileOf(String day, int session, int part) {
        return new File(dir, PREFIX + day + "_" + session + "_" + part + ".log");
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
        if (dir == null) {
            DebugLog.get().log("Persist", "readDay(" + day + ") dir=null，无历史");
            return Collections.emptyList();
        }
        File[] fs = listDayFiles(day);
        if (fs == null || fs.length == 0) {
            DebugLog.get().log("Persist", "readDay(" + day + ") 无文件");
            return Collections.emptyList();
        }
        // v1.30.2: 读取结果数量 DebugLog（能看到历史页/导出拿到了多少条）
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
            } catch (Throwable t) {
                DebugLog.get().log("Persist", "readDay(" + day + ") file " + f.getName() + " read error: " + t);
            }
        }
        if (ring != null) out = new ArrayList<>(ring);
        out.sort(Comparator.comparingLong(a -> a.seq));
        if (max > 0 && out.size() > max) {
            out = new ArrayList<>(out.subList(out.size() - max, out.size()));
        }
        DebugLog.get().log("Persist", "readDay(" + day + ") files=" + fs.length + " entries=" + out.size());
        return out;
    }

    /** 删除某天；day==null 删除全部历史 */
    public void clear(String day) {
        if (dir == null) {
            DebugLog.get().log("Persist", "clear(" + day + ") dir=null");
            return;
        }
        File[] fs = (day == null)
                ? dir.listFiles((d, name) -> name.startsWith(PREFIX) && name.endsWith(".log"))
                : listDayFiles(day);
        if (fs == null || fs.length == 0) {
            DebugLog.get().log("Persist", "clear(" + day + ") 无文件可删");
            return;
        }
        // v1.30.2: 清空历史 DebugLog（能看到删除文件数）
        for (File f : fs) {
            try {
                if (f.delete()) DebugLog.get().log("Persist", "clear deleted " + f.getName());
            } catch (Throwable t) {
                DebugLog.get().log("Persist", "clear delete fail " + f.getName() + ": " + t);
            }
        }
        // v1.47 P1-8: 同步清理 sessions.json 元数据里被删文件条目（避免残留累积）
        removeMetaPrefix(day);
        // v1.28 P1: 若正在写的文件被删，通知写线程重开新文件
        resetRequested = true;
    }

    /** v1.47 P1-8: 删除元数据中 name 以 day 开头的条目（day=null 全清） */
    private void removeMetaPrefix(String day) {
        if (dir == null) return;
        try {
            File mf = new File(dir, META_NAME);
            if (!mf.exists()) return;
            org.json.JSONObject o = new org.json.JSONObject(new String(readAll(mf), StandardCharsets.UTF_8));
            java.util.Iterator<String> it = o.keys();
            java.util.List<String> rm = new java.util.ArrayList<>();
            while (it.hasNext()) {
                String name = it.next();
                if (day == null || name.startsWith(PREFIX + day)) rm.add(name);
            }
            if (rm.isEmpty()) return;
            for (String n : rm) o.remove(n);
            File tmp = new File(mf.getAbsolutePath() + ".tmp");
            try (FileOutputStream out = new FileOutputStream(tmp)) {
                out.write(o.toString().getBytes(StandardCharsets.UTF_8));
            }
            if (!tmp.renameTo(mf)) {
                try (FileOutputStream out2 = new FileOutputStream(mf)) {
                    out2.write(o.toString().getBytes(StandardCharsets.UTF_8));
                }
            }
        } catch (Throwable t) {
            DebugLog.get().log("Persist", "removeMetaPrefix FAIL: " + t);
        }
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

    // v1.47 P2-9: 改为 static 同包可见——LogStore.esc 委托本方法（去重；统一 Locale.US 十六进制格式）
    static String esc(String s) {
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
