package com.dustinky.spyprobe;

import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * v1.48: 主进程侧结构化 HTTP 条目存储（UI 详情页数据源）
 *
 * 目标进程推送的 HttpEntry 落在这里（内存环形 MAX 200 + 追加写文件 http_entries.jsonl）。
 * UI 点请求行时按 id 查询；历史页可从文件回溯（新版本抓的）。
 * 内存环形只保留最近 200 条（防膨胀）；文件按天滚动（http_entries_<yyyy-MM-dd>.jsonl）。
 *
 * 与目标进程 HttpStore 的区别：不主动 push（主进程是终点），只 add/find/read。
 */
public class HomeHttpStore {

    private static final int MAX_MEM = 200;

    private static final HomeHttpStore INSTANCE = new HomeHttpStore();
    public static HomeHttpStore get() { return INSTANCE; }

    private final List<HttpEntry> mem = new ArrayList<>();
    // v1.50 P2-13: 落盘攒批——高频请求（视频流/轮询）不再每条 open/close 文件，
    //   写线程每 2s flush 一次 pending（崩溃最多丢 2s 详情数据，内存环形仍保留）
    private final List<HttpEntry> pending = new ArrayList<>();
    private final Object lock = new Object();

    private volatile File dir = null;
    private volatile boolean writerStarted = false;

    private HomeHttpStore() { }

    /** 设置落盘目录（主进程 filesDir）——由主进程初始化处调用一次 */
    public void init(File filesDir) {
        if (dir != null) return;
        File d = new File(filesDir, "http_entries");
        if (d.mkdirs() || d.isDirectory()) dir = d;
        ensureWriter();
    }

    public boolean isInitialized() { return dir != null; }

    private void ensureWriter() {
        synchronized (lock) {
            if (writerStarted) return;
            writerStarted = true;
            Thread t = new Thread(this::writeLoop, "SpyProbe-HttpPersist");
            t.setDaemon(true);
            t.start();
        }
    }

    private void writeLoop() {
        while (true) {
            try {
                Thread.sleep(2000);
                flushPending();
            } catch (InterruptedException ie) {
                return;
            } catch (Throwable t) {
                DebugLog.get().logNoMirror("HomeHttp", "writeLoop err: " + t);
            }
        }
    }

    private void flushPending() {
        List<HttpEntry> batch;
        synchronized (lock) {
            if (pending.isEmpty()) return;
            batch = new ArrayList<>(pending);
            pending.clear();
        }
        if (dir == null || batch.isEmpty()) return;
        try {
            File f = new File(dir, "http_entries_" + java.time.LocalDate.now() + ".jsonl");
            StringBuilder sb = new StringBuilder();
            for (HttpEntry e : batch) {
                if (e == null) continue;
                try { sb.append(e.toJson().toString()).append('\n'); } catch (Throwable ignored) { }
            }
            if (sb.length() > 0) {
                FileOutputStream fos = new FileOutputStream(f, true);
                fos.write(sb.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
                fos.close();
            }
        } catch (Throwable ignored) { }
    }

    /** 追加条目（内存立即 + 落盘攒批） */
    public void add(HttpEntry e) {
        synchronized (lock) {
            mem.add(e);
            while (mem.size() > MAX_MEM) mem.remove(0);
            if (e != null) pending.add(e);
        }
        ensureWriter();
    }

    /** 按 id 查内存（实时页用；历史页走文件） */
    public HttpEntry find(long id) {
        synchronized (lock) {
            for (int i = mem.size() - 1; i >= 0; i--) {
                if (mem.get(i).id == id) return mem.get(i);
            }
            return null;
        }
    }

    /** 内存全部（调试/导出用） */
    public List<HttpEntry> snapshot() {
        synchronized (lock) { return new ArrayList<>(mem); }
    }

    /** v1.50 P0-1: 清空内存环形（实时清空按钮用；文件保留历史） */
    public void clearMem() {
        synchronized (lock) { mem.clear(); }
    }

    /** 从 jsonl 文件读某天全部（历史页回溯；文件不存在返回空）
     *  v1.62 P2-15: 加 max 上限（默认 5000 条）——视频站高频请求一天几万条，
     *  全读会 OOM/卡 UI（HttpDetailPage 一次性渲染所有条目） */
    public List<HttpEntry> readDay(File filesDir, String day) {
        return readDay(filesDir, day, 5000);
    }

    /** v1.62 P2-15: 带条数上限的 readDay（历史页可分页回溯） */
    public List<HttpEntry> readDay(File filesDir, String day, int max) {
        List<HttpEntry> out = new ArrayList<>();
        try {
            File d = new File(filesDir, "http_entries");
            File f = new File(d, "http_entries_" + day + ".jsonl");
            if (!f.isFile()) return out;
            java.io.BufferedReader br = new java.io.BufferedReader(new java.io.FileReader(f, java.nio.charset.StandardCharsets.UTF_8));
            String line;
            while ((line = br.readLine()) != null) {
                if (out.size() >= max) break;
                if (line.trim().isEmpty()) continue;
                try {
                    HttpEntry e = HttpEntry.fromJson(new JSONObject(line));
                    if (e != null) out.add(e);
                } catch (Throwable ignored) { }
            }
            br.close();
        } catch (Throwable ignored) { }
        return out;
    }

    /** v1.63 P2-6: 按 id 流式查找某天文件（不全量读内存 + 不受 readDay 5000 截断影响） */
    public HttpEntry findInDay(File filesDir, String day, long id) {
        try {
            File d = new File(filesDir, "http_entries");
            File f = new File(d, "http_entries_" + day + ".jsonl");
            if (!f.isFile()) return null;
            java.io.BufferedReader br = new java.io.BufferedReader(new java.io.FileReader(f, java.nio.charset.StandardCharsets.UTF_8));
            String line;
            HttpEntry hit = null;
            while ((line = br.readLine()) != null) {
                if (line.trim().isEmpty()) continue;
                try {
                    JSONObject o = new JSONObject(line);
                    if (o.optLong("id", -1) != id) continue;
                    HttpEntry e = HttpEntry.fromJson(o);
                    if (e != null) { hit = e; break; }
                } catch (Throwable ignored) { }
            }
            br.close();
            return hit;
        } catch (Throwable ignored) {
            return null;
        }
    }
}
