package com.dustinky.spyprobe;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * v1.55: 主进程结构化事件存储（SpyProbe 自己家）
 *
 * 接收目标进程 9900 /api/push_event 推送的 SpyEvent，UI 日志页按 [EVT#id] 关联渲染卡片。
 * 内存环形只保留最近 {@link #MAX_MEM} 条（防膨胀）；文件按天滚动 event_entries_<yyyy-MM-dd>.jsonl。
 *
 * 与 HomeHttpStore 同构（终点不主动 push）：只 add/find/read。
 */
public class HomeEventStore {

    private static final int MAX_MEM = 4096;

    private static final HomeEventStore INSTANCE = new HomeEventStore();
    public static HomeEventStore get() { return INSTANCE; }

    private final List<SpyEvent> mem = new ArrayList<>();
    private final List<SpyEvent> pending = new ArrayList<>();
    private final Object lock = new Object();

    private volatile File dir = null;
    private volatile boolean writerStarted = false;

    private HomeEventStore() { }

    /** 设置落盘目录（主进程 filesDir）——由主进程初始化处调用一次 */
    public void init(File filesDir) {
        if (dir != null) return;
        File d = new File(filesDir, "event_entries");
        if (!d.exists() && !d.mkdirs()) {
            DebugLog.get().log("HomeEvent", "mkdir fail: " + d.getAbsolutePath());
            return;
        }
        dir = d;
        if (!writerStarted) {
            writerStarted = true;
            Thread t = new Thread(this::writeLoop, "SpyProbe-HomeEventWrite");
            t.setDaemon(true);
            t.start();
        }
    }

    /** 新事件（主进程接收端，push_event 路由调用） */
    public void add(SpyEvent e) {
        synchronized (lock) {
            mem.add(e);
            pending.add(e);
            while (mem.size() > MAX_MEM) mem.remove(0);
            // pending 上限 500，防推送洪峰时内存无界
            while (pending.size() > MAX_MEM) pending.remove(0);
        }
    }

    /** 按 id 查（内存优先） */
    public SpyEvent find(long id) {
        synchronized (lock) {
            for (SpyEvent e : mem) {
                if (e.id == id) return e;
            }
            return null;
        }
    }

    /** 全部（UI 分析/渲染用） */
    public List<SpyEvent> all() {
        synchronized (lock) {
            return new ArrayList<>(mem);
        }
    }

    public int size() {
        synchronized (lock) { return mem.size(); }
    }

    public void clearMem() {
        synchronized (lock) {
            mem.clear();
        }
    }

    /** 按天读取历史文件（UI 历史页回溯）
     *  v1.63 P2-5: 加条数上限（对齐 HomeHttpStore 5000）——事件频率比 HTTP 更高（SQL/JSON/LOG 海量），
     *  全读会 OOM/卡 UI */
    public List<SpyEvent> readDay(File filesDir, String day) {
        return readDay(filesDir, day, 5000);
    }

    /** v1.63 P2-5: 带条数上限的 readDay */
    public List<SpyEvent> readDay(File filesDir, String day, int max) {
        List<SpyEvent> out = new ArrayList<>();
        try {
            File d = new File(filesDir, "event_entries");
            if (!d.exists()) return out;
            File f = new File(d, "event_entries_" + day + ".jsonl");
            if (!f.exists()) return out;
            java.io.BufferedReader br = new java.io.BufferedReader(new java.io.InputStreamReader(
                    new java.io.FileInputStream(f), java.nio.charset.StandardCharsets.UTF_8));
            String line;
            while ((line = br.readLine()) != null) {
                if (out.size() >= max) break;
                try {
                    JSONObject o = new JSONObject(line);
                    SpyEvent e = SpyEvent.fromJson(o);
                    if (e != null) out.add(e);
                } catch (Throwable ignored) { }
            }
            br.close();
        } catch (Throwable t) {
            DebugLog.get().log("HomeEvent", "readDay fail: " + t);
        }
        return out;
    }

    /** v1.63 P2-6: 按 id 流式查找某天事件文件（不全量读内存 + 不受 readDay 5000 截断影响） */
    public SpyEvent findInDay(File filesDir, String day, long id) {
        try {
            File d = new File(filesDir, "event_entries");
            if (!d.exists()) return null;
            File f = new File(d, "event_entries_" + day + ".jsonl");
            if (!f.exists()) return null;
            java.io.BufferedReader br = new java.io.BufferedReader(new java.io.InputStreamReader(
                    new java.io.FileInputStream(f), java.nio.charset.StandardCharsets.UTF_8));
            String line;
            SpyEvent hit = null;
            while ((line = br.readLine()) != null) {
                try {
                    JSONObject o = new JSONObject(line);
                    if (o.optLong("id", -1) != id) continue;
                    SpyEvent e = SpyEvent.fromJson(o);
                    if (e != null) { hit = e; break; }
                } catch (Throwable ignored) { }
            }
            br.close();
            return hit;
        } catch (Throwable t) {
            DebugLog.get().log("HomeEvent", "findInDay fail: " + t);
            return null;
        }
    }

    /** 写线程：攒批 2s flush（与 HomeHttpStore 同构，避免每条 open/close） */
    private void writeLoop() {
        while (true) {
            try {
                Thread.sleep(2000);
                flushPending();
            } catch (InterruptedException ie) {
                return;
            } catch (Throwable t) {
                DebugLog.get().log("HomeEvent", "writeLoop err: " + t);
            }
        }
    }

    private void flushPending() {
        List<SpyEvent> batch;
        synchronized (lock) {
            if (pending.isEmpty()) return;
            batch = new ArrayList<>(pending);
            pending.clear();
        }
        File d = dir;
        if (d == null) return;
        try {
            String day = new java.text.SimpleDateFormat("yyyy-MM-dd", java.util.Locale.US)
                    .format(new java.util.Date());
            File f = new File(d, "event_entries_" + day + ".jsonl");
            java.io.FileOutputStream fos = new java.io.FileOutputStream(f, true);
            java.io.BufferedWriter bw = new java.io.BufferedWriter(new java.io.OutputStreamWriter(
                    fos, java.nio.charset.StandardCharsets.UTF_8));
            for (SpyEvent e : batch) {
                bw.write(e.toJson().toString());
                bw.newLine();
            }
            bw.close();
        } catch (Throwable t) {
            DebugLog.get().log("HomeEvent", "flush fail: " + t);
        }
    }
}
