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
    private final Object lock = new Object();

    private volatile File dir = null;

    private HomeHttpStore() { }

    /** 设置落盘目录（主进程 filesDir）——由主进程初始化处调用一次 */
    public void init(File filesDir) {
        if (dir != null) return;
        File d = new File(filesDir, "http_entries");
        if (d.mkdirs() || d.isDirectory()) dir = d;
    }

    public boolean isInitialized() { return dir != null; }

    /** 追加条目（内存 + 落盘） */
    public void add(HttpEntry e) {
        synchronized (lock) {
            mem.add(e);
            while (mem.size() > MAX_MEM) mem.remove(0);
        }
        if (dir != null && e != null) {
            try {
                File f = new File(dir, "http_entries_" + java.time.LocalDate.now() + ".jsonl");
                JSONObject o = e.toJson();
                FileOutputStream fos = new FileOutputStream(f, true);
                fos.write((o.toString() + "\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));
                fos.close();
            } catch (Throwable ignored) { }
        }
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

    /** 从 jsonl 文件读某天全部（历史页回溯；文件不存在返回空） */
    public List<HttpEntry> readDay(File filesDir, String day) {
        List<HttpEntry> out = new ArrayList<>();
        try {
            File d = new File(filesDir, "http_entries");
            File f = new File(d, "http_entries_" + day + ".jsonl");
            if (!f.isFile()) return out;
            java.io.BufferedReader br = new java.io.BufferedReader(new java.io.FileReader(f, java.nio.charset.StandardCharsets.UTF_8));
            String line;
            while ((line = br.readLine()) != null) {
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
}
