package com.dustinky.spyprobe;

/*
 * SpyProbe —— 通用逆向探测 / 抓包工作台
 * Copyright (c) 2026 kiminbaek（原作者）
 * 许可证：SpyProbe 自定义许可证（不可商用，二次开发需注明原作者版权）
 * 详见项目根 LICENSE / README.md：https://github.com/kiminbaek/SpyProbe
 */

import android.util.Log;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.Date;
import java.util.Locale;

/**
 * v1.29: 独立调试日志（与正式日志完全分离）
 *
 * 背景：v1.27/v1.28 用户反馈"历史无记录/导出失败/重启丢日志"，但正式日志走
 * LogPersister（依赖反射 ActivityThread.currentApplication() 拿 filesDir，
 * 失败时静默跳过，dir=null → log() 直接 return，一行不写盘且无任何痕迹）。
 *
 * DebugLog 设计（三保险，任何一环失败都不影响其它）：
 * 1. 内存环形缓冲（固定 512 条）——即使 filesDir 永远拿不到也有内容可查
 * 2. 落盘 files/spyprobe_debug.log（同步直写，不走队列/写线程，失败即暴露）
 * 3. android.util.Log.d("SpyProbeDebug", ...)——logcat 也能抓
 *
 * 任何代码可随时 DebugLog.get().log(tag, msg)，线程安全。
 */
public class DebugLog {

    private static final String TAG = "SpyProbeDebug";
    private static final int RING_CAP = 512;
    private static final long MAX_FILE = 256L * 1024; // 256KB 滚动

    private static final DebugLog INSTANCE = new DebugLog();
    public static DebugLog get() { return INSTANCE; }

    private final Object lock = new Object();
    private final ArrayDeque<String> ring = new ArrayDeque<>(RING_CAP);
    private final SimpleDateFormat FMT = new SimpleDateFormat("HH:mm:ss.SSS", Locale.US);

    private volatile File file = null;      // files/spyprobe_debug.log
    private volatile boolean failed = false; // 文件写过但出错过 → 每条都尝试重开
    private BufferedWriter writer = null;    // v1.31.1 P3-5: 持 writer 复用（此前每次 open/close）
    // v1.42 P2-14: 目标进程镜像进 LogStore 的防递归标志——DebugLog.log → LogStore.log →
    //   flushPush 失败 → DebugLog.log（PushHome）→ 若再写 LogStore 则无限递归，这里掐断。
    private static final ThreadLocal<Boolean> IN_LOGSTORE = new ThreadLocal<>();

    private DebugLog() { }

    /**
     * 设置落盘路径（幂等：已设置则忽略，仅首次生效）。
     * 在 ModuleMain 拿到 filesDir 后立即调用；拿不到 filesDir 时只走内存+logcat。
     */
    public void init(File filesDir) {
        synchronized (lock) {
            if (file != null) return;
            if (filesDir == null) {
                logLocked("DebugLog.init(null) — 无法落盘，仅内存+logcat", true);
                return;
            }
            file = new File(filesDir, "spyprobe_debug.log");
            logLocked("DebugLog.init -> " + file.getAbsolutePath(), true);
        }
    }

    /** 线程安全入口 */
    public void log(String tag, String msg) {
        synchronized (lock) {
            logLocked("[" + tag + "] " + msg, true);
        }
    }

    /** v1.42 P2-14: 不镜像 LogStore 的入口——LogStore/PcapWriter 推送失败留痕用
     *  （推送失败 → DebugLog → 若再镜像回 LogStore → 再推送失败 → 无限递归） */
    public void logNoMirror(String tag, String msg) {
        synchronized (lock) {
            logLocked("[" + tag + "] " + msg, false);
        }
    }

    /** 需持锁调用；mirror=true 时（目标进程 file==null）镜像进 LogStore 推回主进程 */
    private void logLocked(String line, boolean mirror) {
        String ts = FMT.format(new Date());
        String full = ts + " " + line;
        ring.addLast(full);
        while (ring.size() > RING_CAP) ring.removeFirst();
        try {
            Log.d(TAG, full);
        } catch (Throwable t) { /* logcat 失败忽略 */ }
        appendFile(full);
        // v1.42 P2-14: 目标进程（init 未拿到 filesDir，file==null）的调试日志镜像进 LogStore →
        //   随 push 通道回主进程 9900 → 主进程 LogPersister 落自己家。进程崩溃后调试日志也能在主进程查到。
        //   IN_LOGSTORE 双保险防递归（主线程内 LogStore.log 若回调 DebugLog 会被掐断）。
        if (mirror && file == null && !Boolean.TRUE.equals(IN_LOGSTORE.get())) {
            try {
                IN_LOGSTORE.set(Boolean.TRUE);
                LogStore.get().log("Dbg", full);
            } catch (Throwable t) { /* 镜像失败不影响调试日志本身 */ }
            finally {
                IN_LOGSTORE.remove();
            }
        }
    }

    /** 同步追加（v1.31.1 P3-5: 持 writer 复用；256KB 滚动时关闭重建；失败关闭下次重开） */
    private void appendFile(String line) {
        File f = file;
        if (f == null) return;
        try {
            if (f.length() > MAX_FILE) {
                // 滚动：删旧文件，从 0 开始（调试日志保留最近信息即可）
                closeWriter();
                boolean del = f.delete();
                if (!del) { /* 删除失败继续写（append） */ }
            }
            BufferedWriter w = writer;
            if (w == null) {
                w = new BufferedWriter(new OutputStreamWriter(
                        new FileOutputStream(f, true), StandardCharsets.UTF_8));
                writer = w;
            }
            w.write(line);
            w.newLine();
            w.flush();
            failed = false;
        } catch (Throwable t) {
            closeWriter(); // 写失败关闭，下次重开（避免持有坏 writer 一直写不进去）
            failed = true;
            try {
                Log.e(TAG, "debug log file write fail: " + t);
            } catch (Throwable t2) { }
        }
    }

    /** v1.31.1 P3-5: 关闭 writer（滚动/写失败时调用） */
    private void closeWriter() {
        BufferedWriter w = writer;
        writer = null;
        if (w != null) {
            try {
                w.close();
            } catch (Throwable t) { }
        }
    }

    /**
     * v1.30.2: 导出当前调试日志全文（内存环形 + 已落盘文件全文，重启后文件仍在）。
     * 背景：目标进程重启后环形清空，但 files/spyprobe_debug.log 保留——"越详细越好"不能丢。
     */
    public String dump() {
        synchronized (lock) {
            StringBuilder sb = new StringBuilder();
            for (String s : ring) {
                sb.append(s).append('\n');
            }
            File f = file;
            if (f != null && f.exists()) {
                sb.append("---- file: ").append(f.getAbsolutePath())
                  .append(" size=").append(f.length()).append('\n');
                // 环形被清空（进程重启过）或文件内容比环形多时，合并文件全文
                if (ring.isEmpty() || f.length() > ring.size() * 48L) {
                    try (java.io.BufferedReader r = new java.io.BufferedReader(
                            new java.io.InputStreamReader(new java.io.FileInputStream(f), StandardCharsets.UTF_8))) {
                        String line;
                        while ((line = r.readLine()) != null) {
                            sb.append(line).append('\n');
                        }
                    } catch (Throwable t) {
                        sb.append("(read debug file fail: ").append(t).append(")\n");
                    }
                }
            } else {
                sb.append("---- no debug file yet (filesDir 未拿到)\n");
            }
            // v1.53: 附加崩溃记录（主进程 files/spyprobe_crash.log；目标进程崩溃 push 回来也写这里）
            try {
                String crash = CrashCatcher.readCrashLog();
                if (crash != null) {
                    sb.append("---- crash log (spyprobe_crash.log) ----\n").append(crash);
                }
            } catch (Throwable t) {
                sb.append("(read crash log fail: ").append(t).append(")\n");
            }
            return sb.toString();
        }
    }

    public File file() { return file; }
}
