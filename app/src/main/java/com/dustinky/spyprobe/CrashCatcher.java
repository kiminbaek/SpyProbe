package com.dustinky.spyprobe;

/*
 * v1.53: 全局崩溃捕获 —— 让调试日志能抓到闪退
 *
 * 背景：用户"闪退从代码猜不出来" → 调试日志该有这个能力。
 *   - UI 进程（主进程）：handler 写 files/spyprobe_crash.log（自家 data，卸载前一直在）
 *   - 目标进程（被 hook 的 App）：handler ① 尝试 push 到主进程 9900 /api/push_crash →
 *     主进程落盘 files/spyprobe_crash.log（下次"发送调试日志"自动附上）；
 *     ② 同时写目标 data files/spyprobe_crash.log 兜底（root 可读）
 *   - 调试日志导出（DebugLog.dump）自动附加崩溃记录 → 用户发调试日志 = 闪退堆栈也到了
 *
 * 说明：本 handler 抓 Java 层未捕获异常（Xposed hook 回调抛错、主线程异常等）。
 *   native 层 SIGSEGV 仍由系统 tombstone 记录（v1.46.0 已根治 SSL_get_fd 方向错误那类闪退）。
 */

import android.content.Context;
import android.os.Process;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class CrashCatcher {

    static final String TAG = "SpyProbe.Crash";
    static final String FILE_NAME = "spyprobe_crash.log";
    static final int HOME_PORT = 9900;

    private static final SimpleDateFormat FMT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US);

    /** 主进程 filesDir（setHomeDir 设置；saveFromTarget 落盘用） */
    private static volatile File homeDir = null;

    private CrashCatcher() { }

    /** 主进程初始化：设置落盘目录 + 安装 handler（MainActivity.onCreate 调用） */
    public static void installMainProcess(Context ctx) {
        try {
            homeDir = ctx.getFilesDir();
            final Thread.UncaughtExceptionHandler prev = Thread.getDefaultUncaughtExceptionHandler();
            Thread.setDefaultUncaughtExceptionHandler((t, e) -> {
                try {
                    append(homeDir, t, e);
                } catch (Throwable t2) { /* 崩溃现场不保证 IO 成功 */ }
                if (prev != null) prev.uncaughtException(t, e);
                else Process.killProcess(Process.myPid());
            });
            DebugLog.get().logNoMirror("Crash", "CrashCatcher installed (main), file="
                    + (homeDir == null ? "null" : new File(homeDir, FILE_NAME).getAbsolutePath()));
        } catch (Throwable t) {
            DebugLog.get().logNoMirror("Crash", "installMainProcess FAIL: " + t);
        }
    }

    /** 目标进程：安装 handler（ModuleMain.onPackageReady 调用） */
    public static void installTargetProcess() {
        try {
            final Thread.UncaughtExceptionHandler prev = Thread.getDefaultUncaughtExceptionHandler();
            Thread.setDefaultUncaughtExceptionHandler((t, e) -> {
                String msg = dump(t, e);
                // ① 尝试 push 到主进程 9900（主进程落盘，调试日志导出可见）
                try { pushToHome(msg); } catch (Throwable t2) { }
                // ② 目标 data files/spyprobe_crash.log 兜底（root 可读；卸载后清）
                try {
                    File dir = targetFilesDir();
                    if (dir != null) append(dir, t, e);
                } catch (Throwable t2) { }
                if (prev != null) prev.uncaughtException(t, e);
                else Process.killProcess(Process.myPid());
            });
            DebugLog.get().logNoMirror("Crash", "CrashCatcher installed (target)");
        } catch (Throwable t) {
            DebugLog.get().logNoMirror("Crash", "installTargetProcess FAIL: " + t);
        }
    }

    /** 目标进程崩溃 push 到主进程的落盘入口（SpyHomeServer /api/push_crash 调用） */
    public static void saveFromTarget(String msg) {
        try {
            File f = homeDir == null ? null : new File(homeDir, FILE_NAME);
            if (f == null) {
                DebugLog.get().logNoMirror("Crash", "saveFromTarget skipped: homeDir==null");
                return;
            }
            synchronized (CrashCatcher.class) {
                f.getParentFile().mkdirs();
                try (FileOutputStream os = new FileOutputStream(f, true)) {
                    os.write((msg + "\n").getBytes(StandardCharsets.UTF_8));
                }
            }
        } catch (Throwable t) {
            DebugLog.get().logNoMirror("Crash", "saveFromTarget FAIL: " + t);
        }
    }

    /** 读取崩溃记录全文（DebugLog.dump 附加用）；无记录返回 null */
    public static String readCrashLog() {
        try {
            File f = homeDir == null ? null : new File(homeDir, FILE_NAME);
            if (f == null || !f.exists() || f.length() == 0) return null;
            StringBuilder sb = new StringBuilder();
            try (BufferedReader r = new BufferedReader(new InputStreamReader(
                    new FileInputStream(f), StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null) sb.append(line).append('\n');
            }
            return sb.toString();
        } catch (Throwable t) {
            return "(read crash log fail: " + t + ")\n";
        }
    }

    /** 崩溃文本格式化 */
    private static String dump(Thread t, Throwable e) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== SpyProbe crash @ ").append(FMT.format(new Date())).append(" ===").append('\n');
        sb.append("thread=").append(t == null ? "?" : t.getName())
          .append(" (id=").append(t == null ? "?" : t.getId()).append(')').append('\n');
        sb.append("process=").append(Process.myPid()).append('\n');
        sb.append("exception=").append(e == null ? "null" : e.getClass().getName())
          .append(": ").append(e == null ? "" : String.valueOf(e.getMessage())).append('\n');
        if (e != null) {
            for (StackTraceElement el : e.getStackTrace()) {
                sb.append("  at ").append(el).append('\n');
            }
            Throwable c = e.getCause();
            int depth = 0;
            while (c != null && depth++ < 10) {
                sb.append("Caused by: ").append(c).append('\n');
                for (StackTraceElement el : c.getStackTrace()) {
                    sb.append("  at ").append(el).append('\n');
                }
                c = c.getCause();
            }
        }
        return sb.toString();
    }

    /** 主进程落盘（UI 进程崩溃） */
    private static void append(File dir, Thread t, Throwable e) {
        File f = dir == null ? null : new File(dir, FILE_NAME);
        if (f == null) return;
        try {
            synchronized (CrashCatcher.class) {
                f.getParentFile().mkdirs();
                try (FileOutputStream os = new FileOutputStream(f, true)) {
                    os.write((dump(t, e) + "\n").getBytes(StandardCharsets.UTF_8));
                }
            }
        } catch (Throwable t2) { /* 崩溃现场不保证 IO 成功 */ }
    }

    /** 目标进程崩溃 → HTTP POST 主进程 9900 /api/push_crash（纯 Socket，崩溃场景最稳） */
    private static void pushToHome(String msg) throws Exception {
        byte[] body = msg.getBytes(StandardCharsets.UTF_8);
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress("127.0.0.1", HOME_PORT), 1500);
            s.setSoTimeout(1500);
            OutputStream os = s.getOutputStream();
            StringBuilder head = new StringBuilder();
            head.append("POST /api/push_crash HTTP/1.1\r\n");
            head.append("Host: 127.0.0.1:").append(HOME_PORT).append("\r\n");
            head.append("Content-Type: text/plain\r\n");
            head.append("Content-Length: ").append(body.length).append("\r\n");
            head.append("Connection: close\r\n\r\n");
            os.write(head.toString().getBytes(StandardCharsets.ISO_8859_1));
            os.write(body);
            os.flush();
            // 读响应（短超时，崩溃场景不阻塞）
            java.io.InputStream is = s.getInputStream();
            byte[] buf = new byte[256];
            try { while (is.read(buf) > 0) { /* drain */ } } catch (Throwable t) { }
        }
    }

    /** 目标进程 filesDir（反射 ActivityThread.currentApplication，失败返回 null） */
    private static File targetFilesDir() {
        try {
            Class<?> at = Class.forName("android.app.ActivityThread");
            Object app = at.getMethod("currentApplication").invoke(null);
            if (app instanceof Context) {
                return ((Context) app).getFilesDir();
            }
        } catch (Throwable t) { }
        return null;
    }
}
