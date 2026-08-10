package com.dustinky.spyprobe;

/*
 * v1.37 P0-5: 日志双端 token 信任模型（借鉴 Guise 显式组件+token 校验思想，自研实现）
 *
 * 【威胁】v1.32 起日志推回主进程 :9900，但 push_logs 无鉴权——本机任意 App 都能伪造
 *   日志/配置灌入主进程（污染分析 + 伪装探测结果）。
 * 【方案】
 *   主进程（SpyProbe 自己）生成随机 token：
 *     ① 写模块自己家 SharedPreferences("spyprobe_sec")  —— 目标进程经 getRemotePreferences 读取
 *     ② 写 files/spyprobe_token 文件                        —— SpyHomeServer 校验用（读文件最快）
 *   目标进程（hook 的 App 内）：
 *     ModuleMain.onPackageReady 调 TokenStore.remoteToken(module) 取 token，
 *     LogStore.flushPush 带 X-Spy-Token header。
 *   SpyHomeServer：
 *     校验 header 与 files/spyprobe_token 一致，不匹配拒绝（403）。
 *
 * 【为什么安全】token 存模块自己 data（App 沙箱隔离，其他 App 不可读）；
 *   目标进程只能通过 libxposed getRemotePreferences（框架 IPC 代读模块自己家）拿到——
 *   这个通道只有被 Xposed 加载的模块代码能访问，非模块 App 无法伪造。
 */

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import io.github.libxposed.api.XposedModule;

public class TokenStore {

    static final String TAG = "SpyProbe.Token";

    private static final String PREFS_NAME = "spyprobe_sec";
    private static final String KEY_TOKEN = "token";
    private static final String FILE_TOKEN = "spyprobe_token";

    // 主进程内存缓存（SpyHomeServer 校验用——server 是静态单例无 Context，这里保证一次生成全局可用）
    private static volatile String cachedHomeToken = "";

    /** 主进程 server 校验用：优先内存缓存，无则读文件；无 token 返回 ""（不校验） */
    public static String homeToken() {
        if (!cachedHomeToken.isEmpty()) return cachedHomeToken;
        return "";
    }

    /** 主进程首次生成后设置缓存（ensureToken 内部调用） */
    private static void cacheToken(String t) {
        if (t != null && !t.isEmpty()) cachedHomeToken = t;
    }

    // ===== 主进程侧 =====

    /** 主进程启动时调用：生成/加载 token，写 SharedPreferences + files 文件双保险 */
    public static String ensureToken(Context ctx) {
        try {
            // 1) files 文件（server 校验主通道）
            File f = new File(ctx.getFilesDir(), FILE_TOKEN);
            if (f.exists()) {
                String t = readFile(f);
                if (t != null && !t.isEmpty()) {
                    cacheToken(t);
                    // v1.40.1 P0 修复: 文件存在时也同步写 SharedPreferences——
                    // 旧实现直接 return，老版本升级后 SP 从未写入 → 目标进程
                    // getRemotePreferences 读空 → push_logs 不带 token → 401
                    try {
                        ctx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                                .edit().putString(KEY_TOKEN, t).commit();
                    } catch (Throwable t2) { }
                    return t;
                }
            }
            // 2) SharedPreferences（目标进程 getRemotePreferences 读取通道）
            SharedPreferences sp = ctx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
            String existing = sp.getString(KEY_TOKEN, "");
            if (!existing.isEmpty()) {
                writeFile(f, existing);
                cacheToken(existing);
                return existing;
            }
            // 生成新 token
            byte[] raw = new byte[24];
            new SecureRandom().nextBytes(raw);
            StringBuilder sb = new StringBuilder(raw.length * 2);
            for (byte b : raw) sb.append(String.format("%02x", b));
            String token = sb.toString();
            sp.edit().putString(KEY_TOKEN, token).apply();
            writeFile(f, token);
            cacheToken(token);
            DebugLog.get().log(TAG, "token generated len=" + token.length());
            return token;
        } catch (Throwable t) {
            Log.e(TAG, "ensureToken fail: " + t);
            return "";
        }
    }

    // ===== 目标进程侧 =====

    /**
     * v1.44.1: HTTP 从主进程 9900 拉 token（根治 libxposed 跨进程读在真机静默返回空）。
     * 用纯 Socket 手写 GET——不能用 HttpURLConnection（会被自己的 NetProbe hook 捕获造成递归，
     * v1.35 推送改纯 Socket 的教训同源）。能收到 401 就说明 9900 活着 → 这里必能拿到 token。
     */
    public static String homeTokenViaHttp() {
        try {
            java.net.Socket sock = new java.net.Socket();
            sock.setTcpNoDelay(true);
            sock.connect(new java.net.InetSocketAddress("127.0.0.1", 9900), 500);
            String head = "GET /api/token HTTP/1.1\r\nHost: 127.0.0.1:9900\r\nConnection: close\r\n\r\n";
            java.io.OutputStream os = sock.getOutputStream();
            os.write(head.getBytes(StandardCharsets.UTF_8));
            os.flush();
            java.io.BufferedReader br = new java.io.BufferedReader(
                    new java.io.InputStreamReader(sock.getInputStream(), StandardCharsets.UTF_8));
            StringBuilder body = new StringBuilder();
            boolean inHeader = true;
            String line;
            while ((line = br.readLine()) != null) {
                if (inHeader) {
                    if (line.trim().isEmpty()) inHeader = false;
                } else {
                    body.append(line);
                }
            }
            br.close();
            os.close();
            sock.close();
            if (body.length() > 0) {
                String t = new org.json.JSONObject(body.toString()).optString("token", "");
                if (!t.isEmpty()) return t;
            }
        } catch (Throwable t) {
            try { DebugLog.get().log(TAG, "homeTokenViaHttp fail: " + t); } catch (Throwable t2) { }
        }
        return "";
    }

    /** 目标进程（hook 的 App）取主进程 token；读不到返回 ""（老版本主进程不校验） */
    public static String remoteToken(XposedModule module) {
        // v1.44.1 P0 修复: HTTP 优先——libxposed 跨进程读（getRemotePreferences/openRemoteFile）
        //   真机静默返回空（v1.21 坑，v1.40.1 双通道全是同一坏通道未真正修好）。
        //   HTTP 走 9900 本机回环网络通道（已证明通——401 都能收到），100% 可靠。
        String viaHttp = homeTokenViaHttp();
        if (!viaHttp.isEmpty()) return viaHttp;
        // 兜底：9900 未起（主进程还没开 UI）时回退 libxposed 双通道（兼容老主进程）
        // v1.40.1 P0 修复: 双通道取 token——
        //   ① getRemotePreferences（v1.21 已知坑: 用户实测重启后仍失效，v1.22 才弃用）
        //   ② openRemoteFile 直读 files/spyprobe_token（libxposed 标准文件 IPC，更可靠）
        // 先试 SP；空/异常再读文件，避免 401。
        try {
            SharedPreferences sp = module.getRemotePreferences(PREFS_NAME);
            String t = sp.getString(KEY_TOKEN, "");
            if (t != null && !t.isEmpty()) return t;
        } catch (Throwable t) {
            DebugLog.get().log(TAG, "remoteToken prefs fail: " + t);
        }
        try {
            android.os.ParcelFileDescriptor pfd = module.openRemoteFile(FILE_TOKEN);
            if (pfd != null) {
                try (java.io.FileInputStream in = new java.io.FileInputStream(pfd.getFileDescriptor())) {
                    byte[] buf = new byte[256];
                    int n = in.read(buf);
                    if (n > 0) {
                        String t = new String(buf, 0, n, StandardCharsets.UTF_8).trim();
                        if (!t.isEmpty()) return t;
                    }
                } finally {
                    try { pfd.close(); } catch (Throwable t2) { }
                }
            }
        } catch (Throwable t) {
            DebugLog.get().log(TAG, "remoteToken file fail: " + t);
        }
        return "";
    }

    // ===== 工具 =====

    private static String readFile(File f) {
        try (FileInputStream in = new FileInputStream(f)) {
            byte[] buf = new byte[(int) f.length()];
            int n = 0;
            while (n < buf.length) {
                int k = in.read(buf, n, buf.length - n);
                if (k < 0) break;
                n += k;
            }
            return new String(buf, 0, n, StandardCharsets.UTF_8).trim();
        } catch (Throwable t) {
            return null;
        }
    }

    private static void writeFile(File f, String token) {
        try {
            File tmp = new File(f.getAbsolutePath() + ".tmp");
            try (FileOutputStream out = new FileOutputStream(tmp)) {
                out.write(token.getBytes(StandardCharsets.UTF_8));
            }
            if (!tmp.renameTo(f)) {
                try (FileOutputStream out2 = new FileOutputStream(f)) {
                    out2.write(token.getBytes(StandardCharsets.UTF_8));
                }
            }
        } catch (Throwable t) {
            Log.e(TAG, "writeFile fail: " + t);
        }
    }
}
