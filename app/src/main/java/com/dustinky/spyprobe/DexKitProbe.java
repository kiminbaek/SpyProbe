package com.dustinky.spyprobe;

import android.os.Environment;

import org.json.JSONArray;
import org.json.JSONObject;
import org.luckypray.dexkit.DexKitBridge;
import org.luckypray.dexkit.result.MethodData;
import org.luckypray.dexkit.query.FindMethod;
import org.luckypray.dexkit.query.matchers.MethodMatcher;

import java.io.File;
import java.util.Collections;
import java.util.List;

import io.github.libxposed.api.XposedModule;

/**
 * v1.9: DexKit 集成（借鉴 AdClose DexKitUtil）
 *
 *  1. 一键导出全部 dex -> /sdcard/Download/SpyProbeDump/<pkg>/（jadx 直接打开）
 *  2. 字符串反查：输入目标字符串 -> 返回引用它的 类#方法 列表（找校验/密钥/接口逻辑入口）
 *
 * DexKit 2.0.7：native 库（libdexkit.so）+ kotlin 依赖，APK 体积会增大。
 * 引用计数 + 延迟释放 + 缓存（照 AdClose 的 DexKitUtil 模式，单例 + create/close）。
 */
public class DexKitProbe {

    static final String TAG = "SpyProbe.DexKit";

    private final XposedModule module;
    private final ClassLoader appCl;
    private final String pkg;

    private volatile DexKitBridge bridge;
    private volatile boolean creating;

    public DexKitProbe(XposedModule module, ClassLoader appCl, String pkg) {
        this.module = module;
        this.appCl = appCl;
        this.pkg = pkg;
    }

    /** 延迟初始化（类加载稳定后调用）；重复调用幂等 */
    public synchronized void init() {
        if (bridge != null || creating) return;
        creating = true;
        try {
            bridge = DexKitBridge.create(appCl, true);
            LogStore.get().log(TAG, "DexKitBridge created for " + pkg);
        } catch (Throwable t) {
            LogStore.get().log(TAG, "DexKitBridge create fail: " + t);
        } finally {
            creating = false;
        }
    }

    public boolean isReady() {
        return bridge != null;
    }

    /** 导出全部 dex -> Download/SpyProbeDump/<pkg>/；无权限时 fallback 到 app 外部专属目录 */
    public String dumpDex() {
        init();
        if (bridge == null) return err("bridge not ready");
        try {
            File dir = null;
            try {
                File dl = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
                dir = new File(dl, "SpyProbeDump/" + pkg);
                if (!dir.exists() && !dir.mkdirs()) dir = null;
                // 验证可写（Android 11+ 无 MANAGE_EXTERNAL_STORAGE 时 mkdir 可能假成功）
                File probe = new File(dir, ".spyprobe_write_test");
                if (!probe.createNewFile()) dir = null;
                probe.delete();
            } catch (Throwable t) {
                dir = null;
            }
            if (dir == null) {
                // fallback：application 外部专属目录（无需权限）
                android.content.Context app = currentApp();
                File base = app != null ? app.getExternalFilesDir(null) : null;
                if (base == null) return err("no writable storage (grant storage permission)");
                dir = new File(base, "dex/" + pkg);
                if (!dir.exists() && !dir.mkdirs()) return err("mkdir fail: " + dir);
            }
            bridge.exportDexFile(dir.getAbsolutePath());
            File[] files = dir.listFiles();
            JSONArray arr = new JSONArray();
            long total = 0;
            if (files != null) {
                for (File f : files) {
                    if (f.isFile() && f.length() > 0) {
                        arr.put(f.getName() + " (" + (f.length() / 1024) + "KB)");
                        total += f.length();
                    }
                }
            }
            JSONObject o = new JSONObject();
            o.put("ok", true);
            o.put("dir", dir.getAbsolutePath());
            o.put("count", arr.length());
            o.put("totalKB", total / 1024);
            o.put("files", arr);
            LogStore.get().log(TAG, "dex exported: " + dir.getAbsolutePath() + " files=" + arr.length());
            return o.toString();
        } catch (Throwable t) {
            LogStore.get().log(TAG, "dex export fail: " + t);
            return err(t.toString());
        }
    }

    /** 字符串反查：返回引用该字符串的方法列表（类#方法#参数） */
    public String findMethods(String str) {
        if (str == null || str.trim().isEmpty()) return err("empty string");
        init();
        if (bridge == null) return err("bridge not ready");
        try {
            List<MethodData> methods = bridge.findMethod(FindMethod.create()
                    .matcher(MethodMatcher.create()
                            .usingStrings(Collections.singletonList(str.trim()))));
            JSONArray arr = new JSONArray();
            int shown = 0;
            for (MethodData m : methods) {
                if (shown >= 200) break; // 结果上限防卡
                shown++;
                JSONObject o = new JSONObject();
                try {
                    o.put("class", m.getDeclaredClassName());
                } catch (Throwable t) {
                    o.put("class", "?");
                }
                o.put("method", m.getMethodName());
                o.put("params", joinParams(m));
                try {
                    o.put("returnType", m.getReturnTypeName());
                } catch (Throwable t) {
                    o.put("returnType", "?");
                }
                arr.put(o);
            }
            JSONObject o = new JSONObject();
            o.put("ok", true);
            o.put("query", str.trim());
            o.put("total", methods.size());
            o.put("shown", shown);
            o.put("methods", arr);
            LogStore.get().log(TAG, "string-find \"" + str + "\" total=" + methods.size());
            return o.toString();
        } catch (Throwable t) {
            LogStore.get().log(TAG, "string-find fail: " + t);
            return err(t.toString());
        }
    }

    /** 释放 bridge（UI 手动触发/重启时） */
    public synchronized void close() {
        try {
            if (bridge != null) bridge.close();
        } catch (Throwable t) {
            LogStore.get().log(TAG, "bridge close fail: " + t);
        }
        bridge = null;
        LogStore.get().log(TAG, "DexKitBridge closed");
    }

    private static String joinParams(MethodData m) {
        try {
            List<String> ps = m.getParamTypeNames();
            if (ps == null || ps.isEmpty()) return "";
            StringBuilder sb = new StringBuilder();
            for (String p : ps) {
                if (sb.length() > 0) sb.append(", ");
                sb.append(p);
            }
            return sb.toString();
        } catch (Throwable t) {
            return "?";
        }
    }

    private static android.content.Context currentApp() {
        try {
            Class<?> at = Class.forName("android.app.ActivityThread");
            Object app = at.getMethod("currentApplication").invoke(null);
            return app instanceof android.content.Context ? (android.content.Context) app : null;
        } catch (Throwable t) {
            return null;
        }
    }

    private static String err(String msg) {
        try {
            JSONObject o = new JSONObject();
            o.put("ok", false);
            o.put("error", msg);
            return o.toString();
        } catch (Throwable t) {
            return "{\"ok\":false,\"error\":\"" + msg.replace("\\", "\\\\").replace("\"", "\\\"") + "\"}";
        }
    }
}
