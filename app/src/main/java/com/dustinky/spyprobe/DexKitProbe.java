package com.dustinky.spyprobe;

import android.os.Environment;

import org.json.JSONArray;
import org.json.JSONObject;
import org.luckypray.dexkit.DexKitBridge;
import org.luckypray.dexkit.result.ClassData;
import org.luckypray.dexkit.result.MethodData;
import org.luckypray.dexkit.query.FindClass;
import org.luckypray.dexkit.query.FindMethod;
import org.luckypray.dexkit.query.enums.StringMatchType;
import org.luckypray.dexkit.query.matchers.ClassMatcher;
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
            // v1.20 P0-2: 显式加载 dexkit native 库 —— 之前缺 System.loadLibrary，
            // DexKitBridge.create 报 No implementation found for nativeInitDexKitByClassLoader，
            // 导致 DexKit 完全不可用。loadLibrary 幂等，重复调用无害。
            System.loadLibrary("dexkit");
            bridge = DexKitBridge.create(appCl, true);
            DebugLog.get().logNoMirror(TAG, "DexKitBridge created for " + pkg);
        } catch (Throwable t) {
            DebugLog.get().logNoMirror(TAG, "DexKitBridge create fail: " + t);
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
            DebugLog.get().logNoMirror(TAG, "dex exported: " + dir.getAbsolutePath() + " files=" + arr.length());
            return o.toString();
        } catch (Throwable t) {
            DebugLog.get().logNoMirror(TAG, "dex export fail: " + t);
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
            DebugLog.get().logNoMirror(TAG, "string-find \"" + str + "\" total=" + methods.size());
            return o.toString();
        } catch (Throwable t) {
            DebugLog.get().logNoMirror(TAG, "string-find fail: " + t);
            return err(t.toString());
        }
    }

    /**
     * v1.38 P2-8: 类名模糊搜索 → 自动生成 hook 清单（hooker gs 命令借鉴）
     *
     * 输入类名关键字（Contains 匹配，忽略大小写）→ 返回匹配类的全部方法列表。
     * 用户可直接把返回的 类#方法 复制到「探测」页手动 hook（MethodProbe 规则）。
     * 与 findMethods（字符串反查）互补：一个按方法内容找，一个按类名找。
     */
    public String findClassMethods(String pattern) {
        if (pattern == null || pattern.trim().isEmpty()) return err("empty pattern");
        init();
        if (bridge == null) return err("bridge not ready");
        try {
            java.util.List<ClassData> classes = bridge.findClass(FindClass.create()
                    .matcher(ClassMatcher.create()
                            .className(pattern.trim(), StringMatchType.Contains, true)));
            JSONArray arr = new JSONArray();
            int shown = 0;
            for (ClassData cd : classes) {
                if (shown >= 50) break; // 类上限防卡
                shown++;
                JSONObject o = new JSONObject();
                o.put("class", cd.getName());
                o.put("methodCount", cd.getMethodCount());
                JSONArray ms = new JSONArray();
                for (MethodData md : cd.getMethods()) {
                    if (ms.length() >= 60) break; // 每类方法上限
                    JSONObject mo = new JSONObject();
                    mo.put("method", md.getMethodName());
                    mo.put("params", joinParams(md));
                    try {
                        mo.put("returnType", md.getReturnTypeName());
                    } catch (Throwable t) {
                        mo.put("returnType", "?");
                    }
                    ms.put(mo);
                }
                o.put("methods", ms);
                arr.put(o);
            }
            JSONObject o = new JSONObject();
            o.put("ok", true);
            o.put("query", pattern.trim());
            o.put("total", classes.size());
            o.put("shown", shown);
            o.put("classes", arr);
            DebugLog.get().logNoMirror(TAG, "class-find \"" + pattern + "\" total=" + classes.size());
            return o.toString();
        } catch (Throwable t) {
            DebugLog.get().logNoMirror(TAG, "class-find fail: " + t);
            return err(t.toString());
        }
    }

    /**
     * v1.40 P0: 找混淆 OkHttpClient 类（类名含 "OkHttpClient"），返回类名字符串；未找到返回 null。
     * 依赖 dexKit 已初始化（ModuleMain t=5000ms init；调用方 findOkHttpClientClass 会检查 isReady）。
     */
    public String findOkHttpClientClass() {
        return findFirstClass("OkHttpClient");
    }

    /** v1.40 P0: 更宽匹配——类名含 "OkHttp" 的类（可能直接是 OkHttpClient 的变体/包装） */
    public String findOkHttpAnyClass() {
        return findFirstClass("OkHttp");
    }

    /**
     * v1.75 打磨 A3: 按方法特征找 OkHttpClient（连类名都混淆的极端场景兜底）。
     * 原理：okhttp 官方 proguard keep public API → OkHttpClient.newCall(okhttp3.Request) 方法签名稳定。
     * 不依赖类名含 "OkHttp" 特征，直接枚举所有 newCall 方法，参数含 okhttp3.Request 的声明类即 OkHttpClient。
     * 返回类名字符串；未找到返回 null。依赖 dexKit 已初始化。
     */
    public String findOkHttpClientByMethod() {
        if (bridge == null) return null;
        try {
            List<MethodData> methods = bridge.findMethod(FindMethod.create()
                    .matcher(MethodMatcher.create()
                            .name("newCall", StringMatchType.Equals, true)));
            if (methods == null || methods.isEmpty()) return null;
            for (MethodData md : methods) {
                try {
                    List<String> ps = md.getParamTypeNames();
                    if (ps == null || ps.size() != 1) continue;
                    if (!"okhttp3.Request".equals(ps.get(0))) continue;
                    String name = md.getDeclaredClassName();
                    if (name == null || name.isEmpty()) continue;
                    // 双重验证：类可加载且确有 newCall(okhttp3.Request)
                    Class<?> cls = Class.forName(name, false, appCl);
                    Class<?> req = Class.forName("okhttp3.Request", false, appCl);
                    cls.getMethod("newCall", req);
                    return name;
                } catch (Throwable t) { }
            }
            return null;
        } catch (Throwable t) {
            return null;
        }
    }

    private String findFirstClass(String needle) {
        if (bridge == null) return null;
        try {
            java.util.List<ClassData> classes = bridge.findClass(FindClass.create()
                    .matcher(ClassMatcher.create()
                            .className(needle, StringMatchType.Contains, true)));
            if (classes == null || classes.isEmpty()) return null;
            for (ClassData cd : classes) {
                try {
                    String name = cd.getName();
                    if (name == null || name.isEmpty()) continue;
                    // 验证该类确实可加载且含 newCall(Request)（防误匹配非 OkHttpClient 类）
                    Class<?> cls = Class.forName(name, false, appCl);
                    try {
                        Class<?> req = Class.forName("okhttp3.Request", false, appCl);
                        cls.getMethod("newCall", req);
                        return name;
                    } catch (Throwable t) {
                        // 无 newCall(Request)，继续找下一个
                    }
                } catch (Throwable t) { }
            }
            return null;
        } catch (Throwable t) {
            return null;
        }
    }

    /** 释放 bridge（UI 手动触发/重启时） */
    public synchronized void close() {
        try {
            if (bridge != null) bridge.close();
        } catch (Throwable t) {
            DebugLog.get().logNoMirror(TAG, "bridge close fail: " + t);
        }
        bridge = null;
        DebugLog.get().logNoMirror(TAG, "DexKitBridge closed");
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
