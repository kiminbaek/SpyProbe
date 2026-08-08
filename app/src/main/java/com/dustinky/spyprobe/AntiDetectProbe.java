package com.dustinky.spyprobe;

import android.util.Log;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;

/**
 * v1.13: 反检测 hook 集（fckvip hook_hide_root / hook_hide_xposed 借鉴）
 *
 * 作用：隐藏 root / Xposed 痕迹，防止目标 App 检测到模块环境后拒绝运行。
 * 与 EnvProbe（探测端）互为镜像：EnvProbe 记录目标 App 检测到了什么，
 * 本模块伪装目标 App 看到的世界（探测端 ↔ 伪装端）。
 *
 * 开关（Config）：antiRoot / antiXposed，UI 设置页下发。
 *
 * 实现分两层：
 * 1. beforeHookedMethod —— 拦截 File.exists / Runtime.exec / SystemProperties.get / ClassLoader.loadClass
 * 2. afterHookedMethod —— 净化返回值（StackTraceElement.getClassName / BufferedReader.readLine / DexPathList$Element.toString / Method.getModifiers）
 */
public class AntiDetectProbe {

    static final String TAG = "SpyProbe.Anti";

    private final XposedModule module;
    private final ClassLoader appCl;

    public AntiDetectProbe(XposedModule module, ClassLoader appCl) {
        this.module = module;
        this.appCl = appCl;
    }

    /** root 检测特征文件（fckvip 黑名单精简版） */
    private static final String[] ROOT_FILES = {
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
            "/system/app/Superuser.apk", "/system/etc/init.d/99SuperSUDaemon",
            "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su",
            "/cache/su", "/system/.supersu", "/system/etc/.has_su_daemon",
            "/system/bin/.ext/.su", "/vendor/bin/su", "/vendor/xbin/su",
            "/system/app/Magisk.apk", "/data/adb/magisk", "/sbin/magisk",
            "/system/bin/app_process_xposed",
    };

    /** Xposed 特征类名（loadClass 拦截） */
    private static final Set<String> XPOSED_CLASSES = new HashSet<String>(Arrays.asList(
            "de.robv.android.xposed.XposedBridge",
            "de.robv.android.xposed.XposedHelpers",
            "de.robv.android.xposed.XC_MethodHook",
            "de.robv.android.xposed.XC_MethodReplacement",
            "de.robv.android.xposed.XposedInit",
            "com.swift.sandbox.SandHook",
            "com.swift.sandbox.XposedCompat",
            "io.github.libxposed",
            "io.github.libxposed.api",
            "io.github.libxposed.service",
            "org.lsposed.lspd"));

    private volatile boolean installed = false;

    /** 安装反检测 hook（线程安全，防重复装） */
    public synchronized void install() {
        if (installed) return;
        installed = true;
        try {
            // ===== 隐藏 root =====
            // File.exists(String) —— root 特征文件返回 false
            try {
                module.hook(java.io.File.class.getMethod("exists"))
                        .intercept((chain) -> {
                            if (!Config.get().antiRoot) return chain.proceed();
                            Object thiz = chain.getThisObject();
                            if (thiz instanceof java.io.File) {
                                String path = ((java.io.File) thiz).getPath();
                                if (isRootFile(path)) {
                                    LogStore.get().log(TAG, "[anti-root] File.exists(" + path + ") -> false");
                                    return Boolean.FALSE;
                                }
                            }
                            return chain.proceed();
                        });
            } catch (Throwable t) { }

            // File(String) 构造器 —— 构造 root 特征文件路径时拦截（fckvip 10000 号 hook）
            try {
                module.hook(java.io.File.class.getConstructor(String.class))
                        .intercept((chain) -> {
                            Object r = chain.proceed();
                            if (!Config.get().antiRoot) return r;
                            Object thiz = chain.getThisObject();
                            if (thiz instanceof java.io.File) {
                                String path = ((java.io.File) thiz).getPath();
                                if (isRootFile(path)) {
                                    LogStore.get().log(TAG, "[anti-root] File构造(" + path + ") 已拦截");
                                    // 把路径换成无害路径（防后续 exists 命中）
                                    try {
                                        java.lang.reflect.Field f = java.io.File.class.getDeclaredField("path");
                                        f.setAccessible(true);
                                        f.set(thiz, "/nonexistent/" + path.hashCode());
                                    } catch (Throwable t2) { }
                                }
                            }
                            return r;
                        });
            } catch (Throwable t) { }

            // Runtime.exec(String) / exec(String[]) —— 拦截 su / magisk 命令
            // v1.15 P1-1: 命中后返回 fake Process（不能 return null —— 调用方 waitFor() 直接 NPE 崩溃）
            try {
                for (Method m : Runtime.class.getDeclaredMethods()) {
                    if (!m.getName().equals("exec")) continue;
                    Class<?>[] pts = m.getParameterTypes();
                    if (pts.length >= 1 && (pts[0] == String.class || pts[0] == String[].class)) {
                        module.hook(m).intercept((chain) -> {
                            if (!Config.get().antiRoot) return chain.proceed();
                            List<Object> args = chain.getArgs();
                            // v1.16 P1-3: 兼容 exec(String) 与 exec(String[])（数组形式 join 后判断，此前数组漏拦）
                            String cmd;
                            Object a0 = args.get(0);
                            if (a0 instanceof String[]) {
                                StringBuilder sb = new StringBuilder();
                                for (String s : (String[]) a0) {
                                    if (sb.length() > 0) sb.append(' ');
                                    sb.append(s);
                                }
                                cmd = sb.toString().toLowerCase();
                            } else {
                                cmd = a0 == null ? "" : a0.toString().toLowerCase();
                            }
                            if (cmd.contains("su") || cmd.contains("magisk") || cmd.contains("busybox")
                                    || cmd.contains("which root") || cmd.contains("whoami")) {
                                LogStore.get().log(TAG, "[anti-root] Runtime.exec(" + cmd + ") 已拦截");
                                return fakeProcess();
                            }
                            return chain.proceed();
                        });
                    }
                }
            } catch (Throwable t) { }

            // SystemProperties.get(String) / get(String,String) —— key 含 xposed/magisk/su 返回空
            // v1.16 P2-4: 补 get(String,String) 重载（此前只 hook get(String)，带默认值的调用漏拦）
            try {
                Class<?> sysProp = Class.forName("android.os.SystemProperties", true, appCl);
                for (Method m : sysProp.getDeclaredMethods()) {
                    if (!m.getName().equals("get")) continue;
                    Class<?>[] pts = m.getParameterTypes();
                    if (pts.length == 1 && pts[0] == String.class) {
                        module.hook(m).intercept((chain) -> {
                            if (!Config.get().antiRoot && !Config.get().antiXposed) return chain.proceed();
                            List<Object> args = chain.getArgs();
                            String key = args.get(0) == null ? "" : args.get(0).toString().toLowerCase();
                            if (key.contains("xposed") || key.contains("magisk") || key.contains("supersu")
                                    || key.contains("frida") || key.contains("substrate")) {
                                LogStore.get().log(TAG, "[anti] SystemProperties.get(" + key + ") -> \"\"");
                                return "";
                            }
                            return chain.proceed();
                        });
                    } else if (pts.length == 2 && pts[0] == String.class && pts[1] == String.class) {
                        module.hook(m).intercept((chain) -> {
                            if (!Config.get().antiRoot && !Config.get().antiXposed) return chain.proceed();
                            List<Object> args = chain.getArgs();
                            String key = args.get(0) == null ? "" : args.get(0).toString().toLowerCase();
                            if (key.contains("xposed") || key.contains("magisk") || key.contains("supersu")
                                    || key.contains("frida") || key.contains("substrate")) {
                                LogStore.get().log(TAG, "[anti] SystemProperties.get(" + key + ",def) -> \"\"");
                                return "";
                            }
                            return chain.proceed();
                        });
                    }
                }
            } catch (Throwable t) { }

            // ===== 隐藏 Xposed =====
            // ClassLoader.loadClass(String) —— Xposed 特征类返回 null（"类不存在"语义，fckvip 18 号 hook）
            // v1.15 P0-2: 原来 proceed(new Object[]{"/system/app/classic.jar"}) 把类名替换成文件路径
            //   → loadClass 必然 ClassNotFoundException，目标 app 崩溃风险；且污染 ClassLoadProbe 记录。
            //   现在直接 return null：Class.forName 收到 null 抛 ClassNotFoundException，app 走正常"类不存在"分支。
            try {
                for (Method m : ClassLoader.class.getDeclaredMethods()) {
                    if (!m.getName().equals("loadClass") || m.getParameterTypes().length < 1) continue;
                    if (m.getParameterTypes()[0] != String.class) continue;
                    module.hook(m).intercept((chain) -> {
                        if (!Config.get().antiXposed) return chain.proceed();
                        List<Object> args = chain.getArgs();
                        String name = args.get(0) == null ? "" : args.get(0).toString();
                        if (containsXposed(name)) {
                            LogStore.get().log(TAG, "[anti-xposed] loadClass(" + name + ") -> null(类不存在)");
                            return null;
                        }
                        return chain.proceed();
                    });
                }
            } catch (Throwable t) { }

            // StackTraceElement.getClassName() —— 调用栈隐藏 xposed 痕迹（fckvip 20 号 hook）
            // v1.19 P0: 严禁用 thiz.toString() —— StackTraceElement.toString() 内部会调用 getClassName()，
            //   而 getClassName() 正被本 hook 拦截 → 回调内 toString() → 又进 hook → 无限递归爆栈。
            //   改用反射读私有字段 declaringClass（绕开 getClassName() 方法，不触发本 hook）。
            try {
                module.hook(StackTraceElement.class.getMethod("getClassName"))
                        .intercept((chain) -> {
                            if (!Config.get().antiXposed) return chain.proceed();
                            Object thiz = chain.getThisObject();
                            if (thiz == null) return chain.proceed();
                            String cls = null;
                            try {
                                java.lang.reflect.Field f = StackTraceElement.class.getDeclaredField("declaringClass");
                                f.setAccessible(true);
                                cls = (String) f.get(thiz);
                            } catch (Throwable t) { }
                            if (cls != null && (cls.contains("xposed") || cls.contains("Xposed") || cls.contains("lspd"))) {
                                return "";
                            }
                            return chain.proceed();
                        });
            } catch (Throwable t) { }

            // Modifier.isNative(int) —— 防 native 检测 Xposed 方法（fckvip 24 号 hook）
            // v1.15 P0-1: 原来 hook 静态方法 Modifier.isNative(int)（getThisObject 恒 null → 永久失效）。
            //   改为 hook 实例方法 Method.getModifiers()：对 xposed 特征类的 Method，返回值去掉 native 位（0x100）。
            try {
                module.hook(Method.class.getMethod("getModifiers"))
                        .intercept((chain) -> {
                            if (!Config.get().antiXposed) return chain.proceed();
                            Object thiz = chain.getThisObject();
                            if (thiz instanceof Method) {
                                Method m = (Method) thiz;
                                String declaring = m.getDeclaringClass().getName();
                                if (containsXposed(declaring)) {
                                    int mod = ((Integer) chain.proceed()).intValue();
                                    LogStore.get().log(TAG, "[anti-xposed] Method.getModifiers(" + declaring
                                            + "." + m.getName() + ") 去掉 native 位");
                                    return Integer.valueOf(mod & ~Modifier.NATIVE);
                                }
                            }
                            return chain.proceed();
                        });
            } catch (Throwable t) { }

            // BufferedReader.readLine() —— 净化包含 XposedBridge.jar 的输出（fckvip 26 号 hook）
            try {
                module.hook(BufferedReader.class.getMethod("readLine"))
                        .intercept((chain) -> {
                            if (!Config.get().antiXposed) return chain.proceed();
                            Object r = chain.proceed();
                            if (r instanceof String) {
                                String s = (String) r;
                                if (s.contains("XposedBridge.jar") || s.contains("libxposed")
                                        || s.contains("lspd") || s.contains("magisk")) {
                                    return "";
                                }
                            }
                            return r;
                        });
            } catch (Throwable t) { }

            // Class.getDeclaredField("disableHooks") —— 防 Xposed 卸载检测（fckvip 25 号 hook）
            try {
                module.hook(Class.class.getMethod("getDeclaredField", String.class))
                        .intercept((chain) -> {
                            if (!Config.get().antiXposed) return chain.proceed();
                            List<Object> args = chain.getArgs();
                            String name = args.get(0) == null ? "" : args.get(0).toString();
                            if (name.equals("disableHooks")) {
                                LogStore.get().log(TAG, "[anti-xposed] getDeclaredField(disableHooks) -> disableHook");
                                args.set(0, "disableHook");
                            }
                            return chain.proceed();
                        });
            } catch (Throwable t) { }

            LogStore.get().log(TAG, "[anti] AntiDetectProbe installed (antiRoot=" + Config.get().antiRoot
                    + " antiXposed=" + Config.get().antiXposed + ")");
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[anti] install error: " + t);
            installed = false;
        }
    }

    /** v1.15 P1-1: 假 Process（拦截 su/magisk exec 时返回，避免 NPE；waitFor 返回 1=失败语义） */
    private static Process fakeProcess() {
        return new Process() {
            @Override
            public OutputStream getOutputStream() { return new ByteArrayOutputStream(); }
            @Override
            public InputStream getInputStream() { return new ByteArrayInputStream(new byte[0]); }
            @Override
            public InputStream getErrorStream() { return new ByteArrayInputStream(new byte[0]); }
            @Override
            public int waitFor() { return 1; }
            @Override
            public int exitValue() { return 1; }
            @Override
            public void destroy() { }
        };
    }

    private static boolean isRootFile(String path) {
        if (path == null) return false;
        String p = path.toLowerCase();
        for (String rf : ROOT_FILES) {
            if (p.equals(rf) || p.equals(rf + ".xposed")) return true;
        }
        // 兜底：文件名含 su/magisk 且路径在常见系统目录
        if (p.startsWith("/system/") || p.startsWith("/sbin/") || p.startsWith("/vendor/")
                || p.startsWith("/data/adb/") || p.startsWith("/data/local/")) {
            String name = p.substring(p.lastIndexOf('/') + 1);
            if (name.equals("su") || name.equals("magisk") || name.equals("busybox")
                    || name.startsWith("su.") || name.startsWith("magisk")) {
                return true;
            }
        }
        return false;
    }

    private static boolean containsXposed(String s) {
        if (s == null) return false;
        String lower = s.toLowerCase();
        for (String c : XPOSED_CLASSES) {
            if (lower.contains(c.toLowerCase())) return true;
        }
        return false;
    }
}
