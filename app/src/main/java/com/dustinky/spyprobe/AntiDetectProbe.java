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

    /** root 检测特征文件（fckvip 黑名单精简版 + v1.38 P1-6 hooker bypass_root_detect 清单扩充：
     *   magisk 各路径 / KernelSU / SuperSU 安装目录 / Xposed 框架文件） */
    private static final String[] ROOT_FILES = {
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
            "/system/app/Superuser.apk", "/system/etc/init.d/99SuperSUDaemon",
            "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su",
            "/cache/su", "/system/.supersu", "/system/etc/.has_su_daemon",
            "/system/bin/.ext/.su", "/vendor/bin/su", "/vendor/xbin/su",
            "/system/app/Magisk.apk", "/data/adb/magisk", "/sbin/magisk",
            "/system/bin/app_process_xposed",
            // v1.38 P1-6 扩充
            "/sbin/.magisk", "/system/bin/magisk", "/system/xbin/magisk",
            "/data/adb/magisk.img", "/data/adb/magisk.db",
            "/data/adb/ksu", "/data/adb/ksud", "/system/bin/ksud", "/system/xbin/ksud",
            "/data/adb/kernelsu", "/data/adb/kerelsu",
            "/vendor/etc/init.d/99SuperSUDaemon", "/system/app/SuperSU", "/system/app/MagiskManager",
            "/system/framework/XposedBridge.jar", "/system/bin/app_process32_xposed", "/system/bin/app_process64_xposed",
            "/data/app/com.topjohnwu.magisk", "/data/app/eu.chainfire.supersu",
    };

    /** Xposed 特征类名（loadClass 拦截）—— v1.31.1 P2-6: 精确匹配+子包边界，避免误伤框架自身/其他含子串类 */
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

    // v1.44 (HMA Hide-My-Applist 借鉴，自定义版权"注明出处可摘取"):
    // 隐藏应用列表——目标 App 常用 pm.getInstalledPackages() 扫描已装模块（SpyProbe/LSPosed/Magisk）
    // 检测 Xposed 环境。HMA 在系统服务层 hook PMS filterAppAccessLPr/AppsFilter.shouldFilterApplication，
    // SpyProbe 作为目标进程 hook 模块，直接在 ApplicationPackageManager 层过滤更简单且同效。
    // 系统包（android/com.android.*）永不隐藏，防误伤系统组件。
    private static final Set<String> HIDE_PACKAGES = new HashSet<String>(Arrays.asList(
            "com.dustinky.spyprobe",                        // 自身
            "org.lsposed.lspd", "org.lsposed.manager",      // LSPosed
            "com.topjohnwu.magisk", "io.github.vvb2060.magisk", // Magisk
            "de.robv.android.xposed.installer",             // Xposed Installer
            "eu.chainfire.supersu", "com.koushikdutta.superuser", // SuperSU / Superuser
            "me.weishu.kernelsu",                           // KernelSU
            "com.android.vending"));                        // Google Play（部分检测看商店数量）

    /** v1.44: 判断包名是否应隐藏（系统包永不隐藏） */
    private static boolean isHiddenPkg(String pkg) {
        if (pkg == null) return false;
        if (pkg.equals("android") || pkg.startsWith("android.") || pkg.startsWith("com.android.")) return false;
        return HIDE_PACKAGES.contains(pkg);
    }

    /** v1.44: 应用列表过滤通用逻辑（保持"少几个应用"自然语义，不返回 null/空） */
    private static <T> java.util.List<T> filterHiddenPkgs(java.util.List<T> list, String logTag) {
        java.util.List<T> kept = new java.util.ArrayList<T>();
        for (T item : list) {
            String pkg = pkgNameOf(item);
            if (pkg != null && isHiddenPkg(pkg)) {
                LogStore.get().log(TAG, "[anti-applist] " + logTag + " 过滤 " + pkg);
            } else {
                kept.add(item);
            }
        }
        return kept;
    }

    /** v1.44: 从 PackageInfo/ApplicationInfo/ResolveInfo 取包名（反射，避免硬依赖具体类型） */
    private static String pkgNameOf(Object item) {
        if (item == null) return null;
        try {
            if (item instanceof android.content.pm.PackageInfo) {
                return ((android.content.pm.PackageInfo) item).packageName;
            }
            if (item instanceof android.content.pm.ApplicationInfo) {
                return ((android.content.pm.ApplicationInfo) item).packageName;
            }
            if (item instanceof android.content.pm.ResolveInfo) {
                android.content.pm.ResolveInfo ri = (android.content.pm.ResolveInfo) item;
                if (ri.activityInfo != null) return ri.activityInfo.packageName;
                if (ri.serviceInfo != null) return ri.serviceInfo.packageName;
                if (ri.providerInfo != null) return ri.providerInfo.packageName;
                return ri.resolvePackageName;
            }
        } catch (Throwable t) { }
        return null;
    }

    private volatile boolean installed = false;

    /** 安装反检测 hook（线程安全，防重复装） */
    public synchronized void install() {
        // v1.37 P0-1: 惰性安装——antiRoot/antiXposed 都关闭时完全不装反检测 hook
        // v1.44: 加 antiApplist 条件（三开关全关才跳过）
        if (!Config.get().antiRoot && !Config.get().antiXposed && !Config.get().antiApplist) {
            DebugLog.get().log("AntiDetect", "install() skipped: antiRoot/antiXposed/antiApplist all false");
            return;
        }
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
            // v1.31.1 P3-8: 改 path 时同步改 pathBytes（File 内部字段，不一致会导致 equals/hashCode 与 getPath 矛盾）
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
                                    String fake = "/nonexistent/" + path.hashCode();
                                    try {
                                        java.lang.reflect.Field f = java.io.File.class.getDeclaredField("path");
                                        f.setAccessible(true);
                                        f.set(thiz, fake);
                                    } catch (Throwable t2) { }
                                    try {
                                        java.lang.reflect.Field fb = java.io.File.class.getDeclaredField("pathBytes");
                                        fb.setAccessible(true);
                                        fb.set(thiz, fake.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                                    } catch (Throwable t2) { }
                                }
                            }
                            return r;
                        });
            } catch (Throwable t) { }

            // v1.38 P1-6: hooker bypass_root_detect 借鉴——File.listFiles() 过滤 root 特征文件
            //   （App 常 list /system/bin 等目录找 su/magisk 可执行文件；exists 单独 hook 拦不住目录列举）
            try {
                module.hook(java.io.File.class.getMethod("listFiles"))
                        .intercept((chain) -> {
                            Object r = chain.proceed();
                            if (!Config.get().antiRoot) return r;
                            if (r instanceof java.io.File[]) {
                                java.io.File[] arr = (java.io.File[]) r;
                                java.util.List<java.io.File> kept = new java.util.ArrayList<java.io.File>();
                                for (java.io.File f : arr) {
                                    if (isRootFile(f.getPath())) {
                                        LogStore.get().log(TAG, "[anti-root] File.listFiles 过滤 " + f.getPath());
                                    } else {
                                        kept.add(f);
                                    }
                                }
                                return kept.toArray(new java.io.File[0]);
                            }
                            return r;
                        });
            } catch (Throwable t) { }
            // File.listFiles(FileFilter) / listFiles(FilenameFilter) —— 带过滤器的列举
            try {
                module.hook(java.io.File.class.getMethod("listFiles", java.io.FileFilter.class))
                        .intercept((chain) -> {
                            Object r = chain.proceed();
                            if (!Config.get().antiRoot) return r;
                            if (r instanceof java.io.File[]) {
                                java.io.File[] arr = (java.io.File[]) r;
                                java.util.List<java.io.File> kept = new java.util.ArrayList<java.io.File>();
                                for (java.io.File f : arr) {
                                    if (isRootFile(f.getPath())) {
                                        LogStore.get().log(TAG, "[anti-root] File.listFiles(filter) 过滤 " + f.getPath());
                                    } else {
                                        kept.add(f);
                                    }
                                }
                                return kept.toArray(new java.io.File[0]);
                            }
                            return r;
                        });
            } catch (Throwable t) { }

            // v1.38 P1-6: File.canRead() / canExecute() —— root 特征文件不可读/不可执行
            try {
                module.hook(java.io.File.class.getMethod("canRead"))
                        .intercept((chain) -> {
                            if (!Config.get().antiRoot) return chain.proceed();
                            Object thiz = chain.getThisObject();
                            if (thiz instanceof java.io.File && isRootFile(((java.io.File) thiz).getPath())) {
                                return Boolean.FALSE;
                            }
                            return chain.proceed();
                        });
                module.hook(java.io.File.class.getMethod("canExecute"))
                        .intercept((chain) -> {
                            if (!Config.get().antiRoot) return chain.proceed();
                            Object thiz = chain.getThisObject();
                            if (thiz instanceof java.io.File && isRootFile(((java.io.File) thiz).getPath())) {
                                return Boolean.FALSE;
                            }
                            return chain.proceed();
                        });
                LogStore.get().log(TAG, "[anti-root] hooked File.listFiles/canRead/canExecute (v1.38 P1-6)");
            } catch (Throwable t) { }

            // v1.38 P1-6: Debug.isDebuggerConnected() -> false —— 防调试器检测（常见 root 检测前置项）
            try {
                module.hook(android.os.Debug.class.getMethod("isDebuggerConnected"))
                        .intercept((chain) -> {
                            if (!Config.get().antiRoot) return chain.proceed();
                            return Boolean.FALSE;
                        });
                LogStore.get().log(TAG, "[anti-root] hooked Debug.isDebuggerConnected (v1.38 P1-6)");
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
                            // v1.19 P1-1: su 改独立 token 匹配（cmd.contains("su") 会误伤 status/measure/ensure 等）
                            if (isSuCmd(cmd) || cmd.contains("magisk") || cmd.contains("busybox")
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
            // v1.38 P1-6: 净化扩展——su/magisk/ksu 可执行输出（ps/which 结果）也拦
            try {
                module.hook(BufferedReader.class.getMethod("readLine"))
                        .intercept((chain) -> {
                            if (!Config.get().antiXposed) return chain.proceed();
                            Object r = chain.proceed();
                            if (r instanceof String) {
                                String s = (String) r;
                                if (s.contains("XposedBridge.jar") || s.contains("libxposed")
                                        || s.contains("lspd") || s.contains("magisk")
                                        || s.contains("KernelSU") || s.contains("ksud")
                                        || s.contains("/system/bin/su") || s.contains("/system/xbin/su")
                                        || s.contains("/sbin/su") || s.contains("Superuser.apk")
                                        || s.contains("which su") || s.equalsIgnoreCase("su")) {
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

            // ===== 隐藏应用列表（v1.44 HMA 借鉴）=====
            // 目标 App 最常见的 Xposed/root 检测：pm.getInstalledPackages() 扫已装应用，看有没有
            // SpyProbe/LSPosed/Magisk。hook ApplicationPackageManager（PackageManager 的实现类，
            // 目标进程实际持有的对象）过滤返回列表；getPackageInfo 直接抛"未安装"。
            // 注意：hook 实现类方法而非接口方法（libxposed 无法 hook 无实现体的接口方法）。
            try {
                Class<?> apmCls = Class.forName("android.app.ApplicationPackageManager", true, appCl);
                // getInstalledPackages(int) -> List<PackageInfo>
                try {
                    module.hook(apmCls.getMethod("getInstalledPackages", int.class))
                            .intercept((chain) -> {
                                if (!Config.get().antiApplist) return chain.proceed();
                                Object r = chain.proceed();
                                if (r instanceof List) {
                                    @SuppressWarnings("unchecked")
                                    List<Object> list = (List<Object>) r;
                                    return filterHiddenPkgs(list, "getInstalledPackages");
                                }
                                return r;
                            });
                } catch (Throwable t) { }
                // getInstalledApplications(int) -> List<ApplicationInfo>
                try {
                    module.hook(apmCls.getMethod("getInstalledApplications", int.class))
                            .intercept((chain) -> {
                                if (!Config.get().antiApplist) return chain.proceed();
                                Object r = chain.proceed();
                                if (r instanceof List) {
                                    @SuppressWarnings("unchecked")
                                    List<Object> list = (List<Object>) r;
                                    return filterHiddenPkgs(list, "getInstalledApplications");
                                }
                                return r;
                            });
                } catch (Throwable t) { }
                // queryIntentActivities(Intent, int) -> List<ResolveInfo>
                try {
                    module.hook(apmCls.getMethod("queryIntentActivities",
                                    android.content.Intent.class, int.class))
                            .intercept((chain) -> {
                                if (!Config.get().antiApplist) return chain.proceed();
                                Object r = chain.proceed();
                                if (r instanceof List) {
                                    @SuppressWarnings("unchecked")
                                    List<Object> list = (List<Object>) r;
                                    return filterHiddenPkgs(list, "queryIntentActivities");
                                }
                                return r;
                            });
                } catch (Throwable t) { }
                // getPackageInfo(String, int) -> 隐藏包抛 NameNotFoundException（"未安装"语义）
                try {
                    module.hook(apmCls.getMethod("getPackageInfo", String.class, int.class))
                            .intercept((chain) -> {
                                if (!Config.get().antiApplist) return chain.proceed();
                                List<Object> args = chain.getArgs();
                                String pkg = args.get(0) == null ? "" : args.get(0).toString();
                                if (isHiddenPkg(pkg)) {
                                    LogStore.get().log(TAG, "[anti-applist] getPackageInfo(" + pkg
                                            + ") -> NameNotFoundException");
                                    throw new android.content.pm.PackageManager.NameNotFoundException(pkg);
                                }
                                return chain.proceed();
                            });
                } catch (Throwable t) { }
                LogStore.get().log(TAG, "[anti-applist] hooked getInstalledPackages/getInstalledApplications/"
                        + "queryIntentActivities/getPackageInfo (HMA 借鉴, v1.44)");
            } catch (Throwable t) {
                LogStore.get().log(TAG, "[anti-applist] hook error: " + t);
            }

            LogStore.get().log(TAG, "[anti] AntiDetectProbe installed (antiRoot=" + Config.get().antiRoot
                    + " antiXposed=" + Config.get().antiXposed
                    + " antiApplist=" + Config.get().antiApplist + ")");
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
            public void destroy() { }        };
    }

    /** v1.19 P1-1: su 独立 token 匹配（避免误伤 status/measure/ensure 等含 "su" 子串的命令） */
    private static boolean isSuCmd(String cmd) {
        if (cmd == null || cmd.isEmpty()) return false;
        return cmd.equals("su") || cmd.startsWith("su ") || cmd.endsWith(" su")
                || cmd.contains(" su ") || cmd.contains("su -") || cmd.contains("su -c")
                || cmd.contains("which su") || cmd.contains("\\su");
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

    /** v1.31.1 P2-6: 精确匹配 + 子包边界（"io.github.libxposed" 只匹配自身或 . 子包，不匹配 "notio.github.libxposed" 等含子串类） */
    private static boolean containsXposed(String s) {
        if (s == null) return false;
        String lower = s.toLowerCase();
        for (String c : XPOSED_CLASSES) {
            String cl = c.toLowerCase();
            if (lower.equals(cl) || lower.startsWith(cl + ".")) return true;
        }
        return false;
    }
}
