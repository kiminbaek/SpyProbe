package com.dustinky.spyprobe;

import android.util.Log;

import java.lang.reflect.Method;

import io.github.libxposed.api.XposedModule;

/**
 * App 日志拦截（v1.5 新增）：
 * hook android.util.Log.d/i/e/w/v，记录目标 App 自己打的日志。
 * 反编译神器：多数 app 上线前没删 Log，日志直接泄露 URL/状态/错误/逻辑走向。
 * 默认开（logcatCapture=true），但高频日志会刷屏，设置里可关。
 * 记录格式：[Log.d] tag: msg
 */
public class LogCatProbe {

    static final String TAG = "SpyProbe.Log";

    private final XposedModule module;

    public LogCatProbe(XposedModule module) {
        this.module = module;
    }

    // v1.6: 系统 tag 黑名单（app 进程内 Android framework 也在打 Log，排除系统噪音）
    private static final java.util.Set<String> SYSTEM_TAGS = new java.util.HashSet<>(java.util.Arrays.asList(
            "AndroidRuntime", "System", "System.err", "System.out", "ActivityManager", "ActivityTaskManager",
            "ActivityThread", "ViewRootImpl", "InputDispatcher", "Choreographer", "OpenGLRenderer",
            "libEGL", "hwui", "zygote", "art", "dalvikvm", "NetworkSecurityConfig", "StrictMode",
            "Instrumentation", "WindowManager", "PackageManager", "ContextImpl", "Binder",
            "GraphicsEnvironment", "Looper", "MessageQueue", "View", "WifiService", "ConnectivityService",
            "NetworkMonitor", "DnsResolver", "Resolv", "TrafficStats", "libc", "SurfaceFlinger",
            "InputMethodManager", "InsetsController", "ViewRootImpl", "DecorView", "PhoneWindow",
            "AlarmManager", "JobScheduler", "DropBoxManager", "MediaCodec", "AudioTrack", "AudioFlinger",
            "OMXClient", "libprocessgroup", "SELinux", "AppOps", "Activity", "FragmentManager",
            "ResourcesManager", "Bitmap", "Skia", "skia", "Gralloc", "Vulkan", "EGL_emulation"
    ));

    /** v1.6: 是否系统噪音 tag（黑名单精确匹配，空 tag 也跳过） */
    private static boolean isSystemNoise(Object tag) {
        if (tag == null) return true;
        String t = tag.toString();
        if (t.isEmpty()) return true;
        // 精确匹配黑名单
        if (SYSTEM_TAGS.contains(t)) return true;
        // 前缀模式（如 AndroidRuntime-xxx / System-xxx）
        for (String s : SYSTEM_TAGS) {
            if (t.startsWith(s + "-") || t.startsWith(s + ":")) return true;
        }
        return false;
    }

    public void install(String phase) {
        String[] levels = {"d", "i", "e", "w", "v"};
        int hooked = 0;
        for (String lv : levels) {
            // 两种重载：level(String tag, String msg) 和 level(String tag, String msg, Throwable tr)
            for (int argc = 2; argc <= 3; argc++) {
                try {
                    Method m;
                    if (argc == 2) {
                        m = Log.class.getMethod(lv, String.class, String.class);
                    } else {
                        m = Log.class.getMethod(lv, String.class, String.class, Throwable.class);
                    }
                    final String fLv = lv;
                    module.hook(m).intercept(chain -> {
                        Object r = chain.proceed();
                        if (Config.get().logcatCapture) {
                            try {
                                Object tag = chain.getArg(0);
                                // v1.6: 系统噪音 tag 过滤（防刷屏 + 减性能开销）
                                if (isSystemNoise(tag)) return r;
                                Object msg = chain.getArg(1);
                                String m1 = msg == null ? "null" : String.valueOf(msg);
                                if (m1.length() > 500) m1 = m1.substring(0, 500) + "...(" + m1.length() + ")";
                                LogStore.get().log(TAG, "[Log." + fLv + "] " + tag + ": " + m1);
                            } catch (Throwable t) { }
                        }
                        return r;
                    });
                    hooked++;
                } catch (Throwable t) { }
            }
        }
        LogStore.get().log(TAG, "[" + phase + "] hooked Log d/i/e/w/v x" + hooked);
    }
}
