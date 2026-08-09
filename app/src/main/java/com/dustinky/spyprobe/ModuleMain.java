package com.dustinky.spyprobe;

/*
 * SpyProbe —— 通用逆向探测 / 抓包工作台
 * Copyright (c) 2026 kiminbaek（原作者）
 * 许可证：SpyProbe 自定义许可证（不可商用，二次开发需注明原作者版权）
 * 详见项目根 LICENSE / README.md：https://github.com/kiminbaek/SpyProbe
 */

import android.util.Log;

import io.github.libxposed.api.XposedModule;

/**
 * SpyProbe 逆向探测模块入口
 *
 * 在目标 App 进程内：
 * 1. 安装网络抓包 hook（SSL 绕过 / OkHttp / HttpURLConnection）
 * 2. 启动本地 HTTP server（127.0.0.1:9901）
 * UI（MainActivity）通过 HTTP 拉取日志、下发配置、探测函数。
 *
 * v1.6：
 *   - 7 个延迟线程合并为 1 个调度线程（按时间点依次安装各探测）
 *   - hook/hijack 规则持久化到模块远程偏好（getRemotePreferences），进程重启自动重挂
 */
public class ModuleMain extends XposedModule {

    static final String TAG = "SpyProbe";

    @Override
    public void onPackageLoaded(PackageLoadedParam param) {
        log(Log.INFO, TAG, "onPackageLoaded: " + param.getPackageName());
    }

    @Override
    public void onPackageReady(PackageReadyParam param) {
        log(Log.INFO, TAG, "onPackageReady: " + param.getPackageName());
        final String pkg = param.getPackageName();
        final ClassLoader cl = param.getClassLoader();

        NetProbe net = new NetProbe(this, cl);
        MethodProbe mth = new MethodProbe(this, cl);
        // v1.19 探测 b: 传入 mth 供类加载自动 hook 联动
        ClassLoadProbe clsProbe = new ClassLoadProbe(this, cl, mth);
        PrefsProbe prefs = new PrefsProbe(this);
        SQLiteProbe sqlite = new SQLiteProbe(this);
        // v1.5: 反编译增强探测
        UrlProbe urlProbe = new UrlProbe(this, cl);
        CryptoProbe crypto = new CryptoProbe(this);
        LogCatProbe logcat = new LogCatProbe(this);
        ActivityProbe act = new ActivityProbe(this);
        JsonProbe json = new JsonProbe(this, cl);
        // v1.9: 环境检测探测 + DexKit（导出 dex / 字符串反查）
        EnvProbe env = new EnvProbe(this, cl);
        DexKitProbe dexKit = new DexKitProbe(this, cl, pkg);
        // v1.13: 反检测 hook 集（隐藏 root/Xposed，防目标 App 检测）
        AntiDetectProbe anti = new AntiDetectProbe(this, cl);
        // v1.22: 抓包开关持久化文件——目标 App 自身 data 目录（零 IPC，重启必恢复）
        // v1.25 P2-9: hook/hijack 规则持久化同目录文件（spyprobe_rules.json），弃用远程偏好
        final java.io.File cfgFile = resolveCfgFile();
        // v1.29: 日志持久化初始化（DebugLog 三保险：内存环形 + 落盘 + logcat）
        // v1.29 修复：原实现 currentApplication() 返回 null 时静默跳过 → dir=null 一行不写盘且无痕迹。
        // 现在：立即尝试 + 延迟重试（1s/3s/10s），任何失败写 DebugLog。
        DebugLog.get().init(appFilesDirOrNull());
        initLogPersister("early", 0);
        scheduleLogPersisterRetry(1000);
        scheduleLogPersisterRetry(3000);
        scheduleLogPersisterRetry(10000);
        SpyServer server = new SpyServer(net, mth, clsProbe, pkg, dexKit, cfgFile);

        // 立即装网络 hook
        net.install("early");

        // v1.5: URL 构造捕捉（尽早装，URL 在启动期就大量构造）
        try {
            urlProbe.install("early");
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "url probe install error: " + t);
        }

        // v1.5: App 日志拦截（尽早装）
        try {
            logcat.install("early");
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "logcat probe install error: " + t);
        }

        // v1.6: 单个调度线程按时间点依次安装延迟探测 + 持久化规则重挂
        // v1.8: 延迟安装的探测 phase 统一标 "late"（此前误标 "early" 误导日志）
        new Thread(() -> {
            // t=1500ms: 类加载探测（延迟确保类加载器稳定）
            try {
                Thread.sleep(1500);
                clsProbe.install("late");
            } catch (Throwable t) {
                log(Log.ERROR, TAG, "class probe install error: " + t);
            }

            // t=2000ms: 加密/Activity/JSON/SharedPreferences + 环境检测 + server
            try {
                Thread.sleep(500);
                // v1.22: 恢复用户抓包开关——必须在所有延迟探测安装 + server.start() 之前，
                // 否则 UI 连上 server 先拿到默认配置、probe 也按默认开关记录
                Config.get().loadConfig(cfgFile);
                // v1.10: native 层抓包（libc + SSL_write/SSL_read + HTTP/2），越早装越好
                try {
                    NativeProbe.init();
                } catch (Throwable t) {
                    log(Log.ERROR, TAG, "native probe init error: " + t);
                }
                // v1.23: 每个延迟探测单独 try-catch——任何一个装失败不能拖垮 server 启动
                try { crypto.install("late"); } catch (Throwable t) { log(Log.ERROR, TAG, "crypto probe install error: " + t); }
                try { act.install("late"); } catch (Throwable t) { log(Log.ERROR, TAG, "activity probe install error: " + t); }
                try { json.install("late"); } catch (Throwable t) { log(Log.ERROR, TAG, "json probe install error: " + t); }
                try { prefs.install("late"); } catch (Throwable t) { log(Log.ERROR, TAG, "prefs probe install error: " + t); }
                try { env.install("late"); } catch (Throwable t) { log(Log.ERROR, TAG, "env probe install error: " + t); }
                // v1.13: 反检测 hook 集（延迟装；hook File/Runtime 等高频类，避开启动风暴）
                try {
                    anti.install();
                } catch (Throwable t) {
                    log(Log.ERROR, TAG, "anti-detect install error: " + t);
                }
            } catch (Throwable t) {
                log(Log.ERROR, TAG, "deferred probe install error: " + t);
            }
            // v1.23: server 启动独立 try-catch——无论探测装没装上，server 必须起来（UI 才能连）
            try {
                server.start();
            } catch (Throwable t) {
                log(Log.ERROR, TAG, "server start error: " + t);
            }

            // t=2500ms: SQLite 记录
            try {
                Thread.sleep(500);
                sqlite.install("late");
            } catch (Throwable t) {
                log(Log.ERROR, TAG, "sqlite probe install error: " + t);
            }

            // t=5000ms: DexKit 初始化（导出 dex / 字符串反查，等类加载稳定）+ 持久化 hook/hijack 规则重挂
            try {
                Thread.sleep(2500);
                dexKit.init();
                // v1.25 P2-9: 规则从文件加载（与 cfgFile 同目录，零 IPC）
                java.io.File rulesFile = (cfgFile != null && cfgFile.getParentFile() != null)
                        ? new java.io.File(cfgFile.getParentFile(), "spyprobe_rules.json") : null;
                boolean loaded = Config.get().loadRules(rulesFile);
                if (loaded) log(Log.INFO, TAG, "loaded persisted hook rules, re-hooking...");
                for (Config.HookSpec spec : Config.get().hooks) {
                    if (!spec.enabled) continue;
                    try {
                        mth.hookMethod(spec.className, spec.methodName, spec.paramTypes);
                    } catch (Throwable t) {
                        LogStore.get().log(TAG, "re-hook fail: " + spec.className + "." + spec.methodName + " : " + t);
                    }
                }
                if (loaded) LogStore.get().log(TAG, "re-hook done, rules=" + Config.get().hooks.size()
                        + " hijacks=" + Config.get().hijacks.size());
            } catch (Throwable t) {
                log(Log.ERROR, TAG, "re-hook error: " + t);
            }
        }, "SpyProbe-Scheduler").start();

        log(Log.INFO, TAG, "SpyProbe ready for " + pkg);
    }

    /** v1.22: 目标 App data 目录下的抓包开关持久化文件（files/spyprobe_cfg.json）；失败返回 null */
    private static java.io.File resolveCfgFile() {
        try {
            Class<?> at = Class.forName("android.app.ActivityThread");
            Object app = at.getMethod("currentApplication").invoke(null);
            if (app != null) {
                java.io.File filesDir = (java.io.File) app.getClass().getMethod("getFilesDir").invoke(app);
                if (filesDir != null) return new java.io.File(filesDir, "spyprobe_cfg.json");
            }
        } catch (Throwable t) { }
        return null;
    }

    /** v1.29: 反射拿目标 App filesDir；失败返回 null（不静默，写 DebugLog） */
    private static java.io.File appFilesDirOrNull() {
        try {
            Class<?> at = Class.forName("android.app.ActivityThread");
            Object app = at.getMethod("currentApplication").invoke(null);
            if (app == null) {
                DebugLog.get().log("ModuleMain", "currentApplication()=null（onPackageReady 早期）");
                return null;
            }
            java.io.File filesDir = (java.io.File) app.getClass().getMethod("getFilesDir").invoke(app);
            if (filesDir == null) {
                DebugLog.get().log("ModuleMain", "getFilesDir()=null");
                return null;
            }
            return filesDir;
        } catch (Throwable t) {
            DebugLog.get().log("ModuleMain", "appFilesDirOrNull error: " + t);
            return null;
        }
    }

    /** v1.29: 初始化 LogPersister（幂等：dir 已设则跳过）；成功/失败都留痕 */
    private static void initLogPersister(String phase, int attempt) {
        try {
            java.io.File filesDir = appFilesDirOrNull();
            if (filesDir != null) {
                if (LogPersister.get().isInitialized()) {
                    DebugLog.get().log("Persist", phase + " attempt#" + attempt + " 已初始化，跳过");
                } else {
                    LogPersister.get().init(filesDir);
                    DebugLog.get().log("Persist", phase + " attempt#" + attempt + " init 完成 dir="
                            + LogPersister.get().dirPath());
                }
            } else {
                DebugLog.get().log("Persist", phase + " attempt#" + attempt + " filesDir=null，无法初始化");
            }
        } catch (Throwable t) {
            DebugLog.get().log("Persist", phase + " attempt#" + attempt + " init error: " + t);
        }
    }

    /** v1.29: 延迟重试 LogPersister 初始化（currentApplication 早期可能为 null） */
    private static void scheduleLogPersisterRetry(long delayMs) {
        new Thread(() -> {
            try {
                Thread.sleep(delayMs);
                if (!LogPersister.get().isInitialized()) {
                    initLogPersister("retry", (int) delayMs);
                }
            } catch (Throwable t) {
                DebugLog.get().log("Persist", "retry@" + delayMs + " error: " + t);
            }
        }, "SpyProbe-PersistRetry").start();
    }
}
