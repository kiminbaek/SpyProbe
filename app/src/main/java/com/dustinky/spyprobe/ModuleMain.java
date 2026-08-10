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
        DebugLog.get().log("ModuleMain", "onPackageReady pkg=" + param.getPackageName()
                + " cl=" + (param.getClassLoader() != null ? "ok" : "null"));
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
        // v1.40 P0: 注入 DexKit 到 NetProbe（混淆 OkHttpClient 定位兜底）
        net.setDexKit(dexKit);
        // v1.13: 反检测 hook 集（隐藏 root/Xposed，防目标 App 检测）
        AntiDetectProbe anti = new AntiDetectProbe(this, cl);
        // v1.38 P0-4: 双向认证证书 dump（hooker keystore_dump.js 借鉴，Config.keystoreCapture 开关）
        KeystoreProbe keystore = new KeystoreProbe(this);
        // v1.22: 抓包开关持久化文件——目标 App 自身 data 目录（零 IPC，重启必恢复）
        // v1.25 P2-9: hook/hijack 规则持久化同目录文件（spyprobe_rules.json），弃用远程偏好
        // v1.31.6 P0-1: 早期 currentApplication() 可能为 null → cfgFile 可能解析为 null；
        //   Config.loadConfig/saveConfig 已支持 file==null 时动态重解析，这里仅作日志与 rulesFile 参考
        final java.io.File cfgFile = Config.get().resolveCfgFile();
        DebugLog.get().log("ModuleMain", "cfgFile=" + (cfgFile != null ? cfgFile.getAbsolutePath() : "null"));
        // v1.29: 日志持久化初始化（DebugLog 三保险：内存环形 + 落盘 + logcat）
        // v1.29 修复：原实现 currentApplication() 返回 null 时静默跳过 → dir=null 一行不写盘且无痕迹。
        // 现在：立即尝试 + 延迟重试（1s/3s/10s），任何失败写 DebugLog。
        // v1.32【架构修正】：目标进程不再落盘目标 App data（用户拍板：日志/配置不能放别人家）——
        // DebugLog 只走内存环形 + logcat；正式日志 LogStore 推回主进程 :9900（SpyProbe 自己家落盘）。
        // 历史日志在主进程家 = 免 root、免目标 App 在线。DebugLog.init/LogPersister.init 只在主进程调用。
        // v1.32: 日志推回主进程（SpyProbe 自己家）——目标进程不再落盘目标 App data（历史日志在主进程家，免 root）
        // v1.37 P0-5: 从模块远程偏好取 token 随推送鉴权（防其他 App 伪造日志灌入主进程）
        String pushToken = TokenStore.remoteToken(this);
        DebugLog.get().log("ModuleMain", "push token=" + (pushToken.isEmpty() ? "(none, 老主进程兼容)" : "len " + pushToken.length()));
        // v1.44.1 P0: 传 token provider——推送失败(401)时 LogStore/PcapWriter 自动重拉 token 再重试，
        //   根治 libxposed 跨进程读静默空导致"卸载重装后 401 永远抓不了日志"的问题
        LogStore.get().enablePushHome(pushToken, () -> TokenStore.remoteToken(this));
        // v1.39 P0: pcap 记录推送主进程（与日志推送同 token 鉴权）
        PcapWriter.get().enablePushHome(pushToken, () -> TokenStore.remoteToken(this));
        SpyServer server = new SpyServer(net, mth, clsProbe, pkg, dexKit, cfgFile);

        // v1.37 P0-1: 尽早拉主进程权威配置（惰性 hook 的前提——net.install 之前就知道
        //   用户关了什么探测项，early 阶段就能按配置跳过）。主进程不在线则保持默认值全装，
        //   延迟线程 t=2000ms 再 fallback 目标 data（与 v1.32 原逻辑兼容）。
        final boolean[] earlyCfgLoaded = {false};
        try {
            String earlyCfg = fetchHomeConfig();
            if (earlyCfg != null && !earlyCfg.isEmpty()) {
                Config.get().applyJson(earlyCfg);
                earlyCfgLoaded[0] = true;
                DebugLog.get().log("ModuleMain", "config loaded from HOME (early, for lazy hook)");
            }
        } catch (Throwable t) {
            DebugLog.get().log("ModuleMain", "early config fetch FAIL: " + t);
        }

        // 立即装网络 hook
        // v1.37 P0-2: 统一 HookSafe 包裹——单个 hook 安装失败不拖垮目标进程，失败留痕
        HookSafe.install("ModuleMain", "net.install(early)", () -> net.install("early"));

        // v1.5: URL 构造捕捉（尽早装，URL 在启动期就大量构造）
        HookSafe.install("ModuleMain", "urlProbe.install(early)", () -> urlProbe.install("early"));

        // v1.5: App 日志拦截（尽早装）
        HookSafe.install("ModuleMain", "logcat.install(early)", () -> logcat.install("early"));

        // v1.6: 单个调度线程按时间点依次安装延迟探测 + 持久化规则重挂
        // v1.8: 延迟安装的探测 phase 统一标 "late"（此前误标 "early" 误导日志）
        new Thread(() -> {
            // t=1500ms: 类加载探测（延迟确保类加载器稳定）
            try {
                Thread.sleep(1500);
                HookSafe.install("ModuleMain", "clsProbe.install(late)", () -> clsProbe.install("late"));
            } catch (Throwable t) {
                log(Log.ERROR, TAG, "class probe install error: " + t);
                DebugLog.get().log("ModuleMain", "clsProbe.install FAIL: " + t);
            }

            // t=2000ms: 加密/Activity/JSON/SharedPreferences + 环境检测 + server
            try {
                Thread.sleep(500);
                // v1.22: 恢复用户抓包开关——必须在所有延迟探测安装 + server.start() 之前，
                // 否则 UI 连上 server 先拿到默认配置、probe 也按默认开关记录
                // v1.32: 配置权威源 = 主进程（SpyProbe 自己家）：先 GET :9900/api/config（UI 在跑时用户最新设置），
                // 失败再回退目标 App data cfgFile（v1.31.6 兜底），保证"关 native"在下次启动仍生效。
                // v1.37 P0-1: early 阶段已拉过主进程配置则跳过（惰性 hook 已按配置生效）；
                //   否则按 v1.32 原逻辑：先拉主进程，失败 fallback 目标 data
                boolean homeLoaded = earlyCfgLoaded[0];
                if (!homeLoaded) {
                    try {
                        String homeCfg = fetchHomeConfig();
                        if (homeCfg != null && !homeCfg.isEmpty()) {
                            Config.get().applyJson(homeCfg);
                            homeLoaded = true;
                            DebugLog.get().log("ModuleMain", "config loaded from HOME (:9900)");
                        }
                    } catch (Throwable t) {
                        DebugLog.get().log("ModuleMain", "fetch home config FAIL: " + t);
                    }
                }
                if (!homeLoaded) {
                    Config.get().loadConfig(cfgFile);
                    DebugLog.get().log("ModuleMain", "config loaded from target data (fallback)");
                }
                DebugLog.get().log("ModuleMain", "loadConfig done ssl=" + Config.get().sslBypass
                        + " native=" + Config.get().nativeCapture + " debug=" + Config.get().debugEnabled);
                // v1.10: native 层抓包（libc + SSL_write/SSL_read + HTTP/2），越早装越好
                // v1.37 P0-2: HookSafe 统一包裹（NativeProbe.init 内部也有自己的 try-catch）
                HookSafe.install("ModuleMain", "NativeProbe.init()", () -> NativeProbe.init());
                // v1.23: 每个延迟探测单独 try-catch——任何一个装失败不能拖垮 server 启动
                // v1.37 P0-2: 全部走 HookSafe（统一失败留痕到 LogStore + DebugLog）
                HookSafe.install("ModuleMain", "crypto.install(late)", () -> crypto.install("late"));
                // v1.38 P0-4: mTLS 证书 dump（开关 keystoreCapture；内部自己判断开关，关闭时零成本）
                HookSafe.install("ModuleMain", "keystore.install(late)", () -> keystore.install("late"));
                HookSafe.install("ModuleMain", "act.install(late)", () -> act.install("late"));
                HookSafe.install("ModuleMain", "json.install(late)", () -> json.install("late"));
                HookSafe.install("ModuleMain", "prefs.install(late)", () -> prefs.install("late"));
                HookSafe.install("ModuleMain", "env.install(late)", () -> env.install("late"));
                // v1.13: 反检测 hook 集（延迟装；hook File/Runtime 等高频类，避开启动风暴）
                HookSafe.install("ModuleMain", "anti.install()", () -> anti.install());
            } catch (Throwable t) {
                log(Log.ERROR, TAG, "deferred probe install error: " + t);
                DebugLog.get().log("ModuleMain", "deferred install FAIL: " + t);
            }
            // v1.23: server 启动独立 try-catch——无论探测装没装上，server 必须起来（UI 才能连）
            try {
                DebugLog.get().log("ModuleMain", "installing server.start()");
                server.start();
            } catch (Throwable t) {
                log(Log.ERROR, TAG, "server start error: " + t);
                DebugLog.get().log("ModuleMain", "server.start FAIL: " + t);
            }

            // t=2500ms: SQLite 记录
            try {
                Thread.sleep(500);
                HookSafe.install("ModuleMain", "sqlite.install(late)", () -> sqlite.install("late"));
            } catch (Throwable t) {
                log(Log.ERROR, TAG, "sqlite probe install error: " + t);
                DebugLog.get().log("ModuleMain", "sqlite FAIL: " + t);
            }

            // t=5000ms: DexKit 初始化（导出 dex / 字符串反查，等类加载稳定）+ 持久化 hook/hijack 规则重挂
            try {
                Thread.sleep(2500);
                HookSafe.install("ModuleMain", "dexKit.init()", () -> dexKit.init());
                // v1.25 P2-9: 规则从文件加载（与 cfgFile 同目录，零 IPC）
                java.io.File rulesFile = (cfgFile != null && cfgFile.getParentFile() != null)
                        ? new java.io.File(cfgFile.getParentFile(), "spyprobe_rules.json") : null;
                boolean loaded = Config.get().loadRules(rulesFile);
                if (loaded) {
                    log(Log.INFO, TAG, "loaded persisted hook rules, re-hooking...");
                    DebugLog.get().log("ModuleMain", "rules loaded, re-hooking " + Config.get().hooks.size());
                } else {
                    DebugLog.get().log("ModuleMain", "no rules loaded (first run?)");
                }
                for (Config.HookSpec spec : Config.get().hooks) {
                    if (!spec.enabled) continue;
                    try {
                        mth.hookMethod(spec.className, spec.methodName, spec.paramTypes);
                    } catch (Throwable t) {
                        LogStore.get().log(TAG, "re-hook fail: " + spec.className + "." + spec.methodName + " : " + t);
                        DebugLog.get().log("ModuleMain", "re-hook FAIL " + spec.className + "." + spec.methodName + ": " + t);
                    }
                }
                if (loaded) LogStore.get().log(TAG, "re-hook done, rules=" + Config.get().hooks.size()
                        + " hijacks=" + Config.get().hijacks.size());
                DebugLog.get().log("ModuleMain", "re-hook done rules=" + Config.get().hooks.size()
                        + " hijacks=" + Config.get().hijacks.size());
            } catch (Throwable t) {
                log(Log.ERROR, TAG, "re-hook error: " + t);
                DebugLog.get().log("ModuleMain", "re-hook error: " + t);
            }
        }, "SpyProbe-Scheduler").start();

        log(Log.INFO, TAG, "SpyProbe ready for " + pkg);
        DebugLog.get().log("ModuleMain", "onPackageReady 流程编排完成 pkg=" + pkg);
    }

    /** v1.32: 从主进程（SpyProbe 自己家）拉权威配置；主进程不在线返回 null */
    private static String fetchHomeConfig() {
        try {
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection)
                    new java.net.URL("http://127.0.0.1:9900/api/config").openConnection();
            conn.setConnectTimeout(600);
            conn.setReadTimeout(800);
            conn.setRequestMethod("GET");
            int code = conn.getResponseCode();
            if (code != 200) {
                conn.disconnect();
                return null;
            }
            java.io.InputStream is = conn.getInputStream();
            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = is.read(buf)) > 0) bos.write(buf, 0, n);
            is.close();
            conn.disconnect();
            String json = bos.toString("UTF-8");
            // 校验是配置 JSON（含 native 字段）才返回，避免误拿非配置响应
            if (json.contains("\"native\"")) return json;
            return null;
        } catch (Throwable t) {
            return null;
        }
    }

}
