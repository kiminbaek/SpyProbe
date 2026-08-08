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
        ClassLoadProbe clsProbe = new ClassLoadProbe(this, cl);
        PrefsProbe prefs = new PrefsProbe(this);
        SQLiteProbe sqlite = new SQLiteProbe(this);
        // v1.5: 反编译增强探测
        UrlProbe urlProbe = new UrlProbe(this, cl);
        CryptoProbe crypto = new CryptoProbe(this);
        LogCatProbe logcat = new LogCatProbe(this);
        ActivityProbe act = new ActivityProbe(this);
        JsonProbe json = new JsonProbe(this, cl);
        SpyServer server = new SpyServer(net, mth, clsProbe, pkg);

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

        // v1.5: 加密算法记录（延迟确保 Cipher 类就绪）
        new Thread(() -> {
            try {
                Thread.sleep(2000);
                crypto.install("early");
            } catch (Throwable t) {
                log(Log.ERROR, TAG, "crypto probe install error: " + t);
            }
        }, "SpyProbe-Crypto").start();

        // v1.5: Activity/Intent 记录（延迟确保 ActivityThread 就绪）
        new Thread(() -> {
            try {
                Thread.sleep(2000);
                act.install("early");
            } catch (Throwable t) {
                log(Log.ERROR, TAG, "activity probe install error: " + t);
            }
        }, "SpyProbe-Act").start();

        // v1.5: JSON/Gson 序列化记录（延迟确保类就绪）
        new Thread(() -> {
            try {
                Thread.sleep(2000);
                json.install("early");
            } catch (Throwable t) {
                log(Log.ERROR, TAG, "json probe install error: " + t);
            }
        }, "SpyProbe-Json").start();

        // v1.4: 装 SQLite 增删改查记录
        new Thread(() -> {
            try {
                Thread.sleep(2500);
                sqlite.install("early");
            } catch (Throwable t) {
                log(Log.ERROR, TAG, "sqlite probe install error: " + t);
            }
        }, "SpyProbe-SQLite").start();

        // v1.3: 装 SharedPreferences key 记录（延迟确保实现类已加载）
        new Thread(() -> {
            try {
                Thread.sleep(2000);
                prefs.install("early");
            } catch (Throwable t) {
                log(Log.ERROR, TAG, "prefs probe install error: " + t);
            }
        }, "SpyProbe-Prefs").start();

        // v1.2: 装类加载探测（延迟确保类加载器稳定）
        new Thread(() -> {
            try {
                Thread.sleep(1500);
                clsProbe.install("early");
            } catch (Throwable t) {
                log(Log.ERROR, TAG, "class probe install error: " + t);
            }
        }, "SpyProbe-ClassProbe").start();

        // 起 server（延迟确保 app 网络栈就绪）
        new Thread(() -> {
            try {
                Thread.sleep(2000);
                server.start();
            } catch (Throwable t) {
                log(Log.ERROR, TAG, "server start error: " + t);
            }
        }, "SpyProbe-Boot").start();

        // 配置里已下发的 hook 也要重装（热更新场景）
        new Thread(() -> {
            try {
                Thread.sleep(5000);
                for (Config.HookSpec spec : Config.get().hooks) {
                    if (!spec.enabled) continue;
                    try {
                        mth.hookMethod(spec.className, spec.methodName, spec.paramTypes);
                    } catch (Throwable t) {
                        LogStore.get().log(TAG, "re-hook fail: " + spec.className + "." + spec.methodName + " : " + t);
                    }
                }
            } catch (Throwable t) {
                log(Log.ERROR, TAG, "re-hook error: " + t);
            }
        }, "SpyProbe-Rehook").start();

        log(Log.INFO, TAG, "SpyProbe ready for " + pkg);
    }
}
