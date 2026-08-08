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
                    final int fArgc = argc;
                    module.hook(m).intercept(chain -> {
                        Object r = chain.proceed();
                        if (Config.get().logcatCapture) {
                            try {
                                Object tag = chain.getArg(0);
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
