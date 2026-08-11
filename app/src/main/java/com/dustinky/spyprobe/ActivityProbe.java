package com.dustinky.spyprobe;

import android.app.Activity;
import android.content.ContextWrapper;
import android.content.Intent;
import android.os.Bundle;

import java.lang.reflect.Method;

import io.github.libxposed.api.XposedModule;

/**
 * Activity 生命周期 + Intent 跳转记录（v1.5 新增）：
 *   - Activity.onCreate/onResume —— 页面流（付费弹窗从哪来、主界面结构）
 *   - ContextWrapper.startActivity(Intent) —— 跳转目标
 * 默认关（activityCapture=false）防刷屏，UI 按需开启。
 */
public class ActivityProbe {

    static final String TAG = "SpyProbe.Act";

    private final XposedModule module;

    public ActivityProbe(XposedModule module) {
        this.module = module;
    }

    public void install(String phase) {
        // v1.37 P0-1: 惰性安装——开关关闭时完全不装 hook（借鉴 Guise activeHookFeatures，
        //   用户关闭的探测项在目标进程零 hook 存在，减少崩溃面 + 更隐蔽 + 启动更快）
        if (!Config.get().activityCapture) {
            DebugLog.get().logNoMirror("Activity", "install(" + phase + ") skipped: Config.get().activityCapture == false");
            return;
        }
        int hooked = 0;
        // Activity.onCreate(Bundle)
        try {
            Method m = Activity.class.getMethod("onCreate", Bundle.class);
            module.hook(m).intercept(chain -> {
                Object r = chain.proceed();
                if (Config.get().activityCapture) {
                    try {
                        Object thiz = chain.getThisObject();
                        LogStore.get().log(TAG, "[onCreate] " + (thiz == null ? "?" : thiz.getClass().getName()));
                    } catch (Throwable t) { }
                }
                return r;
            });
            hooked++;
        } catch (Throwable t) { }
        // Activity.onResume()
        try {
            Method m = Activity.class.getMethod("onResume");
            module.hook(m).intercept(chain -> {
                Object r = chain.proceed();
                if (Config.get().activityCapture) {
                    try {
                        Object thiz = chain.getThisObject();
                        LogStore.get().log(TAG, "[onResume] " + (thiz == null ? "?" : thiz.getClass().getName()));
                    } catch (Throwable t) { }
                }
                return r;
            });
            hooked++;
        } catch (Throwable t) { }
        // startActivity(Intent)
        try {
            Method m = ContextWrapper.class.getMethod("startActivity", Intent.class);
            module.hook(m).intercept(chain -> {
                Object r = chain.proceed();
                if (Config.get().activityCapture) {
                    try {
                        Object it = chain.getArg(0);
                        if (it instanceof Intent) {
                            Intent i = (Intent) it;
                            String action = i.getAction();
                            String pkg = i.getPackage();
                            String data = i.getDataString();
                            StringBuilder sb = new StringBuilder("[startActivity]");
                            if (action != null) sb.append(" action=").append(action);
                            if (pkg != null) sb.append(" pkg=").append(pkg);
                            if (data != null) sb.append(" data=").append(data);
                            Object thiz = chain.getThisObject();
                            sb.append(" from=").append(thiz == null ? "?" : thiz.getClass().getSimpleName());
                            LogStore.get().log(TAG, sb.toString());
                        }
                    } catch (Throwable t) { }
                }
                return r;
            });
            hooked++;
        } catch (Throwable t) { }
        LogStore.get().log(TAG, "[" + phase + "] hooked Activity/Intent x" + hooked);
    }
}
