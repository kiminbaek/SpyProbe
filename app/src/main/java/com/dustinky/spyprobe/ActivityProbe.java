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
                        logActivityEvent("onCreate", thiz == null ? "?" : thiz.getClass().getName(), null, null, null, null);
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
                        logActivityEvent("onResume", thiz == null ? "?" : thiz.getClass().getName(), null, null, null, null);
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
                            Object thiz = chain.getThisObject();
                            logActivityEvent("startActivity", thiz == null ? "?" : thiz.getClass().getSimpleName(),
                                    action, pkg, data, null);
                        }
                    } catch (Throwable t) { }
                }
                return r;
            });
            hooked++;
        } catch (Throwable t) { }
        DebugLog.get().logNoMirror(TAG, "[" + phase + "] hooked Activity/Intent x" + hooked);
    }

    /** v1.58: Activity 生命周期 / Intent 跳转 → 结构化 ACT 事件（页面流卡片 + 详情页）。
     *  payload: event/class/action/pkg/data/from —— 页面流对逆向帮助大（付费弹窗从哪来、跳转目标）。 */
    private static void logActivityEvent(String event, String cls, String action, String pkg, String data, String from) {
        try {
            long eid = EventStore.get().nextId();
            StringBuilder sb = new StringBuilder("[EVT#" + eid + "]");
            sb.append("[").append(event).append("] ");
            if (cls != null && !cls.isEmpty()) sb.append(cls);
            if (action != null) sb.append(" action=").append(action);
            if (pkg != null) sb.append(" pkg=").append(pkg);
            if (data != null) sb.append(" data=").append(data);
            if (from != null) sb.append(" from=").append(from);
            String msg = sb.toString();
            LogStore.get().log(TAG, msg);
            org.json.JSONObject payload = new org.json.JSONObject();
            payload.put("event", event == null ? "" : event);
            payload.put("class", cls == null ? "" : cls);
            payload.put("action", action == null ? "" : action);
            payload.put("pkg", pkg == null ? "" : pkg);
            payload.put("data", data == null ? "" : data);
            payload.put("from", from == null ? "" : from);
            String title = event + " " + (cls == null ? "" : cls);
            if (title.length() > 90) title = title.substring(0, 90) + "…";
            EventStore.get().add(new SpyEvent("ACT", eid, System.currentTimeMillis(),
                    title, payload, msg, ""));
        } catch (Throwable t) { /* 结构化失败不影响文本日志 */ }
    }
}
