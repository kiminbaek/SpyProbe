package com.dustinky.spyprobe;

import java.lang.reflect.Method;

import io.github.libxposed.api.XposedModule;

/**
 * SharedPreferences key 记录（v1.3 新增）：
 * hook android.app.SharedPreferencesImpl 的 getter 方法，记录 app 读取的偏好 key。
 *
 * 用途：反编译时知道 app 把什么状态存在本地（登录态/配置项/功能开关）。
 * 注意：prefs 读取高频（启动即大量读取），默认 prefsCapture=false 防刷屏，UI 按需开启。
 */
public class PrefsProbe {

    static final String TAG = "SpyProbe.Prefs";

    private final XposedModule module;

    public PrefsProbe(XposedModule module) {
        this.module = module;
    }

    public void install(String phase) {
        // v1.37 P0-1: 惰性安装——开关关闭时完全不装 hook（借鉴 Guise activeHookFeatures，
        //   用户关闭的探测项在目标进程零 hook 存在，减少崩溃面 + 更隐蔽 + 启动更快）
        if (!Config.get().prefsCapture) {
            DebugLog.get().logNoMirror("Prefs", "install(" + phase + ") skipped: Config.get().prefsCapture == false");
            return;
        }
        String[] getters = {"getString", "getBoolean", "getInt", "getLong", "getFloat", "getStringSet"};
        try {
            // SharedPreferencesImpl 是 Android 内部类（bootclasspath），默认 Class.forName 可找到
            Class<?> impl = Class.forName("android.app.SharedPreferencesImpl");
            int hooked = 0;
            for (String gn : getters) {
                try {
                    Method m = findGetter(impl, gn);
                    if (m == null) continue;
                    final String fName = gn;
                    module.hook(m).intercept(chain -> {
                        Object r = chain.proceed();
                        if (Config.get().prefsCapture) {
                            try {
                                Object key = chain.getArg(0);
                                logPrefsEvent(fName, String.valueOf(key), MethodProbe.str(r, 120));
                            } catch (Throwable t) { }
                        }
                        return r;
                    });
                    hooked++;
                } catch (Throwable t) { }
            }
            DebugLog.get().logNoMirror(TAG, "[" + phase + "] hooked SharedPreferencesImpl getters x" + hooked);
        } catch (Throwable t) {
            DebugLog.get().logNoMirror(TAG, "[" + phase + "] SharedPreferencesImpl hook fail: " + t);
        }
    }

    /** v1.58: SharedPreferences 读取 → 结构化 PREFS 事件（卡片 + 详情页）。
     *  反编译价值：知道 app 把什么状态存在本地（登录态/配置项/功能开关）。 */
    private static void logPrefsEvent(String getter, String key, String value) {
        try {
            long eid = EventStore.get().nextId();
            String msg = "[EVT#" + eid + "][" + getter + "] " + key + " -> " + value;
            LogStore.get().log(TAG, msg);
            org.json.JSONObject payload = new org.json.JSONObject();
            payload.put("getter", getter == null ? "" : getter);
            payload.put("key", key == null ? "" : key);
            payload.put("value", value == null ? "" : value);
            String title = getter + " " + (key == null ? "" : key);
            if (title.length() > 90) title = title.substring(0, 90) + "…";
            EventStore.get().add(new SpyEvent("PREFS", eid, System.currentTimeMillis(),
                    title, payload, msg, ""));
        } catch (Throwable t) { /* 结构化失败不影响文本日志 */ }
    }

    /** 找到 getter：SharedPreferencesImpl.getX(String key, T defValue) */
    private Method findGetter(Class<?> impl, String name) {
        for (Method m : impl.getDeclaredMethods()) {
            if (!m.getName().equals(name)) continue;
            Class<?>[] pt = m.getParameterTypes();
            if (pt.length == 2 && pt[0] == String.class) return m;
        }
        return null;
    }
}
