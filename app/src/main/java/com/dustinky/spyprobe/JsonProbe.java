package com.dustinky.spyprobe;

import java.lang.reflect.Method;

import io.github.libxposed.api.XposedModule;

/**
 * JSON 序列化记录（v1.5 新增）：
 *   - org.json.JSONObject.toString() —— app 组装的 JSON 结构
 *   - com.google.gson.Gson.toJson(Object) —— Gson 序列化
 * 用途：反编译时直接看接口请求/响应的数据结构（字段名/层级）。
 * 默认关（jsonCapture=false）防刷屏，UI 按需开启。
 */
public class JsonProbe {

    static final String TAG = "SpyProbe.JSON";

    private final XposedModule module;
    private final ClassLoader appCl;

    public JsonProbe(XposedModule module, ClassLoader appCl) {
        this.module = module;
        this.appCl = appCl;
    }

    public void install(String phase) {
        int hooked = 0;
        // org.json.JSONObject.toString() —— 注意 toString() 被 JSONObject 覆盖，hook 实例方法
        try {
            Class<?> jo = Class.forName("org.json.JSONObject");
            Method m = jo.getMethod("toString");
            module.hook(m).intercept(chain -> {
                Object r = chain.proceed();
                if (Config.get().jsonCapture) {
                    try {
                        String s = r == null ? "null" : r.toString();
                        if (s.length() > 300) s = s.substring(0, 300) + "...(" + s.length() + ")";
                        LogStore.get().log(TAG, "[JSON] " + s);
                    } catch (Throwable t) { }
                }
                return r;
            });
            hooked++;
        } catch (Throwable t) { }

        // com.google.gson.Gson.toJson(Object)
        try {
            Class<?> gson = Class.forName("com.google.gson.Gson", false, appCl);
            for (Method m : gson.getDeclaredMethods()) {
                if (!m.getName().equals("toJson")) continue;
                Class<?>[] pt = m.getParameterTypes();
                // v1.16 P2-8: 补 toJson(Object, Type) 2 参重载（此前只 hook 1 参，带 Type 的序列化漏记）
                boolean target = (pt.length == 1 && !pt[0].isPrimitive())
                        || (pt.length == 2 && pt[0] == Object.class && pt[1] == java.lang.reflect.Type.class);
                if (!target) continue;
                final Method fM = m;
                module.hook(m).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().jsonCapture) {
                        try {
                            Object arg = chain.getArg(0);
                            String s = r == null ? "null" : r.toString();
                            if (s.length() > 300) s = s.substring(0, 300) + "...(" + s.length() + ")";
                            LogStore.get().log(TAG, "[Gson] " + (arg == null ? "?" : arg.getClass().getName()) + " -> " + s);
                        } catch (Throwable t) { }
                    }
                    return r;
                });
                hooked++;
            }
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] Gson hook fail (app 可能不用 Gson): " + t);
        }
        LogStore.get().log(TAG, "[" + phase + "] hooked JSONObject/Gson x" + hooked);
    }
}
