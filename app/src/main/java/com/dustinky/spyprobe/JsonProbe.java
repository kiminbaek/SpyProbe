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
        // v1.37 P0-1: 惰性安装——开关关闭时完全不装 hook（借鉴 Guise activeHookFeatures，
        //   用户关闭的探测项在目标进程零 hook 存在，减少崩溃面 + 更隐蔽 + 启动更快）
        if (!Config.get().jsonCapture) {
            DebugLog.get().logNoMirror("Json", "install(" + phase + ") skipped: Config.get().jsonCapture == false");
            return;
        }
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
                        // v1.53: 过滤自家控制面（SpyServer 9901 /api/ping、/api/config 响应在目标进程内
                        //   经 JSONObject.toString 被本 hook 捕获 → 65 行纯噪音刷屏）
                        if (isSelfControlPlane(s)) return r;
                        boolean truncated = s.length() > 300;
                        if (truncated) s = s.substring(0, 300) + "...(" + s.length() + ")";
                        // v1.55: 结构化 JSON 事件（卡片化）
                        logJsonEvent("JSONObject", s, truncated);
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
                            if (isSelfControlPlane(s)) return r;
                            boolean truncated = s.length() > 300;
                            if (truncated) s = s.substring(0, 300) + "...(" + s.length() + ")";
                            // v1.55: 结构化 JSON 事件（卡片化）
                            logJsonEvent("Gson(" + (arg == null ? "?" : arg.getClass().getName()) + ")", s, truncated);
                        } catch (Throwable t) { }
                    }
                    return r;
                });
                hooked++;
            }
        } catch (Throwable t) {
            DebugLog.get().logNoMirror(TAG, "[" + phase + "] Gson hook fail (app 可能不用 Gson): " + t);
        }
        DebugLog.get().logNoMirror(TAG, "[" + phase + "] hooked JSONObject/Gson x" + hooked);
    }

    /** v1.55: 结构化 JSON 事件——日志行嵌入 [EVT#id]，EventStore 写 SpyEvent（UI 卡片化） */
    private static void logJsonEvent(String source, String content, boolean truncated) {
        try {
            long eid = EventStore.get().nextId();
            String msg = "[EVT#" + eid + "][JSON] " + source + " -> " + content;
            LogStore.get().log(TAG, msg);
            org.json.JSONObject payload = new org.json.JSONObject();
            payload.put("source", source == null ? "" : source);
            payload.put("content", content == null ? "" : content);
            payload.put("truncated", truncated);
            String title = source == null ? "JSON" : source;
            EventStore.get().add(new SpyEvent("JSON", eid, System.currentTimeMillis(),
                    title, payload, msg, ""));
        } catch (Throwable t) { /* 结构化失败不影响文本日志 */ }
    }

    /** v1.53: 自家控制面 JSON 特征识别（SpyServer 9901 响应在目标进程内被本 probe 捕获 → 纯噪音）
     *  v1.54: P0 修复——原实现 `s.length() > 2048 return false` 导致自家 HttpStore.pushBatch 的
     *   大 payload（9KB~38KB，含 "entries"+"source":"TLS" 特征）被放行 → 日志页混入 6 行自家数据。
     *   现在改为：先查特征（长度不限），只剩"完全不像自家"的才靠长度兜底。 */
    private static boolean isSelfControlPlane(String s) {
        if (s == null || s.length() < 8) return false;
        // /api/ping 响应: {"ok":true,"pkg":"app.p2ee1f.p","port":9901,...}
        if (s.contains("\"ok\":true") && s.contains("\"pkg\"") && s.contains("\"port\"")) return true;
        // /api/config 响应: {"sslBypass":true,"okHttp":true,...,"debug":true}
        if (s.contains("\"sslBypass\"")) return true;
        // /api/status 响应: {"uptime":...,"logCount":...,"versionCode":...}
        if (s.contains("\"logCount\"") && s.contains("\"versionCode\"")) return true;
        // v1.53.1: 自家 HttpStore.pushBatch 的推送 payload（目标进程内 JSONObject.toString 被本 hook
        //   捕获 → 日志页出现 {"entries":[{"source":"TLS","id":102,... 自家数据混入）
        // v1.54: 该项不再受长度限制——pushBatch 单批可达 38KB，必须对任意长度生效
        if (s.contains("\"entries\"") && s.contains("\"source\":\"TLS\"")) return true;
        // v1.54: Glide 内存压力事件 {"type":"memoryPressure",...} 对逆向零价值（v1.53 日志 4 行）
        if (s.contains("\"type\":\"memoryPressure\"")) return true;
        return false;
    }
}
