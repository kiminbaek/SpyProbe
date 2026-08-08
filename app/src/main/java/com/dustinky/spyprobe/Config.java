package com.dustinky.spyprobe;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

import io.github.libxposed.api.XposedInterface;

/**
 * 运行期配置（hook 进程内内存态）
 * UI 通过 SpyServer 下发，NetProbe/MethodProbe 实时读取。
 */
public class Config {

    // ===== 网络抓包开关 =====
    public volatile boolean sslBypass = true;      // SSL 证书锁定绕过
    public volatile boolean okhttpCapture = true;  // OkHttp 请求/响应记录
    public volatile boolean urlCapture = true;     // HttpURLConnection 记录
    public volatile boolean dnsCapture = true;     // DNS 解析记录（域名→IP）
    public volatile boolean tcpCapture = true;     // Socket 连接记录（真实 IP:port）
    public volatile boolean classCapture = true;   // 类加载探测
    public volatile boolean webViewCapture = true; // WebView.loadUrl 记录（v1.3）
    public volatile boolean prefsCapture = false;  // SharedPreferences key 记录（v1.3，默认关防刷屏）
    public volatile boolean sqliteCapture = true;  // SQLite 增删改查记录（v1.4）
    public volatile boolean urlBuildCapture = true; // URL/Uri/URI/HttpUrl 构造记录（v1.5）
    public volatile boolean logcatCapture = true;  // App 自身 Log.d/i/e/w/v 拦截（v1.5，默认开）
    public volatile boolean cryptoCapture = false; // Cipher 算法/密钥/IV 记录（v1.5，默认关防刷屏）
    public volatile boolean activityCapture = false; // Activity 生命周期 + Intent 跳转（v1.5，默认关）
    public volatile boolean jsonCapture = false;   // JSONObject/Gson 序列化记录（v1.5，默认关）
    public volatile boolean detailMode = true;     // v1.6: 函数探测详细模式（参数/字段/调用栈）；关=轻量只记参数摘要
    // v1.9: 环境检测探测 + TLS 明文抓包 + 万能连接点 + Cronet
    public volatile boolean envCapture = true;     // 环境检测探测（root/vpn/传感器/防截屏/设备指纹检测记录）
    public volatile boolean tlsCapture = true;     // ConscryptEngine TLS 明文抓包（HTTPS 明文头）
    public volatile boolean connectCapture = true; // BlockGuardOs.connect 万能连接记录（QUIC/自建 TCP）
    public volatile boolean cronetCapture = false; // Cronet 网络栈记录（默认关：与 HttpURLConnection 记录重复度高）
    public volatile String classFilter = "";       // 类加载关键字过滤（空=全部入库不刷屏）
    public volatile boolean classLogAll = false;   // 匹配类是否刷屏输出到日志
    public volatile int bodyLimit = 2048;          // 记录响应体最大字节
    // v1.12: 日志环形缓冲容量（LogStore 动态读取，防日志无限增长；借鉴 Guise 日志归档容量思想）
    public volatile int logLimit = 4096;
    // v1.13: 反检测开关（隐藏 root/Xposed 痕迹，防目标 App 检测；fckvip hook_hide_root 借鉴）
    public volatile boolean antiRoot = false;      // 隐藏 root：File.exists(su)/Runtime.exec/SystemProperties 过滤
    public volatile boolean antiXposed = false;   // 隐藏 Xposed：loadClass/StackTrace/DexPathList/Modifier.isNative
    // v1.15 P0-4: native 层抓包开关（libc+SSL+HTTP2；默认开，高频刷屏时可关）
    public volatile boolean nativeCapture = true;
    // v1.19: 全自动探测（类加载时自动 hook 该类全部方法，免手动扫描）
    public volatile boolean autoProbe = false;
    public volatile String autoProbeFilter = ""; // 关键字过滤（空 = 所有非系统类）

    // ===== 方法探测 hook 列表（动态下发）=====
    public static class HookSpec {
        public final String className;
        public final String methodName;
        public final String paramTypes;   // 如 "java.lang.String,int" 或 ""（全部重载）
        public volatile boolean enabled = true;

        public HookSpec(String className, String methodName, String paramTypes) {
            this.className = className;
            this.methodName = methodName;
            this.paramTypes = paramTypes;
        }
    }

    /** hook 句柄（libxposed HookHandle），支持 unhook */
    public static class HookHandle {
        public final HookSpec spec;
        public final XposedInterface.HookHandle handle;
        public HookHandle(HookSpec spec, XposedInterface.HookHandle handle) {
            this.spec = spec;
            this.handle = handle;
        }
    }

    // v1.13: 通用 hook 规则模式（fckvip 借鉴——hook 会员解锁 4 模式）
    public static final int MODE_RETURN = 0; // 返回值：命中后不执行原方法，强制返回指定值（isVip()→true）
    public static final int MODE_PARAM  = 1; // 参数值：命中后改写方法入参（vipCheck(level)→3）
    public static final int MODE_BLOCK  = 2; // 拦截执行：命中后方法不执行，返回 null/0（绕过支付校验）
    public static final int MODE_STATIC = 3; // 静态变量：命中后写静态字段（UserInfo.IS_VIP=true）
    public static final int MODE_RECORD_PARAMS = 4; // 记录参数（v1.14，借鉴 SimpleHook RECORD_PARAMS）：纯观测不改行为
    public static final int MODE_RECORD_RETURN = 5; // 记录返回值（v1.14，借鉴 SimpleHook RECORD_RETURN）：纯观测不改行为
    public static final int MODE_RECORD_BOTH   = 6; // 记录参数+返回值（v1.14，借鉴 SimpleHook RECORD_PARAMS_RETURN）

    /** v1.13: 通用 hook 规则（原 HijackRule 升级为 4 模式；v1.4 的返回值劫持 = mode RETURN） */
    public static class HijackRule {
        public final String className;
        public final String methodName;
        public final String paramTypes;
        public final int mode;             // MODE_RETURN / MODE_PARAM / MODE_BLOCK / MODE_STATIC
        public final String returnValue;   // MODE_RETURN：字符串形式，按方法返回类型解析：true/false/数字/文本/null
        public final String paramValue;    // MODE_PARAM：格式 "0:值,1:值"（索引:值）
        public final String fieldName;     // MODE_STATIC：静态字段名
        public final String fieldType;     // MODE_STATIC：字段类型（int/long/boolean/float/double/String/...）
        public final String fieldValue;    // MODE_STATIC：字段值

        public HijackRule(String className, String methodName, String paramTypes, String returnValue) {
            this(className, methodName, paramTypes, MODE_RETURN, returnValue, "", "", "", "");
        }

        public HijackRule(String className, String methodName, String paramTypes, int mode,
                          String returnValue, String paramValue, String fieldName, String fieldType, String fieldValue) {
            this.className = className;
            this.methodName = methodName;
            this.paramTypes = paramTypes;
            this.mode = mode;
            this.returnValue = returnValue;
            this.paramValue = paramValue;
            this.fieldName = fieldName;
            this.fieldType = fieldType;
            this.fieldValue = fieldValue;
        }
    }

    public final List<HijackRule> hijacks = new CopyOnWriteArrayList<>();

    // v1.15 P1-2: className 索引（findHijack 高频调用，先查索引再匹配，避免每次 invoke 全表线性扫描）
    private final java.util.Map<String, List<HijackRule>> hijackIndex = new ConcurrentHashMap<>();

    public synchronized void addHijack(String className, String methodName, String paramTypes, String returnValue) {
        addRule(className, methodName, paramTypes, MODE_RETURN, returnValue, "", "", "", "");
    }

    /** v1.13: 通用规则新增/更新（同 class#method(params)+mode 去重）；v1.15 P1-2: 同步维护 className 索引 */
    public synchronized void addRule(String className, String methodName, String paramTypes, int mode,
                                     String returnValue, String paramValue, String fieldName, String fieldType, String fieldValue) {
        String pts = paramTypes == null ? "" : paramTypes;
        for (HijackRule h : hijacks) {
            if (h.className.equals(className) && h.methodName.equals(methodName)
                    && h.paramTypes.equals(pts) && h.mode == mode) {
                hijacks.remove(h);
                List<HijackRule> idx = hijackIndex.get(className);
                if (idx != null) idx.remove(h);
                break;
            }
        }
        HijackRule rule = new HijackRule(className, methodName, pts, mode,
                returnValue == null ? "" : returnValue,
                paramValue == null ? "" : paramValue,
                fieldName == null ? "" : fieldName,
                fieldType == null ? "" : fieldType,
                fieldValue == null ? "" : fieldValue);
        hijacks.add(rule);
        hijackIndex.computeIfAbsent(className, k -> new CopyOnWriteArrayList<>()).add(rule);
    }

    public synchronized boolean removeHijack(String className, String methodName, String paramTypes) {
        boolean removed = hijacks.removeIf(h -> h.className.equals(className)
                && h.methodName.equals(methodName)
                && (paramTypes == null || paramTypes.isEmpty() || h.paramTypes.equals(paramTypes)));
        // v1.15 P1-2: 同步清索引
        if (removed) {
            List<HijackRule> idx = hijackIndex.get(className);
            if (idx != null) {
                idx.removeIf(h -> h.methodName.equals(methodName)
                        && (paramTypes == null || paramTypes.isEmpty() || h.paramTypes.equals(paramTypes)));
                if (idx.isEmpty()) hijackIndex.remove(className);
            }
        }
        return removed;
    }

    /** 查找命中劫持规则（精确匹配 class#method(params)，paramTypes 为空=匹配任一重载）；v1.15 P1-2: 走 className 索引 */
    public synchronized HijackRule findHijack(String className, String methodName, String paramTypes) {
        List<HijackRule> idx = hijackIndex.get(className);
        if (idx == null) return null;
        for (HijackRule h : idx) {
            // v1.14: 方法名/参数支持通配符 "*"（借鉴 SimpleHook MainHook）：* = 匹配任意方法名/任意参数
            if (!h.methodName.equals("*") && !h.methodName.equals(methodName)) continue;
            if (paramTypes == null || paramTypes.isEmpty()) return h;
            if (h.paramTypes.isEmpty() || h.paramTypes.equals("*") || h.paramTypes.equals(paramTypes)) return h;
        }
        return null;
    }

    public final List<HookSpec> hooks = new CopyOnWriteArrayList<>();
    // 内存句柄缓存：key = class#method(params)，用于 unhook
    private final Map<String, List<XposedInterface.HookHandle>> handles = new ConcurrentHashMap<>();

    private static final Config INSTANCE = new Config();
    public static Config get() { return INSTANCE; }

    public void clearHooks() {
        hooks.clear();
        // v1.16 P0-1: 清 Config 记录同时真正 unhook（此前只清 map，hook 永久生效）
        for (List<XposedInterface.HookHandle> list : handles.values()) {
            for (XposedInterface.HookHandle h : list) {
                try { h.unhook(); } catch (Throwable t) { }
            }
        }
        handles.clear();
    }

    public synchronized void addHook(HookSpec spec) {
        // 去重：同 class+method+params 不重复加
        for (HookSpec h : hooks) {
            if (h.className.equals(spec.className) && h.methodName.equals(spec.methodName)
                    && h.paramTypes.equals(spec.paramTypes)) {
                h.enabled = true;
                return;
            }
        }
        hooks.add(spec);
    }

    public synchronized boolean removeHook(String className, String methodName, String paramTypes) {
        boolean removed = hooks.removeIf(h -> h.className.equals(className)
                && h.methodName.equals(methodName)
                && (paramTypes == null || paramTypes.isEmpty() || h.paramTypes.equals(paramTypes)));
        // v1.16 P0-1: 复用 unhookHandles 真正卸载句柄（此前只清 map 不 unhook，hook 永久生效）
        unhookHandles(className, methodName, paramTypes);
        return removed;
    }

    public synchronized void addHandle(String className, String methodName, String paramTypes, XposedInterface.HookHandle h) {
        handles.computeIfAbsent(keyOf(className, methodName, paramTypes), k -> new CopyOnWriteArrayList<>()).add(h);
    }

    /** v1.3: 该 class#method(params) 是否已 hook（防重复 hook 日志翻倍） */
    public synchronized boolean hasHandle(String className, String methodName, String paramTypes) {
        return handles.containsKey(keyOf(className, methodName, paramTypes));
    }

    /** 卸载句柄：paramTypes 非空精确匹配具体签名；空=通配卸载该 class#method 全部重载句柄 */
    public synchronized int unhookHandles(String className, String methodName, String paramTypes) {
        if (paramTypes == null || paramTypes.isEmpty()) {
            String prefix = className + "#" + methodName + "(";
            int n = 0;
            java.util.Iterator<Map.Entry<String, List<XposedInterface.HookHandle>>> it = handles.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry<String, List<XposedInterface.HookHandle>> e = it.next();
                if (!e.getKey().startsWith(prefix)) continue;
                for (XposedInterface.HookHandle h : e.getValue()) {
                    try { h.unhook(); n++; } catch (Throwable t) { }
                }
                it.remove();
            }
            return n;
        }
        String key = keyOf(className, methodName, paramTypes);
        List<XposedInterface.HookHandle> list = handles.remove(key);
        if (list == null) return 0;
        int n = 0;
        for (XposedInterface.HookHandle h : list) {
            try { h.unhook(); n++; } catch (Throwable t) { }
        }
        return n;
    }

    private static String keyOf(String className, String methodName, String paramTypes) {
        return className + "#" + methodName + "(" + (paramTypes == null ? "" : paramTypes) + ")";
    }

    // ===== v1.6: hook/hijack 规则持久化（进程重启自动重挂）=====
    private static final String PREFS_NAME = "spyprobe_rules";
    private static final String KEY_HOOKS = "hooks";
    private static final String KEY_HIJACKS = "hijacks";

    // ===== v1.21/v1.22: 抓包开关持久化（进程重启后恢复用户开关，不再回默认）=====
    // v1.21 用 getRemotePreferences 远程偏好（走 libxposed service IPC），用户实测重启后仍失效；
    // v1.22 改为写目标 App 自身 data 目录文件（进程内直读直写，零 IPC，100% 可靠）

    /** 保存当前 hooks + hijacks 到模块远程偏好（不污染目标 app 数据） */
    public synchronized void saveRules(android.content.SharedPreferences prefs) {
        try {
            org.json.JSONArray hArr = new org.json.JSONArray();
            for (HookSpec h : hooks) {
                if (!h.enabled) continue;
                org.json.JSONObject o = new org.json.JSONObject();
                o.put("c", h.className);
                o.put("m", h.methodName);
                o.put("p", h.paramTypes == null ? "" : h.paramTypes);
                hArr.put(o);
            }
            org.json.JSONArray jArr = new org.json.JSONArray();
            for (HijackRule h : hijacks) {
                org.json.JSONObject o = new org.json.JSONObject();
                o.put("c", h.className);
                o.put("m", h.methodName);
                o.put("p", h.paramTypes == null ? "" : h.paramTypes);
                o.put("mode", h.mode);
                o.put("v", h.returnValue);
                o.put("pv", h.paramValue);
                o.put("fn", h.fieldName);
                o.put("ft", h.fieldType);
                o.put("fv", h.fieldValue);
                jArr.put(o);
            }
            prefs.edit().putString(KEY_HOOKS, hArr.toString()).putString(KEY_HIJACKS, jArr.toString()).apply();
        } catch (Throwable t) { }
    }

    /** 读取持久化规则（进程启动后调用，返回是否加载到内容） */
    public synchronized boolean loadRules(android.content.SharedPreferences prefs) {
        boolean loaded = false;
        try {
            String hStr = prefs.getString(KEY_HOOKS, "");
            if (!hStr.isEmpty()) {
                org.json.JSONArray arr = new org.json.JSONArray(hStr);
                for (int i = 0; i < arr.length(); i++) {
                    org.json.JSONObject o = arr.getJSONObject(i);
                    HookSpec spec = new HookSpec(o.optString("c"), o.optString("m"), o.optString("p"));
                    addHook(spec);
                    loaded = true;
                }
            }
            String jStr = prefs.getString(KEY_HIJACKS, "");
            if (!jStr.isEmpty()) {
                org.json.JSONArray arr = new org.json.JSONArray(jStr);
                for (int i = 0; i < arr.length(); i++) {
                    org.json.JSONObject o = arr.getJSONObject(i);
                    // v1.13: 兼容旧格式（无 mode 字段 = 返回值劫持）
                    int mode = o.optInt("mode", MODE_RETURN);
                    addRule(o.optString("c"), o.optString("m"), o.optString("p"), mode,
                            o.optString("v"), o.optString("pv"), o.optString("fn"), o.optString("ft"), o.optString("fv"));
                    loaded = true;
                }
            }
        } catch (Throwable t) { }
        return loaded;
    }

    // ===== v1.21/v1.22: 抓包开关持久化（进程重启后恢复用户开关，不再回默认）=====
    // v1.21 用 getRemotePreferences 远程偏好（走 libxposed service IPC），用户实测重启后仍失效；
    // v1.22 改为写目标 App 自身 data 目录文件（进程内直读直写，零 IPC，100% 可靠）

    // v1.22: 模块自身调试日志开关（默认关；开启后 LogStore 输出 [DBG] 前缀行，排查持久化/IPC 等问题用）
    public volatile boolean debugEnabled = false;

    /** 保存全部抓包开关到目标 App data 目录文件（每次 UI 下发配置后调用） */
    public synchronized void saveConfig(java.io.File file) {
        if (file == null) return;
        try {
            org.json.JSONObject o = new org.json.JSONObject();
            o.put("sslBypass", sslBypass);
            o.put("okhttp", okhttpCapture);
            o.put("url", urlCapture);
            o.put("dns", dnsCapture);
            o.put("tcp", tcpCapture);
            o.put("classes", classCapture);
            o.put("classFilter", classFilter == null ? "" : classFilter);
            o.put("classLogAll", classLogAll);
            o.put("bodyLimit", bodyLimit);
            o.put("logLimit", logLimit);
            o.put("webView", webViewCapture);
            o.put("prefs", prefsCapture);
            o.put("sqlite", sqliteCapture);
            o.put("urlBuild", urlBuildCapture);
            o.put("logcat", logcatCapture);
            o.put("crypto", cryptoCapture);
            o.put("activity", activityCapture);
            o.put("json", jsonCapture);
            o.put("detailMode", detailMode);
            o.put("env", envCapture);
            o.put("tls", tlsCapture);
            o.put("connect", connectCapture);
            o.put("cronet", cronetCapture);
            o.put("antiRoot", antiRoot);
            o.put("antiXposed", antiXposed);
            o.put("native", nativeCapture);
            o.put("autoProbe", autoProbe);
            o.put("autoProbeFilter", autoProbeFilter == null ? "" : autoProbeFilter);
            o.put("debug", debugEnabled);
            // v1.22: 原子写（tmp + rename），防写入中断损坏配置
            java.io.File tmp = new java.io.File(file.getAbsolutePath() + ".tmp");
            java.io.FileOutputStream fos = new java.io.FileOutputStream(tmp);
            try {
                fos.write(o.toString().getBytes("UTF-8"));
            } finally {
                fos.close();
            }
            if (tmp.renameTo(file)) {
                debugLog("config saved -> " + file.getAbsolutePath() + " (" + o.toString().length() + "B)");
            } else {
                // rename 失败（跨分区/被占用）时退化为直接写目标文件
                java.io.FileOutputStream fos2 = new java.io.FileOutputStream(file);
                try {
                    fos2.write(o.toString().getBytes("UTF-8"));
                } finally {
                    fos2.close();
                }
                debugLog("config saved (direct) -> " + file.getAbsolutePath());
            }
        } catch (Throwable t) {
            debugLog("config save FAIL: " + t);
        }
    }

    /** 进程启动后从目标 App data 目录文件恢复抓包开关（未保存过则保持默认值） */
    public synchronized void loadConfig(java.io.File file) {
        if (file == null) {
            debugLog("config load: file null");
            return;
        }
        try {
            if (!file.exists()) {
                debugLog("config load: no file " + file.getAbsolutePath() + ", keep defaults");
                return;
            }
            java.io.FileInputStream fis = new java.io.FileInputStream(file);
            byte[] buf;
            try {
                java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
                byte[] chunk = new byte[4096];
                int n;
                while ((n = fis.read(chunk)) > 0) bos.write(chunk, 0, n);
                buf = bos.toByteArray();
            } finally {
                fis.close();
            }
            org.json.JSONObject o = new org.json.JSONObject(new String(buf, "UTF-8"));
            sslBypass = o.optBoolean("sslBypass", sslBypass);
            okhttpCapture = o.optBoolean("okhttp", okhttpCapture);
            urlCapture = o.optBoolean("url", urlCapture);
            dnsCapture = o.optBoolean("dns", dnsCapture);
            tcpCapture = o.optBoolean("tcp", tcpCapture);
            classCapture = o.optBoolean("classes", classCapture);
            classFilter = o.optString("classFilter", classFilter);
            classLogAll = o.optBoolean("classLogAll", classLogAll);
            bodyLimit = o.optInt("bodyLimit", bodyLimit);
            logLimit = o.optInt("logLimit", logLimit);
            webViewCapture = o.optBoolean("webView", webViewCapture);
            prefsCapture = o.optBoolean("prefs", prefsCapture);
            sqliteCapture = o.optBoolean("sqlite", sqliteCapture);
            urlBuildCapture = o.optBoolean("urlBuild", urlBuildCapture);
            logcatCapture = o.optBoolean("logcat", logcatCapture);
            cryptoCapture = o.optBoolean("crypto", cryptoCapture);
            activityCapture = o.optBoolean("activity", activityCapture);
            jsonCapture = o.optBoolean("json", jsonCapture);
            detailMode = o.optBoolean("detailMode", detailMode);
            envCapture = o.optBoolean("env", envCapture);
            tlsCapture = o.optBoolean("tls", tlsCapture);
            connectCapture = o.optBoolean("connect", connectCapture);
            cronetCapture = o.optBoolean("cronet", cronetCapture);
            antiRoot = o.optBoolean("antiRoot", antiRoot);
            antiXposed = o.optBoolean("antiXposed", antiXposed);
            nativeCapture = o.optBoolean("native", nativeCapture);
            autoProbe = o.optBoolean("autoProbe", autoProbe);
            autoProbeFilter = o.optString("autoProbeFilter", autoProbeFilter);
            debugEnabled = o.optBoolean("debug", debugEnabled);
            // v1.22: 记录关键开关恢复结果，方便用户反馈日志定位
            debugLog("config restored: prefs=" + prefsCapture + " activity=" + activityCapture
                    + " crypto=" + cryptoCapture + " native=" + nativeCapture + " autoProbe=" + autoProbe);
        } catch (Throwable t) {
            debugLog("config load FAIL: " + t);
        }
    }

    /** v1.22: 模块调试日志（仅 Config.debugEnabled=true 时写入 LogStore，带 [DBG] 前缀） */
    public static void debugLog(String msg) {
        try {
            if (Config.get().debugEnabled) {
                LogStore.get().log("DBG", msg);
            }
        } catch (Throwable t) { }
    }
}
