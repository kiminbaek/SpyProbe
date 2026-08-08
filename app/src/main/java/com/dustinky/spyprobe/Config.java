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

    public synchronized void addHijack(String className, String methodName, String paramTypes, String returnValue) {
        addRule(className, methodName, paramTypes, MODE_RETURN, returnValue, "", "", "", "");
    }

    /** v1.13: 通用规则新增/更新（同 class#method(params)+mode 去重） */
    public synchronized void addRule(String className, String methodName, String paramTypes, int mode,
                                     String returnValue, String paramValue, String fieldName, String fieldType, String fieldValue) {
        String pts = paramTypes == null ? "" : paramTypes;
        for (HijackRule h : hijacks) {
            if (h.className.equals(className) && h.methodName.equals(methodName)
                    && h.paramTypes.equals(pts) && h.mode == mode) {
                hijacks.remove(h);
                break;
            }
        }
        hijacks.add(new HijackRule(className, methodName, pts, mode,
                returnValue == null ? "" : returnValue,
                paramValue == null ? "" : paramValue,
                fieldName == null ? "" : fieldName,
                fieldType == null ? "" : fieldType,
                fieldValue == null ? "" : fieldValue));
    }

    public synchronized boolean removeHijack(String className, String methodName, String paramTypes) {
        return hijacks.removeIf(h -> h.className.equals(className)
                && h.methodName.equals(methodName)
                && (paramTypes == null || paramTypes.isEmpty() || h.paramTypes.equals(paramTypes)));
    }

    /** 查找命中劫持规则（精确匹配 class#method(params)，paramTypes 为空=匹配任一重载） */
    public synchronized HijackRule findHijack(String className, String methodName, String paramTypes) {
        for (HijackRule h : hijacks) {
            if (!h.className.equals(className) || !h.methodName.equals(methodName)) continue;
            if (paramTypes == null || paramTypes.isEmpty()) return h;
            if (h.paramTypes.isEmpty() || h.paramTypes.equals(paramTypes)) return h;
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
        // 同时清理句柄（paramTypes 空 = 通配删除该 class#method 的所有具体签名句柄）
        if (paramTypes == null || paramTypes.isEmpty()) {
            String prefix = className + "#" + methodName + "(";
            java.util.Iterator<Map.Entry<String, List<XposedInterface.HookHandle>>> it = handles.entrySet().iterator();
            while (it.hasNext()) {
                if (it.next().getKey().startsWith(prefix)) it.remove();
            }
        } else {
            handles.remove(keyOf(className, methodName, paramTypes));
        }
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
}
