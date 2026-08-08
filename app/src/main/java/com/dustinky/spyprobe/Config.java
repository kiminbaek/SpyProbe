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
    public volatile String classFilter = "";       // 类加载关键字过滤（空=全部入库不刷屏）
    public volatile boolean classLogAll = false;   // 匹配类是否刷屏输出到日志
    public volatile int bodyLimit = 2048;          // 记录响应体最大字节

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

    /** v1.4: 返回值劫持规则（命中后 hook 回调直接返回强制值，不执行原方法） */
    public static class HijackRule {
        public final String className;
        public final String methodName;
        public final String paramTypes;
        public final String returnValue; // 字符串形式，按方法返回类型解析：true/false/数字/文本/null

        public HijackRule(String className, String methodName, String paramTypes, String returnValue) {
            this.className = className;
            this.methodName = methodName;
            this.paramTypes = paramTypes;
            this.returnValue = returnValue;
        }
    }

    public final List<HijackRule> hijacks = new CopyOnWriteArrayList<>();

    public synchronized void addHijack(String className, String methodName, String paramTypes, String returnValue) {
        // 同 class#method(params) 去重更新
        for (HijackRule h : hijacks) {
            if (h.className.equals(className) && h.methodName.equals(methodName)
                    && h.paramTypes.equals(paramTypes == null ? "" : paramTypes)) {
                hijacks.remove(h);
                break;
            }
        }
        hijacks.add(new HijackRule(className, methodName, paramTypes == null ? "" : paramTypes, returnValue));
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
        // 同时清理句柄
        String key = keyOf(className, methodName, paramTypes);
        handles.remove(key);
        return removed;
    }

    public synchronized void addHandle(String className, String methodName, String paramTypes, XposedInterface.HookHandle h) {
        handles.computeIfAbsent(keyOf(className, methodName, paramTypes), k -> new CopyOnWriteArrayList<>()).add(h);
    }

    /** v1.3: 该 class#method(params) 是否已 hook（防重复 hook 日志翻倍） */
    public synchronized boolean hasHandle(String className, String methodName, String paramTypes) {
        return handles.containsKey(keyOf(className, methodName, paramTypes));
    }

    public synchronized int unhookHandles(String className, String methodName, String paramTypes) {
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
}
