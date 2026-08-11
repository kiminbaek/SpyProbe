package com.dustinky.spyprobe;

import java.lang.reflect.Method;

import io.github.libxposed.api.XposedModule;

/**
 * URL 捕捉（v1.5 新增）：
 * hook java.net.URL 构造 / android.net.Uri.parse / java.net.URI.create / okhttp3.HttpUrl.parse，
 * 记录 app 运行期构造的所有 URL —— 反编译找接口地址/CDN 域名的神器（很多 app 的 URL 是运行时拼的，静态字段/字符串池看不到）。
 */
public class UrlProbe {

    static final String TAG = "SpyProbe.URL";

    // v1.35 P1-1: URL 去重——URL.<init>/Uri.parse/URI.create/HttpUrl.parse 常对同一字符串
    //   连环触发（一次请求记 3-4 条 [URL]/[URI]/[HTTPURL]）。最近 3 秒同 URL 只记一次。
    private static final long URL_DEDUP_MS = 3000;
    private static final java.util.Map<String, Long> sUrlSeen = new java.util.concurrent.ConcurrentHashMap<>();

    /** v1.58: URL 构造点 → 结构化事件（URL 卡片 + 详情页）。
     *  用户诉求：目标 App 数据 + 对逆向有帮助 → 必须结构化显现，不能只留纯文本。
     *  日志行嵌入 [EVT#N]，UI 自动渲染 URL 卡片（绿色），点开详情页有 url/source/调用栈。 */
    private static void logUrlEvent(String url, String source) {
        if (!Config.get().urlBuildCapture || url == null) return;
        // v1.54 P1: 系统级 content:// URI（媒体库/GMS/厂商 provider）对逆向零价值 → 直接过滤
        String lower = url.toLowerCase(java.util.Locale.US);
        if (lower.startsWith("content://")) {
            if (lower.startsWith("content://media")
                    || lower.startsWith("content://com.google.android.gms")
                    || lower.startsWith("content://com.oplusos")
                    || lower.startsWith("content://com.oplus")
                    || lower.contains(".provider.")) {
                return;
            }
        }
        // v1.54 修正：http(s) URL **保留在日志页**——URL 探测的价值是"app 运行时动态拼接的 URL
        //   + 构造调用栈"（静态反编译只能看到写死字符串，拼接逻辑全靠运行时探测），REQ# 卡片只给
        //   网络请求详情，两者是不同维度的信息，不构成重复。不降级 DebugLog。
        long now = System.currentTimeMillis();
        Long prev = sUrlSeen.get(url);
        if (prev != null && now - prev < URL_DEDUP_MS) return;
        sUrlSeen.put(url, now);
        // v1.42 P2-12: 超限处理——旧实现 removeIf 只清超 3s 窗口的项，但窗口内 >1024 个不同
        //   URL 时一条都清不掉 → map 无限膨胀。现在先清过期项；仍超限（窗口内确实爆炸）则整表清空
        //   （最多损失 3s 去重，防内存泄漏优先）。
        if (sUrlSeen.size() > 1024) {
            long cutoff = now - URL_DEDUP_MS;
            sUrlSeen.entrySet().removeIf(e -> now - e.getValue() > cutoff);
            if (sUrlSeen.size() > 1024) {
                sUrlSeen.clear();
            }
        }
        try {
            long eid = EventStore.get().nextId();
            String msg = "[EVT#" + eid + "][URL] " + source + " " + url;
            LogStore.get().log(TAG, msg);
            org.json.JSONObject payload = new org.json.JSONObject();
            payload.put("url", url == null ? "" : url);
            payload.put("source", source == null ? "" : source);
            String stack = StackUtil.getCompact(12);
            String title = url;
            if (title.length() > 90) title = title.substring(0, 90) + "…";
            EventStore.get().add(new SpyEvent("URL", eid, now,
                    title, payload, msg, stack));
        } catch (Throwable t) { /* 结构化失败不影响文本日志 */ }
    }

    private final XposedModule module;
    private final ClassLoader appCl;

    public UrlProbe(XposedModule module, ClassLoader appCl) {
        this.module = module;
        this.appCl = appCl;
    }

    public void install(String phase) {
        // v1.37 P0-1: 惰性安装——开关关闭时完全不装 hook（借鉴 Guise activeHookFeatures，
        //   用户关闭的探测项在目标进程零 hook 存在，减少崩溃面 + 更隐蔽 + 启动更快）
        if (!Config.get().urlBuildCapture) {
            DebugLog.get().logNoMirror("Url", "install(" + phase + ") skipped: Config.get().urlBuildCapture == false");
            return;
        }
        int hooked = 0;
        // 1. java.net.URL.<init>(String) —— 主入口（其它重载内部大多转这个）
        try {
            Class<?> url = Class.forName("java.net.URL");
            java.lang.reflect.Constructor<?> ctor = url.getConstructor(String.class);
            module.hook(ctor).intercept(chain -> {
                Object r = chain.proceed();
                // v1.6: 补开关检查（此前不检查 Config.urlBuildCapture，设置关不掉）
                // v1.35 P1-1: 去重（URL/Uri/URI/HttpUrl 连环触发只记一次）
                if (Config.get().urlBuildCapture) {
                    Object s = chain.getArg(0);
                    if (s instanceof String) {
                        logUrlEvent((String) s, "java.net.URL");
                    }
                }
                return r;
            });
            hooked++;
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] URL ctor hook fail: " + t);
        }
        // 2. android.net.Uri.parse(String) —— Android 常用
        try {
            Class<?> uri = Class.forName("android.net.Uri");
            Method parse = uri.getMethod("parse", String.class);
            module.hook(parse).intercept(chain -> {
                Object r = chain.proceed();
                if (Config.get().urlBuildCapture) {
                    Object s = chain.getArg(0);
                    if (s instanceof String) {
                        logUrlEvent((String) s, "Uri.parse");
                    }
                }
                return r;
            });
            hooked++;
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] Uri.parse hook fail: " + t);
        }
        // 3. java.net.URI.create(String)
        try {
            Class<?> uri = Class.forName("java.net.URI");
            Method create = uri.getMethod("create", String.class);
            module.hook(create).intercept(chain -> {
                Object r = chain.proceed();
                if (Config.get().urlBuildCapture) {
                    Object s = chain.getArg(0);
                    if (s instanceof String) {
                        logUrlEvent((String) s, "URI.create");
                    }
                }
                return r;
            });
            hooked++;
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] URI.create hook fail: " + t);
        }
        // 4. okhttp3.HttpUrl.parse(String) —— OkHttp 应用构造 URL 常用
        try {
            Class<?> hu = Class.forName("okhttp3.HttpUrl", false, appCl);
            Method parse = hu.getMethod("parse", String.class);
            module.hook(parse).intercept(chain -> {
                Object r = chain.proceed();
                if (Config.get().urlBuildCapture) {
                    Object s = chain.getArg(0);
                    if (s instanceof String) {
                        logUrlEvent((String) s, "HttpUrl.parse");
                    }
                }
                return r;
            });
            hooked++;
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] HttpUrl.parse hook fail (app 可能不用 OkHttp): " + t);
        }
        LogStore.get().log(TAG, "[" + phase + "] hooked URL/Uri/URI/HttpUrl x" + hooked);
    }
}
