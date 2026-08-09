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

    private static void logUrlOnce(String url) {
        if (!Config.get().urlBuildCapture || url == null) return;
        long now = System.currentTimeMillis();
        Long prev = sUrlSeen.get(url);
        if (prev != null && now - prev < URL_DEDUP_MS) return;
        sUrlSeen.put(url, now);
        if (sUrlSeen.size() > 1024) {
            long cutoff = now - URL_DEDUP_MS;
            sUrlSeen.entrySet().removeIf(e -> now - e.getValue() > cutoff);
        }
        LogStore.get().log(TAG, "[URL] " + url);
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
            DebugLog.get().log("Url", "install(" + phase + ") skipped: Config.get().urlBuildCapture == false");
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
                        logUrlOnce((String) s);
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
                        logUrlOnce((String) s);
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
                        logUrlOnce((String) s);
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
                        logUrlOnce((String) s);
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
