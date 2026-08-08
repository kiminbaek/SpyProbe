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

    private final XposedModule module;
    private final ClassLoader appCl;

    public UrlProbe(XposedModule module, ClassLoader appCl) {
        this.module = module;
        this.appCl = appCl;
    }

    public void install(String phase) {
        int hooked = 0;
        // 1. java.net.URL.<init>(String) —— 主入口（其它重载内部大多转这个）
        try {
            Class<?> url = Class.forName("java.net.URL");
            java.lang.reflect.Constructor<?> ctor = url.getConstructor(String.class);
            module.hook(ctor).intercept(chain -> {
                Object r = chain.proceed();
                Object s = chain.getArg(0);
                if (s instanceof String) {
                    LogStore.get().log(TAG, "[URL] " + s);
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
                Object s = chain.getArg(0);
                if (s instanceof String) {
                    LogStore.get().log(TAG, "[URI] " + s);
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
                Object s = chain.getArg(0);
                if (s instanceof String) {
                    LogStore.get().log(TAG, "[URI] " + s);
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
                Object s = chain.getArg(0);
                if (s instanceof String) {
                    LogStore.get().log(TAG, "[HTTPURL] " + s);
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
