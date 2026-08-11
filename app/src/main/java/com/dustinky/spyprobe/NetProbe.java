package com.dustinky.spyprobe;

import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import io.github.libxposed.api.XposedModule;

/**
 * 网络抓包核心：
 * 1. SSL 证书锁定绕过（hook SSLContext.init + X509TrustManager.checkServerTrusted + okhttp CertificatePinner）
 * 2. OkHttp 请求/响应记录（hook okhttp3.internal.http.RealInterceptorChain.proceed）
 * 3. HttpURLConnection URL/状态码记录
 */
public class NetProbe {

    static final String TAG = "SpyProbe.Net";

    private final XposedModule module;
    private final ClassLoader appCl;
    // v1.40 P0: DexKit 混淆 OkHttp 定位兜底（ModuleMain 创建后注入；标准类名找不到时用）
    private DexKitProbe dexKit;

    public NetProbe(XposedModule module, ClassLoader appCl) {
        this.module = module;
        this.appCl = appCl;
    }

    /** v1.40 P0: 注入 DexKit（ModuleMain 创建 DexKitProbe 后调用） */
    public void setDexKit(DexKitProbe dexKit) {
        this.dexKit = dexKit;
    }

    /** 安装全部网络 hook
     *  v1.37 P0-1: 惰性安装（借鉴 Guise activeHookFeatures）——按 Config 开关只装用户启用的项，
     *   关闭的探测项在目标进程零 hook 存在（减少崩溃面 + 更隐蔽 + 启动更快）。
     *   注意：early 阶段 Config 尚未从主进程拉取，走默认值（全开）；late 阶段（配置加载后）
     *   若某项被用户关闭，这里跳过不装。 */
    public void install(String phase) {
        DebugLog.get().logNoMirror("Net", "install(" + phase + ") 开始");
        if (Config.get().sslBypass) {
            installSslBypass(phase);
            // v1.38 P0-1: hooker just_trust_me 清单核对——补 12 个 SSL 绕过点
            //   （NetworkSecurityTrustManager/TrustManagerImpl/OkHostnameVerifier/WebView/Cronet/xutils/httpclient 等）
            installSslBypassExt(phase);
        }
        if (Config.get().okhttpCapture) installOkHttpCapture(phase);
        if (Config.get().urlCapture) installUrlCapture(phase);
        if (Config.get().dnsCapture) installDnsCapture(phase);
        if (Config.get().tcpCapture) installSocketCapture(phase);
        if (Config.get().webViewCapture) installWebViewCapture(phase);
        // v1.38 P2-7: WebView debug 开关（hooker webview_enable_debug 借鉴）
        if (Config.get().webViewDebug) installWebViewDebug(phase);
        // v1.9: TLS 明文抓包 + 万能连接点 + Cronet
        if (Config.get().tlsCapture) installTlsCapture(phase);
        if (Config.get().connectCapture) installConnectCapture(phase);
        if (Config.get().cronetCapture) installCronetCapture(phase);
        DebugLog.get().logNoMirror("Net", "install(" + phase + ") 完成");
    }

    // ================= WebView.loadUrl 记录（v1.3）=================
    private void installWebViewCapture(String phase) {
        try {
            Class<?> wv = Class.forName("android.webkit.WebView", false, appCl);
            Method loadUrl = wv.getMethod("loadUrl", String.class);
            module.hook(loadUrl).intercept(chain -> {
                Object r = chain.proceed();
                if (Config.get().webViewCapture) {
                    Object url = chain.getArg(0);
                    if (url != null) {
                        logWebUrlEvent(String.valueOf(url));
                    }
                }
                return r;
            });
            DebugLog.get().logNoMirror("Net", "[" + phase + "] hooked WebView.loadUrl");
        } catch (Throwable t) {
            DebugLog.get().logNoMirror("Net", "[" + phase + "] WebView.loadUrl hook fail: " + t);
        }
    }

    // ================= SSL 证书锁定绕过 =================
    // v1.39 P2: pinning 触发定位——证书校验点被命中时标记"哪种 pinning + 调用方栈"。
    //   一看日志就知道 App 用哪种证书锁定（network_security_config / okhttp pinner / Cronet / 老库…）
    // v1.47 P2-17: 每类 5s 限频（SSLContext.init 每次 TLS 握手都命中，高频连接刷屏）
    private final java.util.concurrent.ConcurrentHashMap<Integer, Long> pinningLast = new java.util.concurrent.ConcurrentHashMap<>();
    private void pinningHit(int idx, String desc) {
        try {
            long now = System.currentTimeMillis();
            Long last = pinningLast.get(idx);
            if (last != null && now - last < 5000) return;
            pinningLast.put(idx, now);
            // v1.58: pinning 触发定位结构化（DETECT 事件，kind=pinning）——知道 App 用哪种证书锁定
            try {
                long eid = EventStore.get().nextId();
                String msg = "[EVT#" + eid + "][Pinning#" + idx + "] " + desc + " | caller: " + StackUtil.getCompact();
                LogStore.get().log(TAG, msg);
                org.json.JSONObject payload = new org.json.JSONObject();
                payload.put("kind", "pinning");
                payload.put("detail", desc + " | caller: " + StackUtil.getCompact());
                EventStore.get().add(new SpyEvent("DETECT", eid, System.currentTimeMillis(),
                        "Pinning#" + idx, payload, msg, ""));
            } catch (Throwable t2) { }
        } catch (Throwable ignored) { }
    }

    /** v1.58: WebView.loadUrl → 结构化 URL 事件（目标 App WebView 加载地址，逆向找 H5 接口） */
    private void logWebUrlEvent(String url) {
        try {
            long eid = EventStore.get().nextId();
            String msg = "[EVT#" + eid + "][URL] WebView.loadUrl " + url;
            LogStore.get().log(TAG, msg);
            org.json.JSONObject payload = new org.json.JSONObject();
            payload.put("url", url == null ? "" : url);
            payload.put("source", "WebView.loadUrl");
            String title = url == null ? "WebView" : url;
            if (title.length() > 90) title = title.substring(0, 90) + "…";
            String stack = StackUtil.getCompact(8);
            EventStore.get().add(new SpyEvent("URL", eid, System.currentTimeMillis(),
                    title, payload, msg, stack));
        } catch (Throwable t) { }
    }

    private void installSslBypass(String phase) {
        // 1. SSLContext.init → 替换 TrustManager 为信任所有
        try {
            final Method init = SSLContext.class.getMethod("init",
                    KeyManager[].class, TrustManager[].class, java.security.SecureRandom.class);
            module.hook(init).intercept(chain -> {
                if (!Config.get().sslBypass) return chain.proceed();
                List<Object> args = chain.getArgs();
                TrustManager[] orig = args.get(1) == null ? null : (TrustManager[]) args.get(1);
                X509TrustManager origX509 = null;
                if (orig != null) {
                    for (TrustManager tm : orig) {
                        if (tm instanceof X509TrustManager) { origX509 = (X509TrustManager) tm; break; }
                    }
                }
                // 显式传新参数数组，确保 libxposed 使用修改后的 TrustManager（P0 修复）
                args.set(1, new TrustManager[]{new TrustAllX509(origX509)});
                Object r = chain.proceed(args.toArray());
                DebugLog.get().logNoMirror(TAG, "[SSL] SSLContext.init bypassed");
                // v1.39 P2: 标准 TLS 握手入口（每次 TLS 连接都会命中）
                pinningHit(1, "SSLContext.init (标准 TLS 握手入口)");
                return r;
            });
            DebugLog.get().logNoMirror("Net", "[" + phase + "] hooked SSLContext.init");
        } catch (Throwable t) {
            DebugLog.get().logNoMirror("Net", "[" + phase + "] SSLContext.init hook fail: " + t);
        }

        // 2. X509TrustManager.checkServerTrusted → 直接返回（信任所有证书）
        try {
            final Method cst = X509TrustManager.class.getMethod("checkServerTrusted",
                    X509Certificate[].class, String.class);
            module.hook(cst).intercept(chain -> {
                if (!Config.get().sslBypass) return chain.proceed();
                // v1.39 P2: 证书链校验点（App 自定义 TrustManager 走这里）
                pinningHit(2, "X509TrustManager.checkServerTrusted (证书链校验点)");
                return null; // 不做校验
            });
            DebugLog.get().logNoMirror("Net", "[" + phase + "] hooked X509TrustManager.checkServerTrusted");
        } catch (Throwable t) {
            DebugLog.get().logNoMirror("Net", "[" + phase + "] X509TrustManager hook fail: " + t);
        }

        // 3. okhttp CertificatePinner.check → 直接返回（绕过证书固定）
        try {
            Class<?> pinner = Class.forName("okhttp3.CertificatePinner", false, appCl);
            Method check = null;
            for (Method m : pinner.getDeclaredMethods()) {
                if (m.getName().equals("check") && m.getParameterTypes().length >= 2) {
                    check = m;
                    break;
                }
            }
            if (check != null) {
                final Method fCheck = check;
                module.hook(check).intercept(chain -> {
                    if (!Config.get().sslBypass) return chain.proceed();
                    // v1.39 P2: okhttp CertificatePinner 命中 = App 做了证书固定！
                    pinningHit(3, "okhttp3.CertificatePinner.check (证书固定 pinner!)");
                    return null;
                });
                DebugLog.get().logNoMirror("Net", "[" + phase + "] hooked CertificatePinner.check");
            } else {
                DebugLog.get().logNoMirror("Net", "[" + phase + "] CertificatePinner.check not found");
            }
        } catch (Throwable t) {
            DebugLog.get().logNoMirror("Net", "[" + phase + "] CertificatePinner hook fail: " + t);
        }
    }

    /** 信任所有证书的 TrustManager（保留原 trustManager 备用） */
    static class TrustAllX509 implements X509TrustManager {
        private final X509TrustManager orig;
        TrustAllX509(X509TrustManager orig) { this.orig = orig; }
        @Override public void checkClientTrusted(X509Certificate[] chain, String authType) { }
        @Override public void checkServerTrusted(X509Certificate[] chain, String authType) { }
        @Override public X509Certificate[] getAcceptedIssuers() { return orig != null ? orig.getAcceptedIssuers() : new X509Certificate[0]; }
    }

    // ================= v1.38 P0-1: hooker just_trust_me 清单补充 SSL 绕过 =================
    // 覆盖现有 3 点之外的盲区：网络安全配置 pinning / Conscrypt TrustManagerImpl 重载 /
    // OkHostnameVerifier / 老 okhttp / xutils / httpclient / WebView / Cronet / Platform.checkServerTrusted。
    // 全部 try-catch：类/方法不存在（不同 ROM/库版本）时静默跳过，不拖垮 install。
    private void installSslBypassExt(String phase) {
        int ok = 0;

        // 1. NetworkSecurityTrustManager.checkPins —— Android 网络安全配置（network_security_config）pinning
        //    签名: List<X509Certificate> checkPins(X509Certificate[] chain, String hostname, String authType)
        //    绕过：直接返回 null（不抛 CertificatePinException → pin 校验放行）
        try {
            Class<?> nstm = Class.forName("android.security.net.config.NetworkSecurityTrustManager");
            Method m = nstm.getMethod("checkPins", X509Certificate[].class, String.class, String.class);
            module.hook(m).intercept(chain -> {
                if (!Config.get().sslBypass) return chain.proceed();
                // v1.39 P2: 系统网络安全配置 pinning（network_security_config.xml 里配了 pin-set）
                pinningHit(4, "NetworkSecurityTrustManager.checkPins (网络安全配置 pin-set!)");
                return null;
            });
            ok++;
            DebugLog.get().logNoMirror("Net", "[" + phase + "] hooked NetworkSecurityTrustManager.checkPins");
        } catch (Throwable t) { }

        // 2. com.android.org.conscrypt.TrustManagerImpl.checkServerTrusted (3 重载)
        //    —— app 直接引用 TrustManagerImpl 类型时，X509TrustManager 接口 hook 覆盖不到这些重载
        try {
            Class<?> tmi = Class.forName("com.android.org.conscrypt.TrustManagerImpl");
            for (Class<?> extra : new Class<?>[]{ javax.net.ssl.SSLSocket.class, javax.net.ssl.SSLEngine.class }) {
                try {
                    Method m = tmi.getMethod("checkServerTrusted", X509Certificate[].class, String.class, extra);
                    module.hook(m).intercept(chain -> {
                        if (!Config.get().sslBypass) return chain.proceed();
                        pinningHit(5, "Conscrypt TrustManagerImpl.checkServerTrusted (直连实现)");
                        return null;
                    });
                    ok++;
                } catch (Throwable t) { }
            }
            try {
                Method m = tmi.getMethod("checkServerTrusted", X509Certificate[].class, String.class);
                module.hook(m).intercept(chain -> {
                    if (!Config.get().sslBypass) return chain.proceed();
                    pinningHit(5, "Conscrypt TrustManagerImpl.checkServerTrusted");
                    return null;
                });
                ok++;
            } catch (Throwable t) { }
            DebugLog.get().logNoMirror("Net", "[" + phase + "] hooked TrustManagerImpl.checkServerTrusted x3");
        } catch (Throwable t) { }

        // 3. TrustManagerImpl.checkTrusted (2 签名) / checkTrustedRecursive —— 链验证内部入口
        try {
            Class<?> tmi = Class.forName("com.android.org.conscrypt.TrustManagerImpl");
            try {
                Method m = tmi.getDeclaredMethod("checkTrusted", X509Certificate[].class);
                module.hook(m).intercept(chain -> {
                    if (!Config.get().sslBypass) return chain.proceed();
                    pinningHit(6, "Conscrypt checkTrusted (链验证内部)");
                    return null;
                });
                ok++;
            } catch (Throwable t) { }
            try {
                Method m = tmi.getDeclaredMethod("checkTrusted", X509Certificate[].class, String.class);
                module.hook(m).intercept(chain -> {
                    if (!Config.get().sslBypass) return chain.proceed();
                    pinningHit(6, "Conscrypt checkTrusted");
                    return null;
                });
                ok++;
            } catch (Throwable t) { }
            try {
                Method m = tmi.getDeclaredMethod("checkTrustedRecursive", X509Certificate[].class, java.util.Date.class, String.class, String.class, boolean.class, java.util.Set.class, java.util.Set.class);
                module.hook(m).intercept(chain -> {
                    if (!Config.get().sslBypass) return chain.proceed();
                    pinningHit(6, "Conscrypt checkTrustedRecursive");
                    return null;
                });
                ok++;
            } catch (Throwable t) { }
            DebugLog.get().logNoMirror("Net", "[" + phase + "] hooked TrustManagerImpl.checkTrusted(+Recursive)");
        } catch (Throwable t) { }

        // 4. X509TrustManagerExtensions.checkServerTrusted —— 带 host 的扩展校验
        //    签名: List<X509Certificate> checkServerTrusted(X509Certificate[] chain, String authType, String host)
        try {
            Class<?> xte = Class.forName("android.net.http.X509TrustManagerExtensions");
            Method m = xte.getMethod("checkServerTrusted", X509Certificate[].class, String.class, String.class);
            module.hook(m).intercept(chain -> {
                if (!Config.get().sslBypass) return chain.proceed();
                pinningHit(7, "X509TrustManagerExtensions.checkServerTrusted (带 host 校验)");
                Object a0 = chain.getArg(0);
                if (a0 instanceof X509Certificate[]) return java.util.Arrays.asList((X509Certificate[]) a0);
                return null;
            });
            ok++;
            DebugLog.get().logNoMirror("Net", "[" + phase + "] hooked X509TrustManagerExtensions.checkServerTrusted");
        } catch (Throwable t) { }

        // 5. okhttp3.internal.tls.OkHostnameVerifier.verify —— 主机名校验（证书 CN/SAN 匹配域名）
        //    签名: boolean verify(String hostname, SSLSession session) / boolean verify(String host, X509Certificate cert)
        try {
            Class<?> ohv = Class.forName("okhttp3.internal.tls.OkHostnameVerifier", false, appCl);
            try {
                Method m = ohv.getMethod("verify", String.class, javax.net.ssl.SSLSession.class);
                module.hook(m).intercept(chain -> {
                    if (!Config.get().sslBypass) return chain.proceed();
                    pinningHit(8, "OkHostnameVerifier.verify(SSLSession) (主机名校验)");
                    return Boolean.TRUE;
                });
                ok++;
            } catch (Throwable t) { }
            try {
                Method m = ohv.getMethod("verify", String.class, X509Certificate.class);
                module.hook(m).intercept(chain -> {
                    if (!Config.get().sslBypass) return chain.proceed();
                    pinningHit(8, "OkHostnameVerifier.verify(cert)");
                    return Boolean.TRUE;
                });
                ok++;
            } catch (Throwable t) { }
            try {
                Method m = ohv.getMethod("verify", X509Certificate.class);
                module.hook(m).intercept(chain -> {
                    if (!Config.get().sslBypass) return chain.proceed();
                    pinningHit(8, "OkHostnameVerifier.verify");
                    return Boolean.TRUE;
                });
                ok++;
            } catch (Throwable t) { }
            if (ok > 0) DebugLog.get().logNoMirror("Net", "[" + phase + "] hooked OkHostnameVerifier.verify");
        } catch (Throwable t) { }

        // 6. com.squareup.okhttp.OkHttpClient.setCertificatePinner —— 老 okhttp (2.x) 证书固定
        try {
            Class<?> ohc = Class.forName("com.squareup.okhttp.OkHttpClient", false, appCl);
            Method m = ohc.getMethod("setCertificatePinner", Class.forName("com.squareup.okhttp.CertificatePinner", false, appCl));
            module.hook(m).intercept(chain -> {
                if (Config.get().sslBypass) {
                    LogStore.get().log(TAG, "[SSL] old-okhttp setCertificatePinner intercepted (bypass)");
                    // v1.39 P2: 老 okhttp (2.x) 证书固定
                    pinningHit(9, "老 okhttp(2.x) setCertificatePinner (证书固定!)");
                    return chain.getThisObject();
                }
                return chain.proceed();
            });
            ok++;
            DebugLog.get().logNoMirror("Net", "[" + phase + "] hooked squareup OkHttpClient.setCertificatePinner");
        } catch (Throwable t) { }

        // 7. xutils RequestParams.setSslSocketFactory / setHostnameVerifier —— 记日志（xutils 库）
        try {
            Class<?> rp = Class.forName("org.xutils.http.RequestParams", false, appCl);
            try {
                Method m = rp.getMethod("setSslSocketFactory", javax.net.ssl.SSLSocketFactory.class);
                module.hook(m).intercept(chain -> {
                    LogStore.get().log(TAG, "[SSL] xutils setSslSocketFactory -> trust-all (bypass)");
                    pinningHit(10, "xutils setSslSocketFactory");
                    return chain.getThisObject();
                });
                ok++;
            } catch (Throwable t) { }
            try {
                Method m = rp.getMethod("setHostnameVerifier", javax.net.ssl.HostnameVerifier.class);
                module.hook(m).intercept(chain -> {
                    LogStore.get().log(TAG, "[SSL] xutils setHostnameVerifier -> allow-all (bypass)");
                    pinningHit(10, "xutils setHostnameVerifier");
                    return chain.getThisObject();
                });
                ok++;
            } catch (Throwable t) { }
        } catch (Throwable t) { }

        // 8. httpclientandroidlib.AbstractVerifier.verify —— 老 Android HttpClient 主机名校验
        //    签名: void verify(String host, SSLSocket ssl) / void verify(String host, String[] cns, String[] subjectAlts) / void verify(String host, X509Certificate cert)
        try {
            Class<?> av = Class.forName("ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier", false, appCl);
            for (Class<?>[] sig : new Class<?>[][]{
                    {String.class, javax.net.ssl.SSLSocket.class},
                    {String.class, String[].class, String[].class},
                    {String.class, X509Certificate.class}}) {
                try {
                    Method m = av.getMethod("verify", sig);
                    module.hook(m).intercept(chain -> {
                        if (!Config.get().sslBypass) return chain.proceed();
                        pinningHit(11, "httpclientandroidlib.AbstractVerifier.verify");
                        return null; // 校验通过（void）
                    });
                    ok++;
                } catch (Throwable t) { }
            }
            DebugLog.get().logNoMirror("Net", "[" + phase + "] hooked AbstractVerifier.verify");
        } catch (Throwable t) { }

        // 9. WebViewClient.onReceivedSslError —— WebView SSL 错误放行
        //    默认实现 cancel() 拒绝；拦截后调 handler.proceed() 放行（不执行原方法）
        try {
            Class<?> wvc = Class.forName("android.webkit.WebViewClient");
            Class<?> handler = Class.forName("android.webkit.SslErrorHandler");
            Class<?> err = Class.forName("android.webkit.SslError");
            Method m = wvc.getMethod("onReceivedSslError", Class.forName("android.webkit.WebView"), handler, err);
            module.hook(m).intercept(chain -> {
                if (!Config.get().sslBypass) return chain.proceed();
                // v1.39 P2: WebView SSL 错误 = H5 页面证书问题（自签/中间人/pinning）
                pinningHit(12, "WebViewClient.onReceivedSslError (H5 证书错误)");
                Object h = chain.getArg(1);
                if (h != null) {
                    try { handler.getMethod("proceed").invoke(h); } catch (Throwable t) { }
                }
                return null;
            });
            ok++;
            DebugLog.get().logNoMirror("Net", "[" + phase + "] hooked WebViewClient.onReceivedSslError (proceed)");
        } catch (Throwable t) { }

        // 10. CronetEngine$Builder.addPublicKeyPins + enablePublicKeyPinningBypassForLocalTrustAnchors —— Cronet pinning
        //     （标准 org.chromium + 字节 com.ttnet 变体都试）
        for (String base : new String[]{"org.chromium.net", "com.ttnet.org.chromium.net"}) {
            try {
                Class<?> b = Class.forName(base + ".CronetEngine$Builder", false, appCl);
                try {
                    Method m = b.getMethod("addPublicKeyPins", String.class, java.util.Collection.class, boolean.class, java.util.Date.class);
                    module.hook(m).intercept(chain -> {
                        if (Config.get().sslBypass) {
                            LogStore.get().log(TAG, "[SSL] Cronet addPublicKeyPins intercepted (bypass) host=" + chain.getArg(0));
                            // v1.39 P2: Cronet 公钥固定（常见于视频/直播类 App）
                            pinningHit(13, "Cronet addPublicKeyPins (公钥固定!) host=" + chain.getArg(0));
                        }
                        return chain.getThisObject();
                    });
                    ok++;
                } catch (Throwable t) { }
                try {
                    Method m = b.getMethod("enablePublicKeyPinningBypassForLocalTrustAnchors", boolean.class);
                    module.hook(m).intercept(chain -> {
                        if (Config.get().sslBypass) {
                            LogStore.get().log(TAG, "[SSL] Cronet enablePinningBypass intercepted");
                            pinningHit(13, "Cronet enablePinningBypass");
                        }
                        return chain.getThisObject();
                    });
                    ok++;
                } catch (Throwable t) { }
            } catch (Throwable t) { }
        }
        DebugLog.get().logNoMirror("Net", "[" + phase + "] SSL bypass ext: " + ok + " hook points installed");

        // 11. com.android.org.conscrypt.Platform.checkServerTrusted (4 重载) —— Conscrypt 底层校验入口
        //     （SSLContext.init 已替换 TM，但部分库直接调 Platform.checkServerTrusted）
        try {
            Class<?> pf = Class.forName("com.android.org.conscrypt.Platform");
            Class<?>[] extra = new Class<?>[]{
                    Class.forName("com.android.org.conscrypt.AbstractConscryptSocket"),
                    Class.forName("com.android.org.conscrypt.OpenSSLEngineImpl"),
                    Class.forName("com.android.org.conscrypt.OpenSSLSocketImpl"),
                    Class.forName("com.android.org.conscrypt.ConscryptEngine")};
            int n = 0;
            for (Class<?> e : extra) {
                try {
                    Method m = pf.getDeclaredMethod("checkServerTrusted", X509Certificate[].class, String.class, e);
                    module.hook(m).intercept(chain -> {
                        if (!Config.get().sslBypass) return chain.proceed();
                        pinningHit(14, "Conscrypt Platform.checkServerTrusted (底层校验)");
                        return null;
                    });
                    n++;
                } catch (Throwable t) { }
            }
            if (n > 0) {
                ok++;
                DebugLog.get().logNoMirror("Net", "[" + phase + "] hooked Platform.checkServerTrusted x" + n);
            }
        } catch (Throwable t) { }

        DebugLog.get().logNoMirror("Net", "[" + phase + "] SSL bypass ext total: " + ok + " (含子点，部分 ROM 无对应类属正常)");
    }

    // ================= v1.38 P2-7: WebView debug 开启（hooker webview_enable_debug 借鉴）=================
    // WebView 构造后自动 setWebContentsDebuggingEnabled(true) —— Chrome DevTools 可调试 H5 页面
    private void installWebViewDebug(String phase) {
        try {
            Class<?> wv = Class.forName("android.webkit.WebView");
            for (Class<?>[] sig : new Class<?>[][]{
                    {android.content.Context.class},
                    {android.content.Context.class, android.util.AttributeSet.class},
                    {android.content.Context.class, android.util.AttributeSet.class, int.class},
                    {android.content.Context.class, android.util.AttributeSet.class, int.class, boolean.class}}) {
                try {
                    java.lang.reflect.Constructor<?> m = wv.getConstructor(sig);
                    module.hook(m).intercept(chain -> {
                        Object r = chain.proceed();
                        if (Config.get().webViewDebug) {
                            Object thiz = chain.getThisObject();
                            if (thiz != null) {
                                try {
                                    wv.getMethod("setWebContentsDebuggingEnabled", boolean.class).invoke(null, true);
                                    // 只在首次记录（WebView 常被大量构造）
                                    if (!webViewDebugLogged) {
                                        webViewDebugLogged = true;
                                        DebugLog.get().logNoMirror(TAG, "[WebView] setWebContentsDebuggingEnabled(true) 已开启");
                                    }
                                } catch (Throwable t) { }
                            }
                        }
                        return r;
                    });
                } catch (Throwable t) { }
            }
            DebugLog.get().logNoMirror("Net", "[" + phase + "] hooked WebView.<init> (debug enabled)");
        } catch (Throwable t) {
            DebugLog.get().logNoMirror("Net", "[" + phase + "] WebView debug hook fail: " + t);
        }
    }
    private static volatile boolean webViewDebugLogged = false;

    // ================= DNS 解析记录（v1.2）=================
    private void installDnsCapture(String phase) {
        // getAllByName(String) 是域名解析主入口（getByName 内部也走它）
        // v1.6: 成功/失败路径合并为单 hook（原双 hook 拦截链冗余），失败也留痕
        try {
            final Method gab = InetAddress.class.getMethod("getAllByName", String.class);
            module.hook(gab).intercept(chain -> {
                Object host = chain.getArg(0);
                try {
                    Object r = chain.proceed();
                    if (Config.get().dnsCapture && r instanceof InetAddress[]) {
                        InetAddress[] addrs = (InetAddress[]) r;
                        StringBuilder sb = new StringBuilder("[DNS] ").append(host).append(" -> [");
                        for (int i = 0; i < addrs.length; i++) {
                            if (i > 0) sb.append(", ");
                            sb.append(addrs[i].getHostAddress());
                        }
                        sb.append("]");
                        String msg = sb.toString();
                        // v1.55: 结构化 Net 事件（DNS 成功）
                        logNetEvent("DNS", String.valueOf(host), "", 0, 0, true, "", msg);
                    }
                    return r;
                } catch (Throwable t) {
                    if (Config.get().dnsCapture) {
                        String msg = "[DNS] FAIL " + host + " : " + t;
                        // v1.55: 结构化 Net 事件（DNS 失败）
                        logNetEvent("DNS", String.valueOf(host), "", 0, 0, false, String.valueOf(t), msg);
                    }
                    throw t;
                }
            });
            DebugLog.get().logNoMirror("Net", "[" + phase + "] hooked InetAddress.getAllByName");
        } catch (Throwable t) {
            DebugLog.get().logNoMirror("Net", "[" + phase + "] DNS hook fail: " + t);
        }
    }

    // ================= Socket 连接记录（v1.2）=================
    // v1.7: 只 hook connect(SocketAddress,int) 一个重载 ——
    //   Socket.connect(SocketAddress) 内部委托 connect(SocketAddress,int)，
    //   同时 hook 两个重载会把同一个连接记 2 次 [TCP]。
    private void installSocketCapture(String phase) {
        try {
            final Method connect = java.net.Socket.class.getMethod("connect", java.net.SocketAddress.class, int.class);
            module.hook(connect).intercept(chain -> {
                Object addr = chain.getArg(0);
                Object to = chain.getArg(1);
                int timeout = to instanceof Integer ? (Integer) to : -1;
                try {
                    Object r = chain.proceed();
                    logSocket(addr, timeout);
                    return r;
                } catch (Throwable t) {
                    logSocketFail(addr, timeout, t);
                    throw t;
                }
            });
            DebugLog.get().logNoMirror("Net", "[" + phase + "] hooked Socket.connect(SocketAddress,int)");
        } catch (Throwable t) {
            DebugLog.get().logNoMirror("Net", "[" + phase + "] Socket.connect(SocketAddress,int) hook fail: " + t);
        }
    }

    private void logSocket(Object addr, int timeout) {
        if (!Config.get().tcpCapture) return;
        try {
            java.net.InetSocketAddress isa = (java.net.InetSocketAddress) addr;
            // v1.51.1: 自家内部通信过滤——目标进程推送日志到主进程 9900 / 拉配置 9900 等
            //   TCP 连接会被 hook 的 Socket.connect 捕获，无过滤则产生 [TCP] 127.0.0.1:9900 自增长刷屏
            if (isSelfInternal(isa)) return;
            String host = isa.getHostString();
            String ip = isa.getAddress() != null ? isa.getAddress().getHostAddress() : "?";
            String msg = "[TCP] " + host + " (" + ip + "):" + isa.getPort()
                    + (timeout > 0 ? " timeout=" + timeout : "");
            // v1.55: 结构化 Net 事件（连接成功）
            logNetEvent("TCP", host, ip, isa.getPort(), timeout, true, "", msg);
        } catch (Throwable t) { }
    }

    /** v1.51.1: 是否 SpyProbe 自家内部端点——回环地址 + 端口段 9900-9910
     *  （主进程数据面 9900 / 目标进程控制面 9901-9910），全部是工具自身通信，不进业务日志流 */
    private static boolean isSelfInternal(java.net.InetSocketAddress isa) {
        if (isa == null) return false;
        String ip = isa.getAddress() != null ? isa.getAddress().getHostAddress() : null;
        if (ip == null) return false;
        boolean loopback = ip.startsWith("127.")
                || ip.equals("::1")
                || ip.startsWith("::ffff:127.")
                || ip.startsWith("0:0:0:0:0:0:0:1");
        if (!loopback) return false;
        int p = isa.getPort();
        return p >= 9900 && p <= 9910;
    }

    /** v1.6: Socket 连接失败留痕（域名/端口 + 错误） */
    private void logSocketFail(Object addr, int timeout, Throwable err) {
        if (!Config.get().tcpCapture) return;
        try {
            java.net.InetSocketAddress isa = (java.net.InetSocketAddress) addr;
            // v1.51.1: 自家内部通信同样过滤（推日志失败也无需进业务日志流）
            if (isSelfInternal(isa)) return;
            String host = isa.getHostString();
            String ip = isa.getAddress() != null ? isa.getAddress().getHostAddress() : "?";
            String msg = "[TCP] FAIL " + host + " (" + ip + "):" + isa.getPort()
                    + (timeout > 0 ? " timeout=" + timeout : "") + " -> " + err;
            // v1.55: 结构化 Net 事件（连接失败）
            logNetEvent("TCP", host, ip, isa.getPort(), timeout, false, String.valueOf(err), msg);
        } catch (Throwable t) { }
    }

    /** v1.55: 结构化 Net 事件（TCP/DNS 连接）——日志行嵌入 [EVT#id]，EventStore 写 SpyEvent */
    private static void logNetEvent(String kind, String host, String ip, int port, int timeout,
                                    boolean ok, String err, String msg) {
        try {
            long eid = EventStore.get().nextId();
            String tagged = "[EVT#" + eid + "]" + msg;
            LogStore.get().log(TAG, tagged);
            org.json.JSONObject payload = new org.json.JSONObject();
            payload.put("kind", kind == null ? "" : kind);
            payload.put("host", host == null ? "" : host);
            payload.put("ip", ip == null ? "" : ip);
            payload.put("port", port);
            payload.put("timeout", timeout);
            payload.put("ok", ok);
            payload.put("err", err == null ? "" : err);
            EventStore.get().add(new SpyEvent("NET", eid, System.currentTimeMillis(),
                    (kind == null ? "" : kind) + " " + (host == null ? "" : host) + ":" + port,
                    payload, tagged, ""));
        } catch (Throwable t) { /* 结构化失败不影响文本日志 */ }
    }

    // ================= OkHttp 抓包 =================
    // v1.6: 反射缓存（每次请求 10+ 次 getMethod → 首次解析后复用）
    // v1.47 P2-1: static 反射字段加 volatile——ensureReq/RespMethods 多线程惰性初始化 data race 无害但规范
    private static volatile Method sReqUrl, sReqMethod, sReqHeaders, sReqBody;
    private static volatile Method sBodyBuffer, sBodyContentLength;
    private static volatile Method sBufferUtf8;
    private static volatile Method sRespPeek, sRespCode, sRespMsg, sRespHeaders, sRespBodyString;
    /** 请求体最大可读字节（超过不 buffer，防 OOM） */
    private static final int MAX_REQ_BODY = 1 << 20;

    private static void ensureReqMethods(Object req) throws Exception {
        if (sReqUrl == null) {
            Class<?> rc = req.getClass();
            sReqUrl = rc.getMethod("url");
            sReqMethod = rc.getMethod("method");
            sReqHeaders = rc.getMethod("headers");
            sReqBody = rc.getMethod("body");
            Class<?> bc = sReqBody.getReturnType();
            sBodyBuffer = bc.getMethod("buffer");
            sBodyContentLength = bc.getMethod("contentLength");
            sBufferUtf8 = sBodyBuffer.getReturnType().getMethod("utf8");
        }
    }

    private static void ensureRespMethods(Object resp) throws Exception {
        if (sRespPeek == null) {
            Class<?> rc = resp.getClass();
            sRespPeek = rc.getMethod("peekBody", long.class);
            sRespCode = rc.getMethod("code");
            sRespMsg = rc.getMethod("message");
            sRespHeaders = rc.getMethod("headers");
            sRespBodyString = sRespPeek.getReturnType().getMethod("string");
        }
    }

    private void installOkHttpCapture(String phase) {
        // hook okhttp3.internal.http.RealInterceptorChain.proceed(Request)
        // 该方法在 okhttp3/okhttp4 均存在，是请求必经链路（包括异步）
        String[] chainCls = {
                "okhttp3.internal.http.RealInterceptorChain",
                "okhttp3.internal.http.RealInterceptorChainKt"
        };
        boolean hooked = false;
        for (String cn : chainCls) {
            try {
                Class<?> chain = Class.forName(cn, false, appCl);
                Method proceed = null;
                for (Method m : chain.getDeclaredMethods()) {
                    if (m.getName().equals("proceed") && m.getParameterTypes().length == 1) {
                        proceed = m;
                        break;
                    }
                }
                if (proceed == null) continue;
                final Method fProceed = proceed;
                module.hook(proceed).intercept(chainParam -> {
                    if (!Config.get().okhttpCapture) return chainParam.proceed();
                    Object req = chainParam.getArg(0);
                    if (req == null) return chainParam.proceed();
                    // v1.35 P1-3: 请求关联 ID——LogStore 下一条 seq，请求/响应行共用，
                    //   同一请求的两条记录可 grep "#123" 关联（轻量方案，不跨层做全链路）
                    long rid = LogStore.get().nextHttpId(); // v1.62 P1-10: 独立 httpId（nextSeq 不消费并发撞 id）
                    // method/url 需在 try 外可见（失败留痕也要用）
                    Object method = null;
                    Object url = null;
                    // v1.48: 结构化 HttpEntry（小黄鸟式详情数据源）
                    HttpEntry he = null;
                    try {
                        ensureReqMethods(req);
                        url = sReqUrl.invoke(req);
                        method = sReqMethod.invoke(req);
                        Object headers = sReqHeaders.invoke(req);
                        StringBuilder sb = new StringBuilder();
                        sb.append("[REQ#").append(rid).append("] >>> ").append(method).append(" ").append(url);
                        // v1.48: 解析请求头为 k-v map（结构化详情用）
                        java.util.Map<String, String> reqHdrs = new java.util.TreeMap<>();
                        if (headers != null) {
                            // okhttp Headers.toString() 格式 "Key: value\n..."
                            String hs = headers.toString();
                            for (String line : hs.split("\n")) {
                                int c = line.indexOf(':');
                                if (c > 0) reqHdrs.put(line.substring(0, c).trim(), line.substring(c + 1).trim());
                            }
                            sb.append("\n    ").append(hs.replace("\n", "\n    "));
                        }
                        // P0-2(v1.6): 记录请求体前先查 contentLength()，超大 body 不 buffer（防 OOM）
                        String reqBodyStr = "";
                        int reqBodyBytes = 0;
                        try {
                            Object body = sReqBody.invoke(req);
                            if (body != null) {
                                long clen = (Long) sBodyContentLength.invoke(body);
                                if (clen > 0 && clen <= MAX_REQ_BODY) {
                                    Object buffer = sBodyBuffer.invoke(body);
                                    if (buffer != null) {
                                        Object bstr = sBufferUtf8.invoke(buffer);
                                        if (bstr != null) {
                                            String bs = bstr.toString();
                                            // v1.36 P2-10: 与响应 peekBody 同下限（Math.max 256）消除不对称；
                                            //   截断标注显示原始长度（旧实现显示截断后长度误导）
                                            int reqLimit = Math.max(256, Config.get().bodyLimit * 1024);
                                            if (bs.length() > reqLimit) {
                                                int reqRawLen = bs.length();
                                                bs = bs.substring(0, reqLimit) + "...(" + reqRawLen + "B)";
                                            }
                                            reqBodyStr = bs;
                                            reqBodyBytes = bs.length();
                                            sb.append("\n    reqBody: ").append(bs.replace("\n", "\n    "));
                                        }
                                    }
                                } else if (clen > MAX_REQ_BODY) {
                                    reqBodyBytes = (int) Math.min(clen, Integer.MAX_VALUE);
                                    sb.append("\n    reqBody: <skipped ").append(clen).append("B, too large>");
                                }
                            }
                        } catch (Throwable t) { /* one-shot body 忽略 */ }
                        LogStore.get().log(TAG, sb.toString());
                        // v1.48: 构建结构化条目（body 类型嗅探，栈摘要取前几帧）
                        String ct = reqHdrs.get("Content-Type");
                        String btype = HttpEntry.sniffBodyType(ct, reqBodyStr);
                        String stack = StackUtil.getCompact();
                        he = new HttpEntry("OKHTTP", rid, System.currentTimeMillis(),
                                Thread.currentThread().getName(),
                                String.valueOf(method), String.valueOf(url),
                                reqHdrs, btype, reqBodyStr, reqBodyBytes,
                                stack, sb.toString());
                        HttpStore.get().add(he);
                    } catch (Throwable t) {
                        LogStore.get().log(TAG, "[OkHttp] req parse fail: " + t);
                    }
                    final HttpEntry fHe = he;
                    // v1.59: 请求头发送完成时刻（proceed 前）
                    if (fHe != null) { fHe.reqEndMs = System.currentTimeMillis(); }
                    Object resp;
                    try {
                        resp = chainParam.proceed();
                    } catch (Throwable t) {
                        // v1.2: 失败请求留痕（连接失败/超时/协议错误），rethrow 保持原行为
                        // v1.35 P1-3: 失败行带关联 ID
                        LogStore.get().log(TAG, "[REQ#" + rid + "] !!! REQUEST FAILED: " + method + " " + url + " -> " + t);
                        // v1.48: 失败请求也补状态（status=0 + done，UI 显示失败）
                        if (fHe != null) { fHe.done = true; fHe.durationMs = System.currentTimeMillis() - fHe.time; }
                        throw t;
                    }
                    // v1.59: 响应头开始到达时刻（proceed 返回，近似）
                    if (fHe != null && fHe.respStartMs == 0) { fHe.respStartMs = System.currentTimeMillis(); }
                    try {
                        int limit = Math.max(256, Config.get().bodyLimit * 1024); // v1.25 P1-2: bodyLimit 单位 KB
                        ensureRespMethods(resp);
                        // okhttp Response.peekBody(long) 不消费原流
                        Object body = sRespPeek.invoke(resp, (long) limit);
                        Object code = sRespCode.invoke(resp);
                        Object msg = sRespMsg.invoke(resp);
                        Object respHeaders = sRespHeaders.invoke(resp);
                        Object bodyStr = body != null ? sRespBodyString.invoke(body) : "";
                        // v1.8: toString() 只调一次（每次调用都重新 UTF-8 解码，大 body 重复解码浪费）
                        String b = bodyStr == null ? "" : bodyStr.toString();
                        // v1.36 P2-10: 截断标注显示原始长度（旧实现 b.length() 已是被截断后的值）
                        int rawLen = b.length();
                        if (rawLen > limit) b = b.substring(0, limit) + "...(" + rawLen + "B)";
                        StringBuilder sb = new StringBuilder();
                        sb.append("[REQ#").append(rid).append("] <<< ").append(code).append(" ").append(msg);
                        // v1.48: 解析响应头为 k-v map
                        java.util.Map<String, String> rspHdrs = new java.util.TreeMap<>();
                        if (respHeaders != null) {
                            // v1.2: 响应头（Set-Cookie / Content-Type / 长度）
                            String hs = respHeaders.toString();
                            for (String line : hs.split("\n")) {
                                int c = line.indexOf(':');
                                if (c > 0) rspHdrs.put(line.substring(0, c).trim(), line.substring(c + 1).trim());
                            }
                            sb.append("\n    ").append(hs.replace("\n", "\n    "));
                        }
                        sb.append("\n    body(").append(b.length()).append("B): ")
                          .append(b.replace("\n", "\n    "));
                        LogStore.get().log(TAG, sb.toString());
                        // v1.48: 填充结构化条目响应
                        if (fHe != null) {
                            String rct = rspHdrs.get("Content-Type");
                            String rtype = HttpEntry.sniffBodyType(rct, b);
                            int rbytes = rawLen > limit ? limit : rawLen;
                            long dur = System.currentTimeMillis() - fHe.time;
                            int status = 0;
                            try { status = ((Number) code).intValue(); } catch (Throwable ignored) { }
                            fHe.complete(status, String.valueOf(msg), rspHdrs, rtype, b, rbytes, dur);
                        }
                    } catch (Throwable t) {
                        LogStore.get().log(TAG, "[OkHttp] resp parse fail: " + t);
                    }
                    return resp;
                });
                DebugLog.get().logNoMirror("Net", "[" + phase + "] hooked " + cn + ".proceed");
                hooked = true;
                break;
            } catch (Throwable t) {
                DebugLog.get().logNoMirror("Net", "[" + phase + "] " + cn + " hook fail: " + t);
            }
        }
        if (!hooked) {
            // 备选：hook okhttp3.RealCall.execute（同步调用）
            try {
                Class<?> call = Class.forName("okhttp3.RealCall", false, appCl);
                Method exec = call.getDeclaredMethod("execute");
                module.hook(exec).intercept(chainParam -> {
                    Object r = chainParam.proceed();
                    if (Config.get().okhttpCapture) {
                        try {
                            Object code = r.getClass().getMethod("code").invoke(r);
                            Object req = r.getClass().getMethod("request").invoke(r);
                            Object url = req.getClass().getMethod("url").invoke(req);
                            Object method = req.getClass().getMethod("method").invoke(req);
                            // v1.58: fallback 也结构化（此前纯文本，无 REQ# 卡片）
                            long rid = LogStore.get().nextHttpId(); // v1.62 P1-10: 独立 httpId（nextSeq 不消费并发撞 id）
                            String line = "[REQ#" + rid + "] <<< " + code + " " + url;
                            LogStore.get().log(TAG, line);
                            HttpEntry he = new HttpEntry("REALCALL", rid, System.currentTimeMillis(),
                                    Thread.currentThread().getName(),
                                    String.valueOf(method), String.valueOf(url),
                                    new java.util.TreeMap<>(), "none", "", 0,
                                    StackUtil.getCompact(), line);
                            // v1.59: REALCALL 时间点（近似：响应已到，reqEnd≈respStart≈now）
                            long nowMs = System.currentTimeMillis();
                            he.setConnMeta("HTTP/1.1", nowMs, nowMs, 0, 0, "", 0, "", 0);
                            int status = 0;
                            try { status = ((Number) code).intValue(); } catch (Throwable ignored) { }
                            he.complete(status, "", new java.util.TreeMap<>(), "text", "", 0, 0);
                            HttpStore.get().add(he);
                        } catch (Throwable t) { }
                    }
                    return r;
                });
                DebugLog.get().logNoMirror("Net", "[" + phase + "] hooked okhttp3.RealCall.execute (fallback)");
            } catch (Throwable t) {
                DebugLog.get().logNoMirror("Net", "[" + phase + "] okhttp hook all fail: " + t);
            }
        }
        // v1.40 P0/P1: OkHttpClient.newCall hook ——
        //   P1 重放缓存（所有 OkHttp 请求必经入口，同步/异步都走）
        //   P0 混淆兜底（okhttp proguard 规则 keep public API：OkHttpClient/Request/Response 类名
        //     与方法名保留，只有 RealInterceptorChain/RealCall 等 internal 类混淆 —— 混淆 App 里
        //     链 hook 失败但 newCall 一定能找到，从 newCall 拿 call 具体类动态 hook 响应记录）
        installNewCallReplay(phase, hooked);
    }

    // ================= v1.40 P0/P1: OkHttpClient.newCall（混淆定位 + 请求重放缓存）=================
    // okhttp 官方 proguard 规则 keep public API → 混淆 App 中：
    //   okhttp3.OkHttpClient / okhttp3.Request / okhttp3.Response / okhttp3.Call 类名保留
    //   newCall() / url() / method() / headers() / body() / execute() / enqueue() 方法名保留
    //   RealInterceptorChain / RealCall 等 internal 类被混淆 → 链 hook 失效
    // 所以 newCall 是混淆场景最稳定的落点：请求记录 + 重放缓存 + 动态 hook 具体 call 类响应。
    private static final java.util.Set<String> dynamicHookedCalls = java.util.concurrent.ConcurrentHashMap.newKeySet();

    private void installNewCallReplay(String phase, boolean chainHooked) {
        try {
            Class<?> ohc = findOkHttpClientClass();
            if (ohc == null) {
                DebugLog.get().logNoMirror("Net", "[" + phase + "] OkHttpClient.newCall hook fail: class not found (混淆?)");
                return;
            }
            Class<?> reqCls = Class.forName("okhttp3.Request", false, appCl);
            final Method newCall = ohc.getMethod("newCall", reqCls);
            final boolean chainHookedF = chainHooked;
            final Class<?> clientCls = ohc;
            module.hook(newCall).intercept(chain -> {
                if (!Config.get().okhttpCapture) return chain.proceed();
                Object req = chain.getArg(0);
                Object call = chain.proceed();
                if (call == null) return call;
                try {
                    // P1: 重放缓存（总是缓存；仅混淆场景 logReq=true 打印请求日志）
                    OkHttpReplay.get().onNewCall(call, req, !chainHookedF);
                } catch (Throwable t) { }
                // P0: 链 hook 失败（混淆场景）→ 动态 hook call 具体类记录响应
                if (!chainHookedF) {
                    try {
                        hookDynamicOkHttpCall(call);
                    } catch (Throwable t) {
                        DebugLog.get().logNoMirror("Net", "dynamic call hook fail: " + t);
                    }
                }
                return call;
            });
            DebugLog.get().logNoMirror("Net", "[" + phase + "] hooked " + ohc.getName() + ".newCall"
                    + (chainHookedF ? " (重放缓存)" : " (混淆兜底: 请求记录+动态响应hook)"));
            DebugLog.get().logNoMirror("Net", "[" + phase + "] hooked " + ohc.getName() + ".newCall chainHooked=" + chainHookedF);
        } catch (Throwable t) {
            DebugLog.get().logNoMirror("Net", "[" + phase + "] OkHttpClient.newCall hook fail: " + t);
        }
    }

    /** v1.40 P0: 找 OkHttpClient 类 —— 标准类名优先，找不到用 DexKit 兜底（极端全混淆） */
    private Class<?> findOkHttpClientClass() {
        // 1. 标准类名（okhttp proguard keep，绝大多数 App 保留）
        try {
            return Class.forName("okhttp3.OkHttpClient", false, appCl);
        } catch (Throwable t) { }
        // 2. DexKit 兜底：类名含 OkHttpClient（混淆后类名仍带特征）
        try {
            if (dexKit != null && dexKit.isReady()) {
                String r = dexKit.findOkHttpClientClass();
                if (r != null && !r.isEmpty()) {
                    return Class.forName(r, false, appCl);
                }
            }
        } catch (Throwable t) { }
        // 3. 类名含 OkHttp（更宽匹配）
        try {
            if (dexKit != null && dexKit.isReady()) {
                String r = dexKit.findOkHttpAnyClass();
                if (r != null && !r.isEmpty()) {
                    return Class.forName(r, false, appCl);
                }
            }
        } catch (Throwable t) { }
        return null;
    }

    /** v1.40 P0: 动态 hook 混淆 RealCall 具体类 —— 记录响应（链 hook 失败时的兜底） */
    private void hookDynamicOkHttpCall(Object call) {
        Class<?> realCls = call.getClass();
        String key = realCls.getName();
        if (dynamicHookedCalls.contains(key)) return; // 每类只 hook 一次
        Class<?> respCls;
        try {
            respCls = Class.forName("okhttp3.Response", false, appCl);
        } catch (Throwable t) {
            return;
        }
        int hooked = 0;
        // a. 返回类型为 Response 的无参方法（混淆 RealCall.getResponseWithInterceptorChain 等价物）——
        //    同步/异步最终都走它，hook 一次两者都覆盖
        try {
            for (Method m : realCls.getDeclaredMethods()) {
                if (m.getParameterTypes().length != 0) continue;
                if (m.getReturnType() != respCls) continue;
                module.hook(m).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().okhttpCapture) {
                        try {
                            Object self = chain.getThisObject();
                            Object req = self != null ? self.getClass().getMethod("request").invoke(self) : null;
                            Object method = null, url = null;
                            if (req != null) {
                                try {
                                    method = req.getClass().getMethod("method").invoke(req);
                                    url = req.getClass().getMethod("url").invoke(req);
                                } catch (Throwable t) { }
                            }
                            StringBuilder sb = new StringBuilder("[OkHttp-混淆] <<< ");
                            try {
                                if (r != null) {
                                    Object code = r.getClass().getMethod("code").invoke(r);
                                    Object msg = r.getClass().getMethod("message").invoke(r);
                                    sb.append(code).append(" ").append(msg);
                                } else {
                                    sb.append("null");
                                }
                            } catch (Throwable t) { sb.append("?"); }
                            if (url != null) sb.append(" ").append(url);
                            // 响应体摘要（peekBody 不消费流）
                            try {
                                if (r != null) {
                                    Method peek = r.getClass().getMethod("peekBody", long.class);
                                    Object pbody = peek.invoke(r, 512L);
                                    if (pbody != null) {
                                        Object s = pbody.getClass().getMethod("string").invoke(pbody);
                                        if (s != null) {
                                            String bs = s.toString();
                                            if (bs.length() > 256) bs = bs.substring(0, 256) + "...(" + bs.length() + "B)";
                                            sb.append("\n    body: ").append(bs.replace("\n", "\n    "));
                                        }
                                    }
                                }
                            } catch (Throwable t) { }
                            LogStore.get().log(TAG, sb.toString());
                        } catch (Throwable t) { }
                    }
                    return r;
                });
                hooked++;
                break;
            }
        } catch (Throwable t) { }
        // b. execute()（同步调用，返回 Response）—— a 找不到时的兜底
        if (hooked == 0) {
            try {
                Method exec = realCls.getMethod("execute");
                if (exec.getReturnType() == respCls) {
                    module.hook(exec).intercept(chain -> {
                        Object r = chain.proceed();
                        if (Config.get().okhttpCapture) {
                            try {
                                Object req = chain.getThisObject() != null
                                        ? chain.getThisObject().getClass().getMethod("request").invoke(chain.getThisObject()) : null;
                                Object url = req != null ? req.getClass().getMethod("url").invoke(req) : "?";
                                Object code = r != null ? r.getClass().getMethod("code").invoke(r) : "?";
                                LogStore.get().log(TAG, "[OkHttp-混淆] <<< " + code + " " + url);
                            } catch (Throwable t) { }
                        }
                        return r;
                    });
                    hooked++;
                }
            } catch (Throwable t) { }
        }
        if (hooked > 0) {
            dynamicHookedCalls.add(key);
            DebugLog.get().logNoMirror("Net", "[OkHttp-混淆] 动态 hooked " + key + " 响应记录 x" + hooked);
            DebugLog.get().logNoMirror("Net", "dynamic hooked " + key + " x" + hooked);
        }
    }

    // ================= HttpURLConnection 记录 =================
    private void installUrlCapture(String phase) {
        try {
            final Method grc = HttpURLConnection.class.getMethod("getResponseCode");
            module.hook(grc).intercept(chainParam -> {
                Object r = chainParam.proceed();
                if (Config.get().urlCapture) {
                    try {
                        HttpURLConnection c = (HttpURLConnection) chainParam.getThisObject();
                        URL u = c.getURL();
                        String m = c.getRequestMethod();
                        // P1: 记录响应头 + Content-Length
                        StringBuilder hd = new StringBuilder();
                        java.util.Map<String, String> rspHdrs = new java.util.TreeMap<>();
                        try {
                            Map<String, List<String>> hf = c.getHeaderFields();
                            if (hf != null) {
                                String cl = c.getHeaderField("Content-Length");
                                String ct = c.getHeaderField("Content-Type");
                                hd.append(" Content-Length=").append(cl == null ? "?" : cl)
                                  .append(" Content-Type=").append(ct == null ? "?" : ct);
                                for (Map.Entry<String, List<String>> e : hf.entrySet()) {
                                    if (e.getKey() != null && e.getValue() != null && !e.getValue().isEmpty()) {
                                        rspHdrs.put(e.getKey(), e.getValue().get(0));
                                    }
                                }
                            }
                        } catch (Throwable t) { }
                        String line = "[HUC] " + m + " " + u + " -> " + r + hd;
                        LogStore.get().log(TAG, line);
                        // v1.48: 轻量结构化（HUC 请求头拿不到，只记录 method/url/status/响应头）
                        // v1.50 P1-4: id 统一用 LogStore.nextSeq()（原来独立 nextId 从 1 起，
                        //   与 OKHTTP 的 rid=LogStore seq 同区间 → HttpStore 环形里可能同 id 冲突，
                        //   UI find(id) 会命中错误条目）
                        // v1.58: 日志行补 [REQ#rid] 前缀（此前 line 无标记，UI 解析不到卡片）
                        long hucRid = LogStore.get().nextHttpId(); // v1.62 P1-10: 独立 httpId
                        line = "[REQ#" + hucRid + "]" + line;
                        HttpEntry he = new HttpEntry("URL_CONN", hucRid, System.currentTimeMillis(),
                                Thread.currentThread().getName(),
                                m, u == null ? "" : u.toString(),
                                new java.util.TreeMap<>(), "none", "", 0,
                                StackUtil.getCompact(), line);
                        // v1.59: URL_CONN 时间点（近似：响应已到，reqEnd≈respStart≈now）
                        long hucNow = System.currentTimeMillis();
                        he.setConnMeta("HTTP/1.1", hucNow, hucNow, 0, 0, "", 0, "", 0);
                        int status = 0;
                        try { status = ((Number) r).intValue(); } catch (Throwable ignored) { }
                        String msg = "";
                        try { msg = c.getResponseMessage(); } catch (Throwable ignored) { }
                        he.complete(status, msg, rspHdrs, "text", "", 0, 0);
                        HttpStore.get().add(he);
                    } catch (Throwable t) { }
                }
                return r;
            });
            DebugLog.get().logNoMirror("Net", "[" + phase + "] hooked HttpURLConnection.getResponseCode");
        } catch (Throwable t) {
            DebugLog.get().logNoMirror("Net", "[" + phase + "] HUC hook fail: " + t);
        }
    }

    // ================= TLS 明文抓包（v1.9，借鉴 AdClose）=================
    // ConscryptEngine.wrap(明文->密文) / unwrap(密文->明文)
    // wrap: src=明文请求（HTTP 头可见），dst=密文；unwrap: src=密文，dst=明文响应
    private void installTlsCapture(String phase) {
        try {
            Class<?> engine = Class.forName("com.android.org.conscrypt.ConscryptEngine", false, appCl);
            int hooked = 0;
            for (Method m : engine.getDeclaredMethods()) {
                if (!m.getName().equals("wrap") && !m.getName().equals("unwrap")) continue;
                if (m.getParameterTypes().length != 2) continue;
                module.hook(m).intercept(chain -> {
                    Object r = chain.proceed();
                    if (!Config.get().tlsCapture) return r;
                    try {
                        boolean isWrap = chain.getExecutable().getName().equals("wrap");
                        Object buf = chain.getArg(isWrap ? 0 : 1); // wrap 看 src(明文)，unwrap 看 dst(明文)
                        if (buf instanceof java.nio.ByteBuffer) {
                            java.nio.ByteBuffer bb = (java.nio.ByteBuffer) buf;
                            java.nio.ByteBuffer dup = bb.duplicate();
                            dup.rewind();
                            int n = dup.remaining();
                            if (n > 64) n = 64;
                            byte[] head = new byte[n];
                            dup.get(head);
                            String txt = new String(head, java.nio.charset.StandardCharsets.UTF_8);
                            // 只记录含 HTTP 特征/可读英文的明文段（防 TLS 1.3 帧噪音）
                            if (txt.contains("HTTP") || txt.matches("(?s)[A-Z]{3,8} /[^\r\n]*")) {
                                // v1.54 P0: ConscryptEngine.wrap/unwrap 抓的 TLS 明文与 v1.52
                                //   TlsHttpParser 结构化链路（REQ# 卡片）完全重复 → 日志页不再输出
                                //   [TLS>]/[TLS<] 文本行（v1.53 日志 112 行噪音），降级调试日志供排查
                                String line = txt.split("\r?\n")[0];
                                if (line.length() > 160) line = line.substring(0, 160) + "...";
                                DebugLog.get().logNoMirror("Net", "[TLS" + (isWrap ? ">]" : "<] ") + line);
                            }
                        }
                    } catch (Throwable t) { }
                    return r;
                });
                hooked++;
            }
            DebugLog.get().logNoMirror("Net", "[" + phase + "] hooked ConscryptEngine.wrap/unwrap x" + hooked);
        } catch (Throwable t) {
            DebugLog.get().logNoMirror("Net", "[" + phase + "] ConscryptEngine hook fail: " + t);
        }
    }

    // ================= 万能连接点：BlockGuardOs.connect（v1.9，借鉴 AdClose）=================
    // libcore.io.BlockGuardOs.connect(FileDescriptor, InetAddress, int)
    // 覆盖所有 native socket 连接（含 QUIC/HTTP3、自建 TCP、DNS over TCP 等）
    private void installConnectCapture(String phase) {
        try {
            Class<?> bgo = Class.forName("libcore.io.BlockGuardOs", false, appCl);
            Method connect = null;
            for (Method m : bgo.getDeclaredMethods()) {
                if (m.getName().equals("connect") && m.getParameterTypes().length == 3) {
                    connect = m;
                    break;
                }
            }
            if (connect == null) {
                DebugLog.get().logNoMirror("Net", "[" + phase + "] BlockGuardOs.connect not found");
                return;
            }
            final Method fConnect = connect;
            module.hook(connect).intercept(chain -> {
                Object r;
                try {
                    r = chain.proceed();
                } catch (Throwable t) {
                    if (Config.get().connectCapture) logConnectArgs(chain, true);
                    throw t;
                }
                if (Config.get().connectCapture) logConnectArgs(chain, false);
                return r;
            });
            DebugLog.get().logNoMirror("Net", "[" + phase + "] hooked BlockGuardOs.connect");
        } catch (Throwable t) {
            DebugLog.get().logNoMirror("Net", "[" + phase + "] BlockGuardOs.connect hook fail: " + t);
        }
    }

    private void logConnectArgs(io.github.libxposed.api.XposedInterface.Chain chain, boolean fail) {
        try {
            Object addr = chain.getArg(1);
            Object port = chain.getArg(2);
            if (addr instanceof java.net.InetAddress) {
                java.net.InetAddress ia = (java.net.InetAddress) addr;
                String ip = ia.getHostAddress();
                // v1.16 P1-4: 172.16-31 才是私网，172.0-15/172.32-255 是公网（此前跳过所有 172.x 误伤公网连接）
                if (ia.isLoopbackAddress() || ip.startsWith("10.") || ip.startsWith("192.168.")
                        || ip.startsWith("127.") || ip.startsWith("0.") || isPrivate172(ip)) return;
                int p = port instanceof Integer ? (Integer) port : -1;
                // v1.54 P1: 栈 12→6 帧（连接失败只需看到目标 App 发起方，系统样板帧无价值）
                String stack = StackUtil.getCompact(6);
                String msg = (fail ? "[TCP] FAIL " : "[TCP] ") + ip + ":" + p
                        + " <- " + stack;
                // v1.55: 结构化 Net 事件（底层 connect，带调用栈）
                logNetEvent("CONNECT", ip, ip, p, -1, !fail,
                        fail ? "connect fail" : "", msg);
            }
        } catch (Throwable t) { }
    }

    /** v1.16 P1-4: 172.16.0.0/12 私网判断（172.x 只有 16-31 段是私网） */
    private static boolean isPrivate172(String ip) {
        if (ip == null || !ip.startsWith("172.")) return false;
        int dot = ip.indexOf('.', 4);
        if (dot <= 4) return false;
        try {
            int second = Integer.parseInt(ip.substring(4, dot));
            return second >= 16 && second <= 31;
        } catch (Throwable t) {
            return false;
        }
    }

    // ================= Cronet 网络栈记录（v1.9，借鉴 AdClose）=================
    // 字节系 app（抖音系/头条系）用 Cronet，不走 OkHttp；
    // getResponse() 是 CronetHttpURLConnection 收响应主入口。
    private void installCronetCapture(String phase) {
        try {
            Class<?> cronet = Class.forName("com.ttnet.org.chromium.net.urlconnection.CronetHttpURLConnection", false, appCl);
            Method getResponse = null;
            for (Method m : cronet.getDeclaredMethods()) {
                if (m.getName().equals("getResponse") && m.getParameterTypes().length == 0) {
                    getResponse = m;
                    break;
                }
            }
            if (getResponse == null) {
                DebugLog.get().logNoMirror("Net", "[" + phase + "] CronetHttpURLConnection.getResponse not found");
                return;
            }
            final Method fGetResponse = getResponse;
            module.hook(getResponse).intercept(chain -> {
                Object r = chain.proceed();
                if (!Config.get().cronetCapture) return r;
                try {
                    Object self = chain.getThisObject();
                    if (self instanceof java.net.HttpURLConnection) {
                        java.net.HttpURLConnection c = (java.net.HttpURLConnection) self;
                        int code = c.getResponseCode();
                        String url = c.getURL() != null ? c.getURL().toString() : "?";
                        if (url.length() > 200) url = url.substring(0, 200) + "...";
                        // v1.58: Cronet 也结构化（此前纯文本，无 REQ# 卡片）
                        long rid = LogStore.get().nextHttpId(); // v1.62 P1-10: 独立 httpId（nextSeq 不消费并发撞 id）
                        String line = "[REQ#" + rid + "] <<< " + c.getRequestMethod() + " " + url + " -> " + code;
                        LogStore.get().log(TAG, line);
                        HttpEntry he = new HttpEntry("CRONET", rid, System.currentTimeMillis(),
                                Thread.currentThread().getName(),
                                c.getRequestMethod(), url,
                                new java.util.TreeMap<>(), "none", "", 0,
                                StackUtil.getCompact(), line);
                        // v1.59: CRONET 时间点（近似：响应已到，reqEnd≈respStart≈now）
                        long cronetNow = System.currentTimeMillis();
                        he.setConnMeta("HTTP/1.1", cronetNow, cronetNow, 0, 0, "", 0, "", 0);
                        he.complete(code, "", new java.util.TreeMap<>(), "text", "", 0, 0);
                        HttpStore.get().add(he);
                    }
                } catch (Throwable t) { }
                return r;
            });
            DebugLog.get().logNoMirror("Net", "[" + phase + "] hooked CronetHttpURLConnection.getResponse");
        } catch (Throwable t) {
            DebugLog.get().logNoMirror("Net", "[" + phase + "] Cronet hook fail: " + t);
        }
    }
}
