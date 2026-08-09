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

    public NetProbe(XposedModule module, ClassLoader appCl) {
        this.module = module;
        this.appCl = appCl;
    }

    /** 安装全部网络 hook
     *  v1.37 P0-1: 惰性安装（借鉴 Guise activeHookFeatures）——按 Config 开关只装用户启用的项，
     *   关闭的探测项在目标进程零 hook 存在（减少崩溃面 + 更隐蔽 + 启动更快）。
     *   注意：early 阶段 Config 尚未从主进程拉取，走默认值（全开）；late 阶段（配置加载后）
     *   若某项被用户关闭，这里跳过不装。 */
    public void install(String phase) {
        DebugLog.get().log("Net", "install(" + phase + ") 开始");
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
        DebugLog.get().log("Net", "install(" + phase + ") 完成");
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
                        LogStore.get().log(TAG, "[WebView] loadUrl: " + url);
                    }
                }
                return r;
            });
            LogStore.get().log(TAG, "[" + phase + "] hooked WebView.loadUrl");
            DebugLog.get().log("Net", "[" + phase + "] hooked WebView.loadUrl");
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] WebView.loadUrl hook fail: " + t);
            DebugLog.get().log("Net", "[" + phase + "] WebView.loadUrl hook fail: " + t);
        }
    }

    // ================= SSL 证书锁定绕过 =================
    // v1.39 P2: pinning 触发定位——证书校验点被命中时标记"哪种 pinning + 调用方栈"。
    //   一看日志就知道 App 用哪种证书锁定（network_security_config / okhttp pinner / Cronet / 老库…）
    private void pinningHit(int idx, String desc) {
        try {
            LogStore.get().log(TAG, "[Pinning#" + idx + "] " + desc + " | caller: " + StackUtil.getCompact());
        } catch (Throwable ignored) { }
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
                LogStore.get().log(TAG, "[SSL] SSLContext.init bypassed");
                // v1.39 P2: 标准 TLS 握手入口（每次 TLS 连接都会命中）
                pinningHit(1, "SSLContext.init (标准 TLS 握手入口)");
                return r;
            });
            LogStore.get().log(TAG, "[" + phase + "] hooked SSLContext.init");
            DebugLog.get().log("Net", "[" + phase + "] hooked SSLContext.init");
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] SSLContext.init hook fail: " + t);
            DebugLog.get().log("Net", "[" + phase + "] SSLContext.init hook fail: " + t);
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
            LogStore.get().log(TAG, "[" + phase + "] hooked X509TrustManager.checkServerTrusted");
            DebugLog.get().log("Net", "[" + phase + "] hooked X509TrustManager.checkServerTrusted");
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] X509TrustManager hook fail: " + t);
            DebugLog.get().log("Net", "[" + phase + "] X509TrustManager hook fail: " + t);
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
                LogStore.get().log(TAG, "[" + phase + "] hooked CertificatePinner.check");
                DebugLog.get().log("Net", "[" + phase + "] hooked CertificatePinner.check");
            } else {
                LogStore.get().log(TAG, "[" + phase + "] CertificatePinner.check not found");
                DebugLog.get().log("Net", "[" + phase + "] CertificatePinner.check not found");
            }
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] CertificatePinner hook fail: " + t);
            DebugLog.get().log("Net", "[" + phase + "] CertificatePinner hook fail: " + t);
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
            LogStore.get().log(TAG, "[" + phase + "] hooked NetworkSecurityTrustManager.checkPins");
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
            LogStore.get().log(TAG, "[" + phase + "] hooked TrustManagerImpl.checkServerTrusted x3");
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
            LogStore.get().log(TAG, "[" + phase + "] hooked TrustManagerImpl.checkTrusted(+Recursive)");
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
            LogStore.get().log(TAG, "[" + phase + "] hooked X509TrustManagerExtensions.checkServerTrusted");
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
            if (ok > 0) LogStore.get().log(TAG, "[" + phase + "] hooked OkHostnameVerifier.verify");
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
            LogStore.get().log(TAG, "[" + phase + "] hooked squareup OkHttpClient.setCertificatePinner");
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
            LogStore.get().log(TAG, "[" + phase + "] hooked AbstractVerifier.verify");
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
            LogStore.get().log(TAG, "[" + phase + "] hooked WebViewClient.onReceivedSslError (proceed)");
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
        LogStore.get().log(TAG, "[" + phase + "] SSL bypass ext: " + ok + " hook points installed");

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
                LogStore.get().log(TAG, "[" + phase + "] hooked Platform.checkServerTrusted x" + n);
            }
        } catch (Throwable t) { }

        LogStore.get().log(TAG, "[" + phase + "] SSL bypass ext total: " + ok + " (含子点，部分 ROM 无对应类属正常)");
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
                                        LogStore.get().log(TAG, "[WebView] setWebContentsDebuggingEnabled(true) 已开启");
                                    }
                                } catch (Throwable t) { }
                            }
                        }
                        return r;
                    });
                } catch (Throwable t) { }
            }
            LogStore.get().log(TAG, "[" + phase + "] hooked WebView.<init> (debug enabled)");
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] WebView debug hook fail: " + t);
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
                        LogStore.get().log(TAG, sb.toString());
                    }
                    return r;
                } catch (Throwable t) {
                    if (Config.get().dnsCapture) {
                        LogStore.get().log(TAG, "[DNS] FAIL " + host + " : " + t);
                    }
                    throw t;
                }
            });
            LogStore.get().log(TAG, "[" + phase + "] hooked InetAddress.getAllByName");
            DebugLog.get().log("Net", "[" + phase + "] hooked InetAddress.getAllByName");
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] DNS hook fail: " + t);
            DebugLog.get().log("Net", "[" + phase + "] DNS hook fail: " + t);
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
            LogStore.get().log(TAG, "[" + phase + "] hooked Socket.connect(SocketAddress,int)");
            DebugLog.get().log("Net", "[" + phase + "] hooked Socket.connect(SocketAddress,int)");
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] Socket.connect(SocketAddress,int) hook fail: " + t);
            DebugLog.get().log("Net", "[" + phase + "] Socket.connect(SocketAddress,int) hook fail: " + t);
        }
    }

    private void logSocket(Object addr, int timeout) {
        if (!Config.get().tcpCapture) return;
        try {
            java.net.InetSocketAddress isa = (java.net.InetSocketAddress) addr;
            String host = isa.getHostString();
            String ip = isa.getAddress() != null ? isa.getAddress().getHostAddress() : "?";
            LogStore.get().log(TAG, "[TCP] " + host + " (" + ip + "):" + isa.getPort()
                    + (timeout > 0 ? " timeout=" + timeout : ""));
        } catch (Throwable t) { }
    }

    /** v1.6: Socket 连接失败留痕（域名/端口 + 错误） */
    private void logSocketFail(Object addr, int timeout, Throwable err) {
        if (!Config.get().tcpCapture) return;
        try {
            java.net.InetSocketAddress isa = (java.net.InetSocketAddress) addr;
            String host = isa.getHostString();
            String ip = isa.getAddress() != null ? isa.getAddress().getHostAddress() : "?";
            LogStore.get().log(TAG, "[TCP] FAIL " + host + " (" + ip + "):" + isa.getPort()
                    + (timeout > 0 ? " timeout=" + timeout : "") + " -> " + err);
        } catch (Throwable t) { }
    }

    // ================= OkHttp 抓包 =================
    // v1.6: 反射缓存（每次请求 10+ 次 getMethod → 首次解析后复用）
    private static Method sReqUrl, sReqMethod, sReqHeaders, sReqBody;
    private static Method sBodyBuffer, sBodyContentLength;
    private static Method sBufferUtf8;
    private static Method sRespPeek, sRespCode, sRespMsg, sRespHeaders, sRespBodyString;
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
                    long rid = LogStore.get().nextSeq();
                    // method/url 需在 try 外可见（失败留痕也要用）
                    Object method = null;
                    Object url = null;
                    try {
                        ensureReqMethods(req);
                        url = sReqUrl.invoke(req);
                        method = sReqMethod.invoke(req);
                        Object headers = sReqHeaders.invoke(req);
                        StringBuilder sb = new StringBuilder();
                        sb.append("[REQ#").append(rid).append("] >>> ").append(method).append(" ").append(url);
                        if (headers != null) {
                            // okhttp Headers.toString() 格式 "Key: value\n..."
                            sb.append("\n    ").append(headers.toString().replace("\n", "\n    "));
                        }
                        // P0-2(v1.6): 记录请求体前先查 contentLength()，超大 body 不 buffer（防 OOM）
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
                                            sb.append("\n    reqBody: ").append(bs.replace("\n", "\n    "));
                                        }
                                    }
                                } else if (clen > MAX_REQ_BODY) {
                                    sb.append("\n    reqBody: <skipped ").append(clen).append("B, too large>");
                                }
                            }
                        } catch (Throwable t) { /* one-shot body 忽略 */ }
                        LogStore.get().log(TAG, sb.toString());
                    } catch (Throwable t) {
                        LogStore.get().log(TAG, "[OkHttp] req parse fail: " + t);
                    }
                    Object resp;
                    try {
                        resp = chainParam.proceed();
                    } catch (Throwable t) {
                        // v1.2: 失败请求留痕（连接失败/超时/协议错误），rethrow 保持原行为
                        // v1.35 P1-3: 失败行带关联 ID
                        LogStore.get().log(TAG, "[REQ#" + rid + "] !!! REQUEST FAILED: " + method + " " + url + " -> " + t);
                        throw t;
                    }
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
                        if (respHeaders != null) {
                            // v1.2: 响应头（Set-Cookie / Content-Type / 长度）
                            sb.append("\n    ").append(respHeaders.toString().replace("\n", "\n    "));
                        }
                        sb.append("\n    body(").append(b.length()).append("B): ")
                          .append(b.replace("\n", "\n    "));
                        LogStore.get().log(TAG, sb.toString());
                    } catch (Throwable t) {
                        LogStore.get().log(TAG, "[OkHttp] resp parse fail: " + t);
                    }
                    return resp;
                });
                LogStore.get().log(TAG, "[" + phase + "] hooked " + cn + ".proceed");
                DebugLog.get().log("Net", "[" + phase + "] hooked " + cn + ".proceed");
                hooked = true;
                break;
            } catch (Throwable t) {
                LogStore.get().log(TAG, "[" + phase + "] " + cn + " hook fail: " + t);
                DebugLog.get().log("Net", "[" + phase + "] " + cn + " hook fail: " + t);
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
                            LogStore.get().log(TAG, "[RealCall] <<< " + code + " " + url);
                        } catch (Throwable t) { }
                    }
                    return r;
                });
                LogStore.get().log(TAG, "[" + phase + "] hooked okhttp3.RealCall.execute (fallback)");
                DebugLog.get().log("Net", "[" + phase + "] hooked okhttp3.RealCall.execute (fallback)");
            } catch (Throwable t) {
                LogStore.get().log(TAG, "[" + phase + "] okhttp hook all fail: " + t);
                DebugLog.get().log("Net", "[" + phase + "] okhttp hook all fail: " + t);
            }
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
                        try {
                            Map<String, List<String>> hf = c.getHeaderFields();
                            if (hf != null) {
                                String cl = c.getHeaderField("Content-Length");
                                String ct = c.getHeaderField("Content-Type");
                                hd.append(" Content-Length=").append(cl == null ? "?" : cl)
                                  .append(" Content-Type=").append(ct == null ? "?" : ct);
                            }
                        } catch (Throwable t) { }
                        LogStore.get().log(TAG, "[HUC] " + m + " " + u + " -> " + r + hd);
                    } catch (Throwable t) { }
                }
                return r;
            });
            LogStore.get().log(TAG, "[" + phase + "] hooked HttpURLConnection.getResponseCode");
            DebugLog.get().log("Net", "[" + phase + "] hooked HttpURLConnection.getResponseCode");
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] HUC hook fail: " + t);
            DebugLog.get().log("Net", "[" + phase + "] HUC hook fail: " + t);
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
                                String line = txt.split("\r?\n")[0];
                                if (line.length() > 160) line = line.substring(0, 160) + "...";
                                LogStore.get().log(TAG, "[TLS" + (isWrap ? ">]" : "<] ") + line);
                            }
                        }
                    } catch (Throwable t) { }
                    return r;
                });
                hooked++;
            }
            LogStore.get().log(TAG, "[" + phase + "] hooked ConscryptEngine.wrap/unwrap x" + hooked);
            DebugLog.get().log("Net", "[" + phase + "] hooked ConscryptEngine.wrap/unwrap x" + hooked);
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] ConscryptEngine hook fail: " + t);
            DebugLog.get().log("Net", "[" + phase + "] ConscryptEngine hook fail: " + t);
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
                LogStore.get().log(TAG, "[" + phase + "] BlockGuardOs.connect not found");
                DebugLog.get().log("Net", "[" + phase + "] BlockGuardOs.connect not found");
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
            LogStore.get().log(TAG, "[" + phase + "] hooked BlockGuardOs.connect");
            DebugLog.get().log("Net", "[" + phase + "] hooked BlockGuardOs.connect");
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] BlockGuardOs.connect hook fail: " + t);
            DebugLog.get().log("Net", "[" + phase + "] BlockGuardOs.connect hook fail: " + t);
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
                LogStore.get().log(TAG, (fail ? "[TCP] FAIL " : "[TCP] ") + ip + ":" + p
                        + " <- " + StackUtil.getCompact());
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
                LogStore.get().log(TAG, "[" + phase + "] CronetHttpURLConnection.getResponse not found");
                DebugLog.get().log("Net", "[" + phase + "] CronetHttpURLConnection.getResponse not found");
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
                        LogStore.get().log(TAG, "[Cronet] " + c.getRequestMethod() + " " + url + " -> " + code);
                    }
                } catch (Throwable t) { }
                return r;
            });
            LogStore.get().log(TAG, "[" + phase + "] hooked CronetHttpURLConnection.getResponse");
            DebugLog.get().log("Net", "[" + phase + "] hooked CronetHttpURLConnection.getResponse");
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] Cronet hook fail: " + t);
            DebugLog.get().log("Net", "[" + phase + "] Cronet hook fail: " + t);
        }
    }
}
