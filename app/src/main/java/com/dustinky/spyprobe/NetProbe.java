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

    /** 安装全部网络 hook */
    public void install(String phase) {
        installSslBypass(phase);
        installOkHttpCapture(phase);
        installUrlCapture(phase);
        installDnsCapture(phase);
        installSocketCapture(phase);
        installWebViewCapture(phase);
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
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] WebView.loadUrl hook fail: " + t);
        }
    }

    // ================= SSL 证书锁定绕过 =================
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
                return r;
            });
            LogStore.get().log(TAG, "[" + phase + "] hooked SSLContext.init");
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] SSLContext.init hook fail: " + t);
        }

        // 2. X509TrustManager.checkServerTrusted → 直接返回（信任所有证书）
        try {
            final Method cst = X509TrustManager.class.getMethod("checkServerTrusted",
                    X509Certificate[].class, String.class);
            module.hook(cst).intercept(chain -> {
                if (!Config.get().sslBypass) return chain.proceed();
                return null; // 不做校验
            });
            LogStore.get().log(TAG, "[" + phase + "] hooked X509TrustManager.checkServerTrusted");
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] X509TrustManager hook fail: " + t);
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
                    return null;
                });
                LogStore.get().log(TAG, "[" + phase + "] hooked CertificatePinner.check");
            } else {
                LogStore.get().log(TAG, "[" + phase + "] CertificatePinner.check not found");
            }
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] CertificatePinner hook fail: " + t);
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

    // ================= DNS 解析记录（v1.2）=================
    private void installDnsCapture(String phase) {
        // getAllByName(String) 是域名解析主入口（getByName 内部也走它）
        try {
            final Method gab = InetAddress.class.getMethod("getAllByName", String.class);
            module.hook(gab).intercept(chain -> {
                Object r = chain.proceed();
                if (Config.get().dnsCapture) {
                    try {
                        Object host = chain.getArg(0);
                        if (host != null && r instanceof InetAddress[]) {
                            InetAddress[] addrs = (InetAddress[]) r;
                            StringBuilder sb = new StringBuilder("[DNS] ").append(host).append(" -> [");
                            for (int i = 0; i < addrs.length; i++) {
                                if (i > 0) sb.append(", ");
                                sb.append(addrs[i].getHostAddress());
                            }
                            sb.append("]");
                            LogStore.get().log(TAG, sb.toString());
                        }
                    } catch (Throwable t) { }
                }
                return r;
            });
            LogStore.get().log(TAG, "[" + phase + "] hooked InetAddress.getAllByName");
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] DNS hook fail: " + t);
        }
        // 解析失败路径也记录（getAllByName 抛 UnknownHostException）
        try {
            final Method gab = InetAddress.class.getMethod("getAllByName", String.class);
            module.hook(gab).intercept(chain -> {
                try {
                    return chain.proceed();
                } catch (Throwable t) {
                    if (Config.get().dnsCapture) {
                        Object host = chain.getArg(0);
                        LogStore.get().log(TAG, "[DNS] FAIL " + host + " : " + t);
                    }
                    throw t;
                }
            });
            LogStore.get().log(TAG, "[" + phase + "] hooked InetAddress.getAllByName (fail-path)");
        } catch (Throwable t) { }
    }

    // ================= Socket 连接记录（v1.2）=================
    private void installSocketCapture(String phase) {
        try {
            final Method connect = java.net.Socket.class.getMethod("connect", java.net.SocketAddress.class);
            module.hook(connect).intercept(chain -> {
                Object r = chain.proceed();
                logSocket(chain.getArg(0), -1);
                return r;
            });
            LogStore.get().log(TAG, "[" + phase + "] hooked Socket.connect(SocketAddress)");
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] Socket.connect(SocketAddress) hook fail: " + t);
        }
        try {
            final Method connect = java.net.Socket.class.getMethod("connect", java.net.SocketAddress.class, int.class);
            module.hook(connect).intercept(chain -> {
                Object r = chain.proceed();
                Object to = chain.getArg(1);
                logSocket(chain.getArg(0), to instanceof Integer ? (Integer) to : -1);
                return r;
            });
            LogStore.get().log(TAG, "[" + phase + "] hooked Socket.connect(SocketAddress,int)");
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] Socket.connect(SocketAddress,int) hook fail: " + t);
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

    // ================= OkHttp 抓包 =================
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
                    // method/url 需在 try 外可见（失败留痕也要用）
                    Object method = null;
                    Object url = null;
                    try {
                        Method urlM = req.getClass().getMethod("url");
                        Method methodM = req.getClass().getMethod("method");
                        Method headersM = req.getClass().getMethod("headers");
                        url = urlM.invoke(req);
                        method = methodM.invoke(req);
                        Object headers = headersM.invoke(req);
                        StringBuilder sb = new StringBuilder();
                        sb.append(">>> ").append(method).append(" ").append(url);
                        if (headers != null) {
                            // okhttp Headers.toString() 格式 "Key: value\n..."
                            sb.append("\n    ").append(headers.toString().replace("\n", "\n    "));
                        }
                        // P1: 记录请求体（RequestBody.buffer()，one-shot body 会抛异常，catch）
                        try {
                            Method bodyM = req.getClass().getMethod("body");
                            Object body = bodyM.invoke(req);
                            if (body != null) {
                                Method bufferM = body.getClass().getMethod("buffer");
                                Object buffer = bufferM.invoke(body);
                                if (buffer != null) {
                                    Method utf8M = buffer.getClass().getMethod("utf8");
                                    Object bstr = utf8M.invoke(buffer);
                                    if (bstr != null) {
                                        String bs = bstr.toString();
                                        if (bs.length() > Config.get().bodyLimit) {
                                            bs = bs.substring(0, Config.get().bodyLimit) + "...(" + bs.length() + "B)";
                                        }
                                        sb.append("\n    reqBody: ").append(bs.replace("\n", "\n    "));
                                    }
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
                        LogStore.get().log(TAG, "[OkHttp] !!! REQUEST FAILED: " + method + " " + url + " -> " + t);
                        throw t;
                    }
                    try {
                        int limit = Math.max(256, Config.get().bodyLimit);
                        // okhttp Response.peekBody(long) 不消费原流
                        Method peek = resp.getClass().getMethod("peekBody", long.class);
                        Object body = peek.invoke(resp, (long) limit);
                        Method codeM = resp.getClass().getMethod("code");
                        Method msgM = resp.getClass().getMethod("message");
                        Method headersM = resp.getClass().getMethod("headers");
                        Object code = codeM.invoke(resp);
                        Object msg = msgM.invoke(resp);
                        Object respHeaders = headersM.invoke(resp);
                        Object bodyStr = body != null ? body.getClass().getMethod("string").invoke(body) : "";
                        String b = bodyStr == null ? "" : bodyStr.toString();
                        if (b.length() > limit) b = b.substring(0, limit) + "...(" + b.length() + "B)";
                        StringBuilder sb = new StringBuilder();
                        sb.append("<<< ").append(code).append(" ").append(msg);
                        if (respHeaders != null) {
                            // v1.2: 响应头（Set-Cookie / Content-Type / 长度）
                            sb.append("\n    ").append(respHeaders.toString().replace("\n", "\n    "));
                        }
                        sb.append("\n    body(").append(bodyStr == null ? 0 : bodyStr.toString().length()).append("B): ")
                          .append(b.replace("\n", "\n    "));
                        LogStore.get().log(TAG, sb.toString());
                    } catch (Throwable t) {
                        LogStore.get().log(TAG, "[OkHttp] resp parse fail: " + t);
                    }
                    return resp;
                });
                LogStore.get().log(TAG, "[" + phase + "] hooked " + cn + ".proceed");
                hooked = true;
                break;
            } catch (Throwable t) {
                LogStore.get().log(TAG, "[" + phase + "] " + cn + " hook fail: " + t);
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
            } catch (Throwable t) {
                LogStore.get().log(TAG, "[" + phase + "] okhttp hook all fail: " + t);
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
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] HUC hook fail: " + t);
        }
    }
}
