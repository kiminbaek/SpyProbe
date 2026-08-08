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
        // v1.9: TLS 明文抓包 + 万能连接点 + Cronet
        installTlsCapture(phase);
        installConnectCapture(phase);
        installCronetCapture(phase);
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
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] DNS hook fail: " + t);
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
                    // method/url 需在 try 外可见（失败留痕也要用）
                    Object method = null;
                    Object url = null;
                    try {
                        ensureReqMethods(req);
                        url = sReqUrl.invoke(req);
                        method = sReqMethod.invoke(req);
                        Object headers = sReqHeaders.invoke(req);
                        StringBuilder sb = new StringBuilder();
                        sb.append(">>> ").append(method).append(" ").append(url);
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
                                            if (bs.length() > Config.get().bodyLimit) {
                                                bs = bs.substring(0, Config.get().bodyLimit) + "...(" + bs.length() + "B)";
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
                        LogStore.get().log(TAG, "[OkHttp] !!! REQUEST FAILED: " + method + " " + url + " -> " + t);
                        throw t;
                    }
                    try {
                        int limit = Math.max(256, Config.get().bodyLimit);
                        ensureRespMethods(resp);
                        // okhttp Response.peekBody(long) 不消费原流
                        Object body = sRespPeek.invoke(resp, (long) limit);
                        Object code = sRespCode.invoke(resp);
                        Object msg = sRespMsg.invoke(resp);
                        Object respHeaders = sRespHeaders.invoke(resp);
                        Object bodyStr = body != null ? sRespBodyString.invoke(body) : "";
                        // v1.8: toString() 只调一次（每次调用都重新 UTF-8 解码，大 body 重复解码浪费）
                        String b = bodyStr == null ? "" : bodyStr.toString();
                        if (b.length() > limit) b = b.substring(0, limit) + "...(" + b.length() + "B)";
                        StringBuilder sb = new StringBuilder();
                        sb.append("<<< ").append(code).append(" ").append(msg);
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
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] ConscryptEngine hook fail: " + t);
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
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] BlockGuardOs.connect hook fail: " + t);
        }
    }

    private void logConnectArgs(io.github.libxposed.api.XposedInterface.Chain chain, boolean fail) {
        try {
            Object addr = chain.getArg(1);
            Object port = chain.getArg(2);
            if (addr instanceof java.net.InetAddress) {
                java.net.InetAddress ia = (java.net.InetAddress) addr;
                String ip = ia.getHostAddress();
                // 跳过回环/本地（噪音）
                if (ia.isLoopbackAddress() || ip.startsWith("10.") || ip.startsWith("192.168.")
                        || ip.startsWith("172.") || ip.startsWith("127.") || ip.startsWith("0.")) return;
                int p = port instanceof Integer ? (Integer) port : -1;
                LogStore.get().log(TAG, (fail ? "[TCP] FAIL " : "[TCP] ") + ip + ":" + p
                        + " <- " + StackUtil.getCompact());
            }
        } catch (Throwable t) { }
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
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] Cronet hook fail: " + t);
        }
    }
}
