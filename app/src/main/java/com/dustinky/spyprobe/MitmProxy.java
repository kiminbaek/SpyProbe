package com.dustinky.spyprobe;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * v7x: 本地 MITM 代理（主进程 127.0.0.1:8888）
 *
 * 流程（CONNECT 代理模式，M1）：
 *   1. 目标 App 流量被 iptables REDIRECT 到本端口（或走 CONNECT 代理）
 *   2. 解析首行 CONNECT host:port（代理模式）/ SO_ORIGINAL_DST（透明模式，M2）
 *   3. 与真实服务器建立 TLS 连接（信任系统 CA）
 *   4. 用 MitmCertManager 的 per-host 证书把已有 app TCP 连接升级为 TLS server 端
 *   5. 双向转发：app 明文流 → 目标加密流；目标明文流 → app 加密流
 *   6. 明文两侧都回调 PlainListener（喂 TlsHttpParser → HttpEntry → HttpStore）
 *
 * 关键：
 *   - ALPN 只提供 http/1.1 → 客户端降级 HTTP/1.1 明文 → TlsHttpParser 直接可解析
 *   - 纯 Java + 不依赖 Android API（NAS 可编译冒烟）；日志走 LogSink
 */
public class MitmProxy {

    public static final String TAG = "SpyProbe.MitmProxy";

    /** connId=连接序号；dir: 0=app→target(请求) 1=target→app(响应) */
    public interface PlainListener {
        void onPlain(int connId, int dir, String host, byte[] data, int len);

        /** 连接关闭（顺带 flush 解析器收尾） */
        default void onClosed(int connId) {}
    }

    private final MitmCertManager certManager;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicInteger connSeq = new AtomicInteger();
    private ServerSocket serverSocket;
    private ExecutorService acceptPool;
    private ExecutorService connPool;
    private PlainListener listener;
    private volatile boolean transparent;

    public MitmProxy(MitmCertManager certManager) {
        this.certManager = certManager;
    }

    /** 启动代理。transparent=true 走 iptables REDIRECT 透明模式（无 CONNECT 头）。返回实际绑定端口，失败抛异常。 */
    public synchronized int start(int port, PlainListener listener, boolean transparent) throws Exception {
        if (running.get()) throw new IllegalStateException("already running");
        if (!certManager.ensureCa()) throw new IllegalStateException("CA init failed");
        this.listener = listener;
        this.transparent = transparent;
        serverSocket = new ServerSocket();
        serverSocket.setReuseAddress(true);
        serverSocket.bind(new InetSocketAddress("127.0.0.1", port));
        int bound = serverSocket.getLocalPort();
        running.set(true);
        acceptPool = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "mitm-accept");
            t.setDaemon(true);
            return t;
        });
        connPool = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "mitm-conn");
            t.setDaemon(true);
            return t;
        });
        acceptPool.execute(this::acceptLoop);
        MitmLog.log("MitmProxy started on 127.0.0.1:" + bound + " transparent=" + transparent);
        return bound;
    }

    /** 兼容：CONNECT 代理模式（M1 冒烟用） */
    public synchronized int start(int port, PlainListener listener) throws Exception {
        return start(port, listener, false);
    }

    public synchronized void stop() {
        running.set(false);
        try { if (serverSocket != null) serverSocket.close(); } catch (IOException ignored) {}
        if (acceptPool != null) acceptPool.shutdownNow();
        if (connPool != null) connPool.shutdownNow();
        MitmLog.log("MitmProxy stopped");
    }

    public boolean isRunning() {
        return running.get();
    }

    public int activeConnections() {
        return connSeq.get();
    }

    private void acceptLoop() {
        while (running.get()) {
            try {
                Socket s = serverSocket.accept();
                int seq = connSeq.incrementAndGet();
                connPool.execute(() -> handleConnection(s, seq, transparent));
            } catch (IOException e) {
                if (running.get()) MitmLog.log("accept err: " + e);
            }
        }
    }

    // ===== 单连接处理 =====

    private void handleConnection(Socket appSocket, int seq, boolean transparent) {
        String host = null;
        SSLSocket appSsl = null;
        SSLSocket targetSsl = null;
        try {
            appSocket.setSoTimeout(60000);
            InputStream appInRaw = appSocket.getInputStream();
            OutputStream appOutRaw = appSocket.getOutputStream();

            // 1. 目标解析（透明模式 vs CONNECT 代理）
            String hostname = null;
            int targetPort = 443;
            String connectIp = null; // 透明模式 SO_ORIGINAL_DST 的真实目标 IP（IPv4）
            byte[] consumed = null;  // 透明模式已读的 ClientHello（回喂 SSL socket）

            if (transparent) {
                // 透明模式：无 CONNECT 头，直接 ClientHello。真实目标 = SO_ORIGINAL_DST，证书域名 = SNI
                String origDst = null;
                int fd = FdUtil.getFd(appSocket);
                if (fd > 0) {
                    try { origDst = MitmSock.getOriginalDst(fd); }
                    catch (Throwable t) { /* 无 native_hook（NAS 冒烟）→ null */ }
                }
                if (origDst != null) {
                    int c = origDst.lastIndexOf(':');
                    if (c > 0) { connectIp = origDst.substring(0, c); targetPort = Integer.parseInt(origDst.substring(c + 1)); }
                }
                TlsSniffer.Result sr = TlsSniffer.sniff(appInRaw);
                if (sr == null) { MitmLog.log("[" + seq + "] transparent: no ClientHello"); return; }
                consumed = sr.consumed;
                hostname = sr.sni != null ? sr.sni : connectIp;
                if (hostname == null) { MitmLog.log("[" + seq + "] transparent: no SNI no origDst"); return; }
                host = hostname;
                MitmLog.log("[" + seq + "] TRANSPARENT host=" + hostname + ":" + targetPort + " orig=" + origDst);
            } else {
                // CONNECT 代理模式
                String connectLine = readLine(appInRaw);
                if (connectLine == null || !connectLine.startsWith("CONNECT ")) {
                    MitmLog.log("[" + seq + "] non-CONNECT: " + connectLine);
                    return;
                }
                String[] parts = connectLine.split(" ");
                String hostPort = parts.length > 1 ? parts[1] : null;
                if (hostPort == null) { writeRaw(appOutRaw, "HTTP/1.1 400 Bad Request\r\n\r\n"); return; }
                host = hostPort;
                int colon = hostPort.lastIndexOf(':');
                if (colon > 0) {
                    hostname = hostPort.substring(0, colon);
                    targetPort = Integer.parseInt(hostPort.substring(colon + 1));
                } else {
                    hostname = hostPort;
                    targetPort = 443;
                }
                MitmLog.log("[" + seq + "] CONNECT " + hostname + ":" + targetPort);

                // 消费 CONNECT 剩余请求头（Host/User-Agent...直到空行），否则残留字节会污染 TLS 握手
                String hdr;
                while ((hdr = readLine(appInRaw)) != null && !hdr.isEmpty()) {
                    // ignore
                }
                // 立即回复 200（客户端收到后才发 ClientHello，否则双方互等/错读）
                writeRaw(appOutRaw, "HTTP/1.1 200 Connection established\r\n\r\n");
            }

            // 2. 真实 TLS 连接（信任系统 CA）
            SSLSocketFactory clientFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            targetSsl = (SSLSocket) clientFactory.createSocket();
            if (transparent && connectIp != null) {
                // 透明模式：优先用 SO_ORIGINAL_DST 的真实 IP（避免重 DNS / 走原连接目标）
                targetSsl.connect(new InetSocketAddress(InetAddress.getByName(connectIp), targetPort), 15000);
            } else {
                targetSsl.connect(new InetSocketAddress(hostname, targetPort), 15000);
            }
            targetSsl.setSoTimeout(60000);
            SSLParameters clientParams = targetSsl.getSSLParameters();
            // 与真实服务器协商，允许 h2/http1.1（服务器决定）
            clientParams.setApplicationProtocols(new String[]{"h2", "http/1.1"});
            targetSsl.setSSLParameters(clientParams);
            targetSsl.startHandshake();

            // 5. 本地 TLS server 端（per-host 证书）
            //    将已有 app TCP socket 包装升级为 TLS server（SSLSocketFactory.createSocket 后切 server 模式）
            SSLContext ctx = buildServerContext(hostname);
            SSLSocketFactory serverFactory = ctx.getSocketFactory();
            // 注：Android SDK 的 SSLSocketFactory 方法面没有 createSocket(Socket, InputStream, boolean)，
            // 但运行时实现（Conscrypt/JDK）都有——反射调用，编译期不引用该签名，NAS 冒烟与 Android 都能跑。
            // v1.74.7 P0-10: Android 16 默认 JSSE 的 3 参实现抛 UnsupportedOperationException
            //   → 先试 3 参反射（Conscrypt AndroidOpenSSL），InvocationTargetException 时
            //   fallback Conscrypt 静态 API newFileDescriptorSocket（支持 consumed 回喂）。
            InputStream consumedIn = consumed != null ? new ByteArrayInputStream(consumed) : null;
            try {
                java.lang.reflect.Method upM = SSLSocketFactory.class.getMethod(
                        "createSocket", Socket.class, InputStream.class, boolean.class);
                appSsl = (SSLSocket) upM.invoke(serverFactory, appSocket, consumedIn, true);
            } catch (java.lang.reflect.InvocationTargetException ite) {
                Throwable cause = ite.getCause();
                // 3 参反射失败（UnsupportedOperationException 等）→ Conscrypt 静态 API 兜底
                if (cause != null && cause instanceof UnsupportedOperationException) {
                    try {
                        java.lang.reflect.Method newFd = Class.forName("org.conscrypt.Conscrypt")
                                .getMethod("newFileDescriptorSocket", SSLContext.class,
                                        Socket.class, InputStream.class, boolean.class);
                        appSsl = (SSLSocket) newFd.invoke(null, ctx, appSocket, consumedIn, true);
                        MitmLog.log("[" + seq + "] TLS upgrade via Conscrypt.newFileDescriptorSocket");
                    } catch (Throwable t2) {
                        throw new IOException("upgrade createSocket(consumed) unsupported", cause);
                    }
                } else {
                    throw cause instanceof Exception ? (Exception) cause : new IOException(cause);
                }
            } catch (NoSuchMethodException | IllegalAccessException nsme) {
                // 极端兜底：4 参版本（Android SDK 必有），但无法回喂 consumed——
                // 仅 CONNECT 模式（consumed==null）可用；透明模式直接失败留痕
                if (consumed != null) throw new IOException("upgrade createSocket(consumed) unsupported");
                appSsl = (SSLSocket) serverFactory.createSocket(appSocket, hostname, targetPort, true);
            }
            appSsl.setUseClientMode(false);
            SSLParameters serverParams = appSsl.getSSLParameters();
            // 关键：只提供 http/1.1 → 客户端降级 → 明文 HTTP/1.1 可被 TlsHttpParser 解析
            serverParams.setApplicationProtocols(new String[]{"http/1.1"});
            appSsl.setSSLParameters(serverParams);
            try { MitmLog.log("[" + seq + "] pre-handshake avail=" + appInRaw.available()); } catch (Throwable ignored) {}
            appSsl.startHandshake();

            String alpn = appSsl.getApplicationProtocol();
            MitmLog.log("[" + seq + "] TLS up host=" + hostname + " alpn=" + alpn);

            // 6. 双向转发
            InputStream appIn = appSsl.getInputStream();
            OutputStream appOut = appSsl.getOutputStream();
            InputStream targetIn = targetSsl.getInputStream();
            OutputStream targetOut = targetSsl.getOutputStream();

            Thread t1 = pump(appIn, targetOut, seq, 0, hostname, "req");
            Thread t2 = pump(targetIn, appOut, seq, 1, hostname, "resp");
            t1.join();
            t2.join();
        } catch (Throwable t) {
            StringBuilder sb = new StringBuilder();
            sb.append("[" + seq + "] conn err: ").append(t).append("\n");
            for (StackTraceElement el : t.getStackTrace()) {
                if (sb.length() < 2000) sb.append("    at ").append(el).append("\n");
            }
            MitmLog.log(sb.toString());
        } finally {
            closeQuietly(appSsl);
            closeQuietly(targetSsl);
            connSeq.decrementAndGet();
            if (listener != null) {
                try { listener.onClosed(seq); } catch (Throwable ignored) {}
            }
            MitmLog.log("[" + seq + "] closed host=" + host);
        }
    }

    /** 单向泵：读 in → 写 out + 回调 PlainListener */
    private Thread pump(InputStream in, OutputStream out, int connId, int dir, String host, String name) {
        Thread t = new Thread(() -> {
            byte[] buf = new byte[32 * 1024];
            try {
                int n;
                while (running.get() && (n = in.read(buf)) > 0) {
                    if (listener != null) {
                        try { listener.onPlain(connId, dir, host, buf, n); }
                        catch (Throwable ignored) {}
                    }
                    out.write(buf, 0, n);
                    out.flush();
                }
            } catch (IOException ignored) {
                // 对端关闭
            } catch (Throwable t2) {
                MitmLog.log("pump " + name + " err: " + t2);
            }
        }, "mitm-pump-" + name);
        t.setDaemon(true);
        t.start();
        return t;
    }

    private SSLContext buildServerContext(String host) throws Exception {
        KeyStore ks = certManager.hostKeyStore(host);
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "spyprobe".toCharArray());
        // v1.74.7 P0-10: 显式用 Conscrypt（AndroidOpenSSL）——真机 Android 16 上默认
        //   SSLContext.getInstance("TLS") 返回的 JSSE 实现不支持 3 参
        //   createSocket(Socket, InputStream, boolean)（父类默认抛 UnsupportedOperationException）
        //   → MITM TLS 升级全挂 → 目标 App 全部 HTTPS 请求失败（一直连线中）。
        //   NAS 冒烟是 JDK 走 4 参路径未暴露；真机透明模式（consumed!=null）必走 3 参。
        SSLContext ctx = null;
        try {
            ctx = SSLContext.getInstance("TLS", "AndroidOpenSSL");
        } catch (Throwable t1) {
            try {
                ctx = SSLContext.getInstance("TLS", "Conscrypt");
            } catch (Throwable t2) {
                ctx = SSLContext.getInstance("TLS");
            }
        }
        ctx.init(kmf.getKeyManagers(), null, null);
        return ctx;
    }

    // ===== 工具 =====

    /** 读一行（\r\n 或 \n 结尾），返回去掉行尾的内容；EOF 返回 null */
    private static String readLine(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder(64);
        int c;
        while ((c = in.read()) != -1) {
            if (c == '\n') break;
            if (c != '\r') sb.append((char) c);
            if (sb.length() > 4096) break;
        }
        if (sb.length() == 0 && c == -1) return null;
        return sb.toString();
    }

    private static void writeRaw(OutputStream out, String s) throws IOException {
        out.write(s.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
        out.flush();
    }

    private static void closeQuietly(Socket s) {
        try { if (s != null) s.close(); } catch (Throwable ignored) {}
    }
}
