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
                StringBuilder fdDiag = new StringBuilder();
                int fd = FdUtil.getFd(appSocket, fdDiag);
                if (fd > 0) {
                    try { origDst = MitmSock.getOriginalDst(fd); }
                    catch (Throwable t) { fdDiag.append("getOriginalDst throw: ").append(t).append("; "); }
                } else {
                    fdDiag.append("FdUtil.getFd=").append(fd).append("; ");
                }
                // v1.74.8 P0-11: origDst 失败必须留痕（此前静默 null → 拿不到真实目标 IP
                //   → DNS 重连被屏蔽成 127.0.0.1 → connect localhost:443 全挂且无从排查）
                if (origDst == null) {
                    MitmLog.log("[" + seq + "] getOriginalDst null fd=" + fd + " diag=" + fdDiag);
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
                MitmLog.log("[" + seq + "] TRANSPARENT host=" + hostname + ":" + targetPort + " orig=" + origDst + " fd=" + fd);
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
                // v1.74.8 P0-11: 预解析 + 防 DNS 屏蔽——目标 App 走 DoH（dns.alidns.com:443）拿真实 IP，
                //   系统 DNS 把这些域名屏蔽成 127.0.0.1 → 此前傻连 localhost:443 → ECONNREFUSED 全挂。
                //   origDst 可用时走上面真实 IP 分支；命中回环说明 origDst 仍失效 → 明确留痕不再傻连。
                InetAddress resolved = InetAddress.getByName(hostname);
                if (resolved.isLoopbackAddress()) {
                    throw new IOException("DNS blocked: " + hostname + " -> " + resolved
                            + " (origDst=null, 无法获知真实目标 IP)");
                }
                targetSsl.connect(new InetSocketAddress(resolved, targetPort), 15000);
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
            // v1.74.8 P0-11: 重写 upgrade——v1.74.7 用的两条路在 Android 16 全不存在（AOSP 源码实锤）：
            //   ① SSLSocketFactory 3 参 createSocket(Socket, InputStream, boolean)
            //      ——Conscrypt OpenSSLSocketFactoryImpl 从未实现该方法，父类默认实现
            //      SSLSocketFactory.java:278 抛 UnsupportedOperationException
            //   ② Conscrypt.newFileDescriptorSocket(SSLContext, Socket, InputStream, boolean)
            //      ——Conscrypt 公共 API 根本没有这个静态方法（NoSuchMethodException，异常还被吞成 unsupported）
            //   → v1.74.7 22 次 "upgrade createSocket(consumed) unsupported" 全是必然。
            //   唯一可用路径：4 参 createSocket(Socket, hostname, port, autoClose)（Conscrypt 已实现），
            //   它通过 socket.getInputStream() 读数据 → 用 ConsumedSocket 把 TlsSniffer 提前消费的
            //   ClientHello 字节前置回流，并强制 engine 路径（fd 路径从 fd 直读会丢掉 consumed）。
            InputStream consumedIn = consumed != null ? new ByteArrayInputStream(consumed) : null;
            appSsl = upgradeToTlsServer(seq, ctx, serverFactory, appSocket, consumedIn, hostname, targetPort);
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

    /**
     * v1.74.8 P0-11: 把已有 app TCP socket（+已消费的 ClientHello 字节）升级为 TLS server 端。
     *
     * 实现（Android 16 AOSP 源码验证过的唯一可用路径）：
     *   - ConsumedSocket 包装 appSocket：getInputStream() 返回「consumed 字节 + 剩余流」的合并流
     *   - Conscrypt.setUseEngineSocket(factory, true) 强制 engine 路径（fd 路径从 fd 直读，会丢 consumed）
     *   - 4 参 createSocket(Socket, hostname, port, autoClose)（Conscrypt OpenSSLSocketFactoryImpl 实现）
     *   - setUseClientMode(false) 由调用方在返回后设置（升级为 TLS server）
     */
    private SSLSocket upgradeToTlsServer(int seq, SSLContext ctx, SSLSocketFactory serverFactory,
                                         Socket appSocket, InputStream consumedIn,
                                         String hostname, int targetPort) throws Exception {
        // ① 强制 Conscrypt engine 路径（非 Conscrypt factory 抛 IllegalArgumentException → 忽略，走默认）
        try {
            java.lang.reflect.Method m = Class.forName("org.conscrypt.Conscrypt")
                    .getMethod("setUseEngineSocket", SSLSocketFactory.class, boolean.class);
            m.invoke(null, serverFactory, Boolean.TRUE);
        } catch (Throwable t) {
            MitmLog.log("[" + seq + "] setUseEngineSocket skip: " + t);
        }
        // ② 包装 socket（consumed 字节前置回喂）
        Socket wrap = consumedIn != null ? new ConsumedSocket(appSocket, consumedIn) : appSocket;
        // ③ 4 参 createSocket
        try {
            SSLSocket s = (SSLSocket) serverFactory.createSocket(wrap, hostname, targetPort, true);
            MitmLog.log("[" + seq + "] TLS upgrade via 4-arg createSocket"
                    + (consumedIn != null ? " (consumed fed via ConsumedSocket)" : ""));
            return s;
        } catch (Throwable t) {
            throw new IOException("upgrade createSocket(4-arg) failed: " + t, t);
        }
    }

    /**
     * v1.74.8 P0-11: 「已消费字节」前置的 Socket 包装——getInputStream() 先吐 consumed，
     *   再接真实 socket 剩余流；其余全部委托给 real。给 Conscrypt 4 参 createSocket 用，
     *   使其引擎路径能读到被 TlsSniffer 提前消费的 ClientHello（不依赖不存在的 3 参 API）。
     */
    private static final class ConsumedSocket extends java.net.Socket {
        private final Socket real;
        private final InputStream in;

        ConsumedSocket(Socket real, InputStream consumed) throws IOException {
            super(); // 仅委托壳，无实际连接
            this.real = real;
            this.in = new java.io.SequenceInputStream(consumed, real.getInputStream());
        }

        @Override public InputStream getInputStream() throws IOException { return in; }
        @Override public OutputStream getOutputStream() throws IOException { return real.getOutputStream(); }
        @Override public boolean isConnected() { return true; }
        @Override public void close() throws IOException { real.close(); }
        @Override public void setSoTimeout(int timeout) throws java.net.SocketException { real.setSoTimeout(timeout); }
        @Override public int getSoTimeout() throws java.net.SocketException { return real.getSoTimeout(); }
        @Override public void setTcpNoDelay(boolean on) throws java.net.SocketException { real.setTcpNoDelay(on); }
        @Override public boolean getTcpNoDelay() throws java.net.SocketException { return real.getTcpNoDelay(); }
        @Override public void setKeepAlive(boolean on) throws java.net.SocketException { real.setKeepAlive(on); }
        @Override public boolean getKeepAlive() throws java.net.SocketException { return real.getKeepAlive(); }
        @Override public void setSoLinger(boolean on, int l) throws java.net.SocketException { real.setSoLinger(on, l); }
        @Override public int getSoLinger() throws java.net.SocketException { return real.getSoLinger(); }
        @Override public void setOOBInline(boolean on) throws java.net.SocketException { real.setOOBInline(on); }
        @Override public boolean getOOBInline() throws java.net.SocketException { return real.getOOBInline(); }
        @Override public void setReceiveBufferSize(int size) throws java.net.SocketException { real.setReceiveBufferSize(size); }
        @Override public int getReceiveBufferSize() throws java.net.SocketException { return real.getReceiveBufferSize(); }
        @Override public void setSendBufferSize(int size) throws java.net.SocketException { real.setSendBufferSize(size); }
        @Override public int getSendBufferSize() throws java.net.SocketException { return real.getSendBufferSize(); }
        @Override public java.net.InetAddress getInetAddress() { return real.getInetAddress(); }
        @Override public java.net.InetAddress getLocalAddress() { return real.getLocalAddress(); }
        @Override public int getPort() { return real.getPort(); }
        @Override public int getLocalPort() { return real.getLocalPort(); }
        @Override public java.net.SocketAddress getRemoteSocketAddress() { return real.getRemoteSocketAddress(); }
        @Override public java.net.SocketAddress getLocalSocketAddress() { return real.getLocalSocketAddress(); }
        @Override public void shutdownInput() throws IOException { real.shutdownInput(); }
        @Override public void shutdownOutput() throws IOException { real.shutdownOutput(); }
        @Override public boolean isClosed() { return real.isClosed(); }
        @Override public boolean isBound() { return real.isBound(); }
        @Override public boolean isInputShutdown() { return real.isInputShutdown(); }
        @Override public boolean isOutputShutdown() { return real.isOutputShutdown(); }
        @Override public String toString() { return "ConsumedSocket(" + real + ")"; }
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
        // v1.74.8 P0-11: 记录实际 provider——升级路径的 Conscrypt.setUseEngineSocket
        //   只对 Conscrypt factory 有效，非 Conscrypt 时跳过（但 4 参 createSocket 仍可用）。
        SSLContext ctx = null;
        try {
            ctx = SSLContext.getInstance("TLS", "AndroidOpenSSL");
            ctx.init(kmf.getKeyManagers(), null, null);
            MitmLog.log("buildServerContext(" + host + ") provider=AndroidOpenSSL");
            return ctx;
        } catch (Throwable t1) {
            MitmLog.log("buildServerContext AndroidOpenSSL unavailable: " + t1);
            try {
                ctx = SSLContext.getInstance("TLS", "Conscrypt");
                ctx.init(kmf.getKeyManagers(), null, null);
                MitmLog.log("buildServerContext(" + host + ") provider=Conscrypt");
                return ctx;
            } catch (Throwable t2) {
                MitmLog.log("buildServerContext Conscrypt unavailable: " + t2);
            }
        }
        ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, null);
        MitmLog.log("buildServerContext(" + host + ") provider=default(" + ctx.getProvider().getName() + ")");
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
