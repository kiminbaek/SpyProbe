package com.dustinky.spyprobe;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.SequenceInputStream;
import java.nio.ByteBuffer;
import java.security.KeyStore;
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
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLParameters;
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
@Deprecated
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
        // v1.74.9 P0-12 诊断：记录 JSSE provider 列表（定位真机 SSLContext 实现/SSLEngine 来源）
        try {
            StringBuilder sb = new StringBuilder("[diag] JSSE providers: ");
            for (java.security.Provider p : java.security.Security.getProviders()) {
                sb.append(p.getName()).append(",");
            }
            MitmLog.log(sb.toString());
        } catch (Throwable ignored) {}
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
        SSLSocket targetSsl = null;
        SSLEngine engine = null;
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
                // v1.74.12 diag: 真机 EOF no ClientHello 定位——sniff 是否成功、consumed 是否完整
                MitmLog.log("[" + seq + "] sniffed consumed=" + sr.consumed.length + " sni=" + sr.sni);
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

            // 2. 本地 TLS server 端（per-host 证书）——标准 JSSE SSLEngine（v1.74.10 P0-13）
            //    v1.74.9 顺序问题：本地握手排在 targetSsl.connect（跨洋 1-2s）之后，
            //    App 发完 ClientHello 等 ServerHello 超时 → 主动关闭 → EOF。
            //    → 本地握手必须先做（App 立即拿到 ServerHello），再连真实服务器。
            SSLContext ctx = buildServerContext(hostname, connectIp);
            engine = ctx.createSSLEngine(hostname, targetPort);
            engine.setUseClientMode(false);
            SSLParameters serverParams = engine.getSSLParameters();
            // v1.74.11 P0-14: 不设置 ALPN → 客户端（只通告 h2）fallback HTTP/1.1，明文可被
            //   TlsHttpParser 解析。旧实现强制只提供 "http/1.1"：91暗网类 App 只通告 h2 →
            //   ALPN 不匹配 → Conscrypt 抛 No matching application layer protocol values →
            //   HANDSHAKE_FAILURE_ON_CLIENT_HELLO → handshake_failure → 握手失败。
            //   服务器不通告 ALPN（RFC 7301）→ 客户端使用默认协议 HTTP/1.1。
            engine.setSSLParameters(serverParams);
            engine.beginHandshake();

            // consumed 字节 + socket 剩余流合并（透明模式回喂 ClientHello）
            InputStream appInSeq = consumed != null
                    ? new SequenceInputStream(new ByteArrayInputStream(consumed), appInRaw)
                    : appInRaw;

            ByteBuffer netIn = ByteBuffer.allocate(NET_BUF);
            ByteBuffer plain = ByteBuffer.allocate(NET_BUF);
            ByteBuffer netOut = ByteBuffer.allocate(NET_BUF);

            engineHandshake(engine, appInSeq, appOutRaw, netIn, plain, netOut, seq, hostname);

            String alpn = engine.getApplicationProtocol();
            MitmLog.log("[" + seq + "] TLS up host=" + hostname + " alpn=" + alpn
                    + " provider=" + ctx.getProvider().getName());

            // 3. 真实 TLS 连接（信任系统 CA）——本地握手完成后才连，避免 App 等待超时
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

            // 4. 双向转发（SSLEngine 解密/加密 + 明文喂 TlsHttpParser）
            InputStream targetIn = targetSsl.getInputStream();
            OutputStream targetOut = targetSsl.getOutputStream();

            Object engineLock = new Object();
            Thread t1 = pumpReq(seq, engine, engineLock, appInSeq, targetOut, netIn, plain, hostname);
            Thread t2 = pumpResp(seq, engine, engineLock, targetIn, appOutRaw, plain, netOut, hostname);
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
            closeQuietly(appSocket);
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
     * v1.74.9 P0-12: 标准 JSSE SSLEngine 做本地 TLS server 端（per-host 证书）。
     *
     * 背景：v1.74.7/v1.74.8 的 Conscrypt 4 参 createSocket + setUseEngineSocket 路线在真机
     *   Android 16 上仍「连线中」——根因是 setUseEngineSocket 因 ClassNotFoundException 静默
     *   失效 → fd 路径直读丢 consumed ClientHello → connection closed。
     *   SSLEngine 不依赖任何第三方/系统扩展 API：数据全程由本类喂给 engine，
     *   consumed 字节直接塞入输入缓冲，彻底绕开 SSLSocket 底层 fd/engine 选择问题。
     */
    private static final int NET_BUF = 64 * 1024;

    /** SSLEngine 握手（阻塞直到 FINISHED）。netIn 初始 limit(0) 表示无有效数据。 */
    private static void engineHandshake(SSLEngine engine, InputStream appIn, OutputStream appOut,
                                        ByteBuffer netIn, ByteBuffer plain, ByteBuffer netOut,
                                        int seq, String hostname) throws IOException {
        ByteBuffer empty = ByteBuffer.allocate(0);
        netIn.limit(0);
        // v1.74.14 修复（外部 AI 审查 + 编译验证）：
        //   1) 用 wrap/unwrap 返回值里的 getHandshakeStatus() 驱动循环，不再用
        //      engine.getHandshakeStatus()——Conscrypt BIO 内部状态已变但 getter 滞后返回
        //      旧值，导致真机「连线中 → EOF」。← 核心修复
        //   2) NEED_TASK 用 while 跑干净所有 delegated task。
        //   ※ 对方 AI 建议的 NEED_UNWRAP_AGAIN case 已否决：它不是标准
        //     SSLEngineResult.HandshakeStatus 枚举常量（标准仅 5 个），编译不过，
        //     运行时 getHandshakeStatus() 也不可能返回它（类型限定）。
        SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();
        while (hs != SSLEngineResult.HandshakeStatus.FINISHED
                && hs != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
            switch (hs) {
                case NEED_UNWRAP: {
                    if (!netIn.hasRemaining()) {
                        netIn.clear();
                        int n = appIn.read(netIn.array(), 0, netIn.capacity());
                        MitmLog.log("[" + seq + "] hsk read=" + n + " hs=" + hs);
                        if (n <= 0) throw new IOException("TLS handshake EOF (no ClientHello)");
                        netIn.limit(n);
                    }
                    SSLEngineResult r = engine.unwrap(netIn, plain);
                    MitmLog.log("[" + seq + "] hsk unwrap status=" + r.getStatus()
                            + " consumed=" + r.bytesConsumed() + " hs=" + r.getHandshakeStatus());
                    if (r.getStatus() == SSLEngineResult.Status.CLOSED)
                        throw new IOException("TLS closed during handshake");
                    if (r.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW)
                        throw new IOException("TLS handshake plaintext overflow");
                    if (r.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                        netIn.compact();
                        int n = appIn.read(netIn.array(), netIn.position(), netIn.remaining());
                        MitmLog.log("[" + seq + "] hsk underflow refill n=" + n);
                        if (n <= 0) throw new IOException("TLS handshake EOF mid-record");
                        netIn.position(netIn.position() + n);
                        netIn.flip();
                    }
                    hs = r.getHandshakeStatus(); // ← 关键修复：用 result 驱动
                    break;
                }
                case NEED_WRAP: {
                    netOut.clear();
                    SSLEngineResult rw = engine.wrap(empty, netOut);
                    MitmLog.log("[" + seq + "] hsk wrap status=" + rw.getStatus()
                            + " produced=" + rw.bytesProduced() + " hs=" + rw.getHandshakeStatus());
                    if (rw.getStatus() == SSLEngineResult.Status.CLOSED)
                        throw new IOException("TLS closed during handshake wrap");
                    if (rw.bytesProduced() > 0) {
                        netOut.flip();
                        appOut.write(netOut.array(), 0, netOut.limit());
                        appOut.flush();
                    }
                    hs = rw.getHandshakeStatus(); // ← 关键修复：用 result 驱动
                    break;
                }
                case NEED_TASK: {
                    MitmLog.log("[" + seq + "] hsk NEED_TASK");
                    Runnable task;
                    while ((task = engine.getDelegatedTask()) != null) { // ← 修复：while 跑干净
                        task.run();
                    }
                    hs = engine.getHandshakeStatus();
                    break;
                }
                default:
                    MitmLog.log("[" + seq + "] handshake unexpected status=" + hs);
                    return;
            }
        }
        MitmLog.log("[" + seq + "] hsk DONE status=" + hs);
    }

    /** 数据阶段：app 密文 → 解密 → 明文转发真实服务器（请求方向）。 */
    private Thread pumpReq(int seq, SSLEngine engine, Object lock, InputStream appIn,
                           OutputStream targetOut, ByteBuffer netIn, ByteBuffer plain,
                           String hostname) {
        Thread t = new Thread(() -> {
            try {
                while (running.get()) {
                    if (!netIn.hasRemaining()) {
                        netIn.clear();
                        int n = appIn.read(netIn.array(), 0, netIn.capacity());
                        if (n <= 0) break;
                        netIn.limit(n);
                    }
                    byte[] produced = null;
                    int producedLen = 0;
                    SSLEngineResult.Status status;
                    synchronized (lock) {
                        SSLEngineResult r = engine.unwrap(netIn, plain);
                        status = r.getStatus();
                        // v1.74.14: 数据阶段检测重握手（TLS1.3 KeyUpdate / 重协商）——
                        //   保守处理：日志 + 关闭连接（pumpReq 无 appOut，无法直接回 wrap 数据；
                        //   Flutter/dart:io 客户端基本不发 KeyUpdate，实际触发概率低）
                        if (r.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
                            MitmLog.log("[" + seq + "] pumpReq mid-stream handshake: "
                                    + r.getHandshakeStatus() + " (conservative close)");
                            status = SSLEngineResult.Status.CLOSED;
                        }
                        if (plain.position() > 0) {
                            producedLen = plain.position();
                            produced = new byte[producedLen];
                            plain.flip();
                            plain.get(produced);
                            plain.clear();
                        }
                    }
                    if (status == SSLEngineResult.Status.CLOSED) break;
                    if (status == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                        MitmLog.log("[" + seq + "] req overflow");
                        break;
                    }
                    if (status == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                        netIn.compact();
                        int n = appIn.read(netIn.array(), netIn.position(), netIn.remaining());
                        if (n <= 0) break;
                        netIn.position(netIn.position() + n);
                        netIn.flip();
                    }
                    if (producedLen > 0) {
                        if (listener != null) {
                            try { listener.onPlain(seq, 0, hostname, produced, producedLen); } catch (Throwable ignored) {}
                        }
                        targetOut.write(produced, 0, producedLen);
                        targetOut.flush();
                    }
                }
            } catch (Throwable t2) {
                if (running.get()) MitmLog.log("[" + seq + "] pump req err: " + t2);
            }
        }, "mitm-pump-req");
        t.setDaemon(true);
        t.start();
        return t;
    }

    /** 数据阶段：真实服务器明文 → 加密 → 密文写给 app（响应方向）。 */
    private Thread pumpResp(int seq, SSLEngine engine, Object lock, InputStream targetIn,
                            OutputStream appOut, ByteBuffer plain, ByteBuffer netOut,
                            String hostname) {
        Thread t = new Thread(() -> {
            try {
                while (running.get()) {
                    plain.clear();
                    int n = targetIn.read(plain.array(), 0, plain.capacity());
                    if (n <= 0) break;
                    plain.limit(n);
                    if (listener != null) {
                        try { listener.onPlain(seq, 1, hostname, plain.array(), n); } catch (Throwable ignored) {}
                    }
                    synchronized (lock) {
                        SSLEngineResult r = engine.wrap(plain, netOut);
                        if (r.getStatus() == SSLEngineResult.Status.CLOSED) break;
                        if (netOut.position() > 0) {
                            netOut.flip();
                            appOut.write(netOut.array(), 0, netOut.limit());
                            appOut.flush();
                            netOut.clear();
                        }
                    }
                }
            } catch (Throwable t2) {
                if (running.get()) MitmLog.log("[" + seq + "] pump resp err: " + t2);
            }
        }, "mitm-pump-resp");
        t.setDaemon(true);
        t.start();
        return t;
    }

    private SSLContext buildServerContext(String host) throws Exception {
        return buildServerContext(host, null);
    }

    private SSLContext buildServerContext(String host, String extraIp) throws Exception {
        KeyStore ks = certManager.hostKeyStore(host, extraIp);
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

    /**
     * v1.74.20 P0-19 自检：主进程用「信任 SpyProbe CA」的 SSLContext 连自己的 MITM server
     *   （127.0.0.1:port，SNI=self-test.local）→ 验证 证书链（CA 签发）+ SAN（iPAddress 127.0.0.1）。
     *   目的：区分「CA/证书本身问题」vs「目标 App（Flutter dart:io）信任锚获取问题」。
     *   自检连接不被 iptables 劫持（主进程 uid 不在目标 uid 规则），直达 8888。
     */
    public static void selfTest(int port, java.io.File caPem) {
        new Thread(() -> {
            try {
                Thread.sleep(300);
                java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
                final java.security.cert.X509Certificate ca;
                try (java.io.FileInputStream fis = new java.io.FileInputStream(caPem)) {
                    ca = (java.security.cert.X509Certificate) cf.generateCertificate(fis);
                }
                javax.net.ssl.X509TrustManager tm = new javax.net.ssl.X509TrustManager() {
                    @Override public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {}
                    @Override public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType)
                            throws java.security.cert.CertificateException {
                        if (chain == null || chain.length == 0) throw new java.security.cert.CertificateException("no chain");
                        try {
                            chain[0].verify(ca.getPublicKey()); // 叶子必须由 SpyProbe CA 签发
                        } catch (Exception e) {
                            throw new java.security.cert.CertificateException("leaf not signed by SpyProbe CA: " + e);
                        }
                    }
                    @Override public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[]{ca}; }
                };
                SSLContext ctx = SSLContext.getInstance("TLS");
                ctx.init(null, new javax.net.ssl.TrustManager[]{tm}, null);
                SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket("127.0.0.1", port);
                s.setSoTimeout(8000);
                javax.net.ssl.SSLParameters sp = s.getSSLParameters();
                sp.setServerNames(java.util.Collections.singletonList(
                        new javax.net.ssl.SNIHostName("self-test.local")));
                s.setSSLParameters(sp);
                s.startHandshake();
                java.security.cert.X509Certificate server =
                        (java.security.cert.X509Certificate) s.getSession().getPeerCertificates()[0];
                boolean hasIp127 = false;
                java.util.Collection<java.util.List<?>> sans = server.getSubjectAlternativeNames();
                if (sans != null) {
                    for (java.util.List<?> san : sans) {
                        if (san != null && san.size() >= 2 && san.get(0) instanceof Integer
                                && ((Integer) san.get(0)).intValue() == 7
                                && "127.0.0.1".equals(String.valueOf(san.get(1)))) hasIp127 = true;
                    }
                }
                s.close();
                MitmLog.log("MITM selfTest PASS chain-ok san-ip127=" + hasIp127
                        + (hasIp127 ? "" : " (MISSING 127.0.0.1 SAN!)"));
            } catch (Throwable t) {
                MitmLog.log("MITM selfTest FAIL: " + t);
            }
        }, "mitm-selftest").start();
    }

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
