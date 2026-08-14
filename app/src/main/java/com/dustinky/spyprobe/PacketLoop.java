package com.dustinky.spyprobe;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicLong;

/**
 * v8x: TUN 包循环（共用：VpnService / Magisk 两种模式）
 *
 * 职责（Clash MIX TUN 思路 + PCAPDroid 观察式转发）：
 *   1. 读 TUN fd 的 IP 包（v4/v6）
 *   2. 解析五元组（TCP/UDP）
 *   3. 记录连接（TUN 类型 SpyEvent：建立/关闭/字节/时长）
 *   4. 简化用户态转发（只观察不改 payload——流量原样透传，App 无感知）
 *
 * TCP 简化（第一版，真机迭代补强）：
 *   - 伪握手：客户端 SYN → 我们 socket connect 服务器 → 回编造的 SYN-ACK（自定 serverSeq）
 *     → 客户端 ACK 丢弃 → 之后 payload 双向透传（seq 用自维护计数器）
 *   - 不做重组/重传/乱序处理（绝大多数场景按序到达，可用；异常连接客户端会重传触发重建）
 * UDP：
 *   - 五元组 → DatagramSocket 映射，payload 双向透传
 *
 * 线程模型：
 *   - reader 线程：读 TUN 包 → 解析 → 分发（连接 worker 队列 / UDP socket）
 *   - 每 TCP 连接一个 worker 线程（connect + 双向转发）
 *   - 每 UDP 连接一个 response 线程
 *
 * 安全：所有异常 try-catch，绝不让 TUN 数据面崩溃拖垮 UI 进程。
 */
public class PacketLoop {

    private static final String TAG = "SpyProbe.PacketLoop";

    /** 出口 socket 防回环（VpnService 模式必须；Magisk 模式 null 不 protect） */
    public interface Protector {
        void protect(Socket s);
        void protect(DatagramSocket s);
    }

    private final InputStream in;
    private final OutputStream out;
    private final Protector protector;
    private final boolean magiskMode;

    private volatile boolean running = false;
    private Thread readerThread;
    private final byte[] readBuf = new byte[65536];

    // 连接表
    private final ConcurrentHashMap<FlowKey, TcpConn> tcpTable = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<FlowKey, UdpConn> udpTable = new ConcurrentHashMap<>();

    // 统计
    private final AtomicLong totalRead = new AtomicLong();
    private final AtomicLong totalWrite = new AtomicLong();
    private final AtomicLong connSeq = new AtomicLong(1);

    /** VpnService 模式：FileInputStream/FileOutputStream（官方 VpnService 模式） */
    public PacketLoop(InputStream in, OutputStream out, Protector protector) {
        this.in = in;
        this.out = out;
        this.protector = protector;
        this.magiskMode = false;
    }

    /**
     * Magisk raw fd 构造（fd 由 MagiskTun.nativeOpenTun 打开）
     * fd 无法直接用 FileInputStream 包装（无 FileDescriptor），
     * 走 PacketLoop 专用 native read/write（native_hook.cpp）。
     */
    public static PacketLoop forRawFd(int fd, Protector protector) {
        return new PacketLoop(fd, protector, true);
    }

    private PacketLoop(int fd, Protector protector, boolean raw) {
        this.in = null;
        this.out = null;
        this.protector = protector;
        this.magiskMode = true;
        this.rawFd = fd;
    }

    private int rawFd = -1;

    /** 启动；返回 null=成功，非 null=错误 */
    public synchronized String start() {
        if (running) return null;
        if (in == null && rawFd < 0) return "无输入流";
        running = true;
        readerThread = new Thread(this::readerLoop, "SpyProbe-TunReader");
        readerThread.setDaemon(true);
        readerThread.start();
        DebugLog.get().logNoMirror(TAG, "start (magisk=" + magiskMode + " fd=" + rawFd + ")");
        return null;
    }

    public synchronized void close() {
        running = false;
        if (readerThread != null) {
            readerThread.interrupt();
            readerThread = null;
        }
        for (TcpConn c : tcpTable.values()) c.close();
        for (UdpConn c : udpTable.values()) c.close();
        tcpTable.clear();
        udpTable.clear();
        if (rawFd >= 0) {
            nativeCloseTun(rawFd);
            rawFd = -1;
        } else {
            try { in.close(); } catch (Throwable t) { }
            try { out.close(); } catch (Throwable t) { }
        }
        DebugLog.get().logNoMirror(TAG, "closed");
    }

    public int connCount() { return tcpTable.size() + udpTable.size(); }
    public long readBytes() { return totalRead.get(); }
    public long writeBytes() { return totalWrite.get(); }

    // ================= reader =================

    private void readerLoop() {
        while (running) {
            try {
                int n;
                if (magiskMode && rawFd >= 0) {
                    n = nativeReadTun(rawFd, readBuf, readBuf.length);
                } else {
                    n = in.read(readBuf);
                }
                if (n <= 0) {
                    if (n < 0) {
                        DebugLog.get().logNoMirror(TAG, "TUN EOF, stop");
                        break;
                    }
                    // n==0：非阻塞 fd 无数据（EAGAIN）→ 小睡防忙等
                    try { Thread.sleep(1); } catch (InterruptedException ie) { break; }
                    continue;
                }
                totalRead.addAndGet(n);
                handlePacket(readBuf, n);
            } catch (Throwable t) {
                DebugLog.get().logNoMirror(TAG, "reader err: " + t);
                try { Thread.sleep(20); } catch (InterruptedException ie2) { break; }
            }
        }
        running = false;
        DebugLog.get().logNoMirror(TAG, "reader exited");
    }

    private void handlePacket(byte[] buf, int len) {
        if (len < 20) return;
        int version = (buf[0] >> 4) & 0x0F;
        if (version == 4) handleV4(buf, len);
        else if (version == 6) handleV6(buf, len);
        // 其他忽略
    }

    private void handleV4(byte[] b, int len) {
        int ihl = (b[0] & 0x0F) * 4;
        if (ihl < 20 || ihl >= len) return;
        int proto = b[9] & 0xFF;
        if (proto != 6 && proto != 17) return; // 只 TCP/UDP
        byte[] src = new byte[4];
        byte[] dst = new byte[4];
        System.arraycopy(b, 12, src, 0, 4);
        System.arraycopy(b, 16, dst, 0, 4);
        FlowKey key = FlowKey.v4(proto, src, dst, readPort(b, ihl, true), readPort(b, ihl, false));
        if (proto == 6) handleTcp(b, len, ihl, key);
        else handleUdp(b, len, ihl, key);
    }

    private void handleV6(byte[] b, int len) {
        int nextHeader = b[6] & 0xFF;
        if (nextHeader != 6 && nextHeader != 17) return; // 简化：忽略扩展头
        byte[] src = new byte[16];
        byte[] dst = new byte[16];
        System.arraycopy(b, 8, src, 0, 16);
        System.arraycopy(b, 24, dst, 0, 16);
        int l4off = 40;
        FlowKey key = FlowKey.v6(nextHeader, src, dst, readPort(b, l4off, true), readPort(b, l4off, false));
        if (nextHeader == 6) handleTcp(b, len, l4off, key);
        else handleUdp(b, len, l4off, key);
    }

    private static int readPort(byte[] b, int l4off, boolean src) {
        int p = src ? 0 : 2;
        if (l4off + p + 1 >= b.length) return 0;
        return ((b[l4off + p] & 0xFF) << 8) | (b[l4off + p + 1] & 0xFF);
    }

    // ================= TCP =================

    private void handleTcp(byte[] b, int len, int l4off, FlowKey key) {
        int tcpHdr = ((b[l4off + 12] >> 4) & 0x0F) * 4;
        if (tcpHdr < 20 || l4off + tcpHdr > len) return;
        long seq = readU32(b, l4off + 4);
        long ack = readU32(b, l4off + 8);
        int flags = b[l4off + 13] & 0x3F;
        int payloadLen = len - (l4off + tcpHdr);
        byte[] payload = null;
        if (payloadLen > 0) {
            payload = new byte[payloadLen];
            System.arraycopy(b, l4off + tcpHdr, payload, 0, payloadLen);
        }

        TcpConn conn = tcpTable.get(key);
        boolean syn = (flags & 0x02) != 0;
        boolean ackF = (flags & 0x10) != 0;
        boolean fin = (flags & 0x01) != 0;
        boolean rst = (flags & 0x04) != 0;

        if (conn == null) {
            if (!syn || ackF) return; // 只从 SYN 建连（对端重传的旧连接直接忽略，客户端会重连）
            conn = new TcpConn(key, seq, b, len, l4off);
            tcpTable.put(key, conn);
            conn.start();
            // SYN 入队（payload 一般空；如有（TFO）也转发）
            if (payload != null && payload.length > 0) conn.clientQueue.offer(payload);
            recordConnOpen(conn, "TCP");
            return;
        }
        // 已建连
        if (rst) {
            conn.remoteClosed("RST");
            return;
        }
        if (fin) {
            // FIN 转发给服务器（socket.shutdownOutput），响应侧 FIN 由 worker 处理
            conn.clientFin(seq, payload);
            return;
        }
        if (payload != null && payload.length > 0) {
            conn.clientQueue.offer(payload);
            // 更新客户端 seq（worker 转发时用；简化：以首个数据段为准）
            conn.clientSeqSeen = seq;
        }
    }

    /** TcpConn：worker 线程负责 socket connect + 伪握手 + 双向转发 */
    private class TcpConn {
        final FlowKey key;
        final LinkedBlockingQueue<byte[]> clientQueue = new LinkedBlockingQueue<>(256);
        final long clientSynSeq;
        volatile long clientSeqSeen;
        volatile boolean serverSeqBaseSet = false;
        volatile long serverSeqBase = 0;   // 伪服务器初始 seq（客户端看到的）
        volatile long clientSeq = 0;       // 客户端当前 seq（构造 ack 用）
        volatile long serverSeq = 0;       // 服务器当前 seq（构造 seq 用）
        volatile boolean closed = false;
        final long openTime = System.currentTimeMillis();
        final long id = connSeq.getAndIncrement();
        volatile SpyEvent event;
        Thread worker;

        TcpConn(FlowKey key, long synSeq, byte[] pkt, int len, int l4off) {
            this.key = key;
            this.clientSynSeq = synSeq;
            this.clientSeq = synSeq + 1;
            this.clientSeqSeen = synSeq + 1;
        }

        void start() {
            worker = new Thread(this::run, "SpyProbe-TunTcp" + id);
            worker.setDaemon(true);
            worker.start();
        }

        void run() {
            Socket sock = null;
            try {
                sock = new Socket();
                sock.setTcpNoDelay(true);
                sock.connect(new InetSocketAddress(key.dstIp(), key.dstPort()), 5000);
                if (protector != null) protector.protect(sock);
                // 伪握手：回 SYN-ACK（seq=serverSeqBase, ack=clientSeq）
                serverSeqBase = 100000 + (id * 997) % 900000; // 固定基线，防同段猜测
                serverSeq = serverSeqBase;
                writeTcpReply(sock, key, 0x12 /* SYN|ACK */, serverSeqBase, clientSeq, null);
                serverSeq = serverSeqBase + 1;
                // 等客户端 ACK（丢弃 payload；一般不携带）
                // 直接进入转发循环
                OutputStream sos = sock.getOutputStream();
                InputStream sis = sock.getInputStream();
                // 客户端→服务器
                while (running && !closed) {
                    byte[] p = clientQueue.poll(200, java.util.concurrent.TimeUnit.MILLISECONDS);
                    if (p != null) {
                        if (p.length == 0) {
                            // FIN 哨兵：关闭发送方向（服务器收到 EOF）
                            try { sock.shutdownOutput(); } catch (Throwable t) { }
                            continue;
                        }
                        sos.write(p);
                        sos.flush();
                        clientSeq += p.length;
                    }
                    // 服务器→客户端
                    int avail;
                    while ((avail = sis.available()) > 0) {
                        byte[] rb = new byte[Math.min(avail, 32768)];
                        int n = sis.read(rb);
                        if (n <= 0) break;
                        writeTcpReply(sock, key, 0x18 /* ACK|PSH */, serverSeq, clientSeq, copy(rb, n));
                        serverSeq += n;
                        recordBytes(n);
                    }
                }
            } catch (Throwable t) {
                DebugLog.get().logNoMirror(TAG, "tcp worker err (" + key.shortStr() + "): " + t);
            } finally {
                if (sock != null) {
                    try { sock.close(); } catch (Throwable t) { }
                }
                tcpTable.remove(key, this);
                recordConnClose(this);
                closed = true;
            }
        }

        void clientFin(long seq, byte[] payload) {
            if (payload != null && payload.length > 0) clientQueue.offer(payload);
            // 通知 worker 关闭发送方向
            try {
                clientQueue.offer(new byte[0]); // 哨兵：空包 = 关闭写
            } catch (Throwable t) { }
        }

        void remoteClosed(String why) {
            closed = true;
            try { clientQueue.offer(new byte[0]); } catch (Throwable t) { }
        }

        void close() {
            closed = true;
            try { clientQueue.offer(new byte[0]); } catch (Throwable t) { }
            if (worker != null) worker.interrupt();
        }
    }

    // ================= UDP =================

    private void handleUdp(byte[] b, int len, int l4off, FlowKey key) {
        if (l4off + 8 > len) return;
        int udpLen = ((b[l4off + 4] & 0xFF) << 8) | (b[l4off + 5] & 0xFF);
        int payloadLen = len - (l4off + 8);
        if (payloadLen <= 0) return;
        byte[] payload = new byte[payloadLen];
        System.arraycopy(b, l4off + 8, payload, 0, payloadLen);
        UdpConn conn = udpTable.get(key);
        if (conn == null) {
            conn = new UdpConn(key);
            UdpConn old = udpTable.putIfAbsent(key, conn);
            if (old != null) conn = old;
            else conn.start();
        }
        conn.send(payload);
        recordBytes(payloadLen);
    }

    private class UdpConn {
        final FlowKey key;
        DatagramSocket sock;
        volatile boolean closed = false;
        final long openTime = System.currentTimeMillis();
        final long id = connSeq.getAndIncrement();
        volatile SpyEvent event;

        UdpConn(FlowKey key) { this.key = key; }

        void start() {
            Thread th = new Thread(() -> {
                try {
                    sock = new DatagramSocket();
                    sock.connect(new InetSocketAddress(key.dstIp(), key.dstPort()));
                    if (protector != null) protector.protect(sock);
                    recordConnOpen(this, "UDP");
                    byte[] rb = new byte[65536];
                    while (running && !closed) {
                        DatagramPacket dp = new DatagramPacket(rb, rb.length);
                        sock.setSoTimeout(1000);
                        try {
                            sock.receive(dp);
                        } catch (java.net.SocketTimeoutException ste) { continue; }
                        writeUdpReply(key, copy(rb, dp.getLength()));
                    }
                } catch (Throwable ex) {
                    DebugLog.get().logNoMirror(TAG, "udp worker err (" + key.shortStr() + "): " + ex);
                } finally {
                    if (sock != null) { try { sock.close(); } catch (Throwable ex2) { } }
                    udpTable.remove(key, this);
                    recordConnClose(this);
                    closed = true;
                }
            }, "SpyProbe-TunUdp" + id);
            th.setDaemon(true);
            th.start();
        }

        void send(byte[] p) {
            try {
                if (sock != null && !closed) {
                    sock.send(new DatagramPacket(p, p.length));
                }
            } catch (Throwable t) { }
        }

        void close() {
            closed = true;
            if (sock != null) { try { sock.close(); } catch (Throwable t) { } }
        }
    }

    // ================= 记录（TUN 事件 → EventStore） =================

    private void recordConnOpen(TcpConn c, String proto) {
        try {
            org.json.JSONObject payload = new org.json.JSONObject();
            payload.put("proto", proto);
            payload.put("src", c.key.srcStr());
            payload.put("dst", c.key.dstStr());
            payload.put("srcPort", c.key.srcPort());
            payload.put("dstPort", c.key.dstPort());
            long id = EventStore.get().nextId();
            String title = "TUN " + proto + " " + c.key.srcStr() + ":" + c.key.srcPort()
                    + " → " + c.key.dstStr() + ":" + c.key.dstPort();
            String logLine = "[TUN] " + title;
            c.event = new SpyEvent("TUN", id, c.openTime, title, payload, logLine, "");
            EventStore.get().add(c.event);
        } catch (Throwable t) { }
    }

    private void recordConnOpen(UdpConn c, String proto) {
        try {
            org.json.JSONObject payload = new org.json.JSONObject();
            payload.put("proto", proto);
            payload.put("src", c.key.srcStr());
            payload.put("dst", c.key.dstStr());
            payload.put("srcPort", c.key.srcPort());
            payload.put("dstPort", c.key.dstPort());
            long id = EventStore.get().nextId();
            String title = "TUN " + proto + " " + c.key.srcStr() + ":" + c.key.srcPort()
                    + " → " + c.key.dstStr() + ":" + c.key.dstPort();
            String logLine = "[TUN] " + title;
            c.event = new SpyEvent("TUN", id, c.openTime, title, payload, logLine, "");
            EventStore.get().add(c.event);
        } catch (Throwable t) { }
    }

    private void recordConnClose(TcpConn c) {
        try {
            if (c.event != null) c.event.complete(System.currentTimeMillis() - c.openTime);
        } catch (Throwable t) { }
    }

    private void recordConnClose(UdpConn c) {
        try {
            if (c.event != null) c.event.complete(System.currentTimeMillis() - c.openTime);
        } catch (Throwable t) { }
    }

    private void recordBytes(int n) {
        totalWrite.addAndGet(n);
    }

    // ================= 响应段构造（写回 TUN） =================

    private void writeTcpReply(Socket sock, FlowKey key, int flags, long seq, long ack, byte[] payload) {
        try {
            if (magiskMode && rawFd >= 0) {
                byte[] pkt = buildTcpPacket(key, flags, seq, ack, payload);
                if (pkt != null) {
                    nativeWriteTun(rawFd, pkt, pkt.length);
                    totalWrite.addAndGet(pkt.length);
                }
                return;
            }
            byte[] pkt = buildTcpPacket(key, flags, seq, ack, payload);
            if (pkt != null) {
                out.write(pkt);
                out.flush();
                totalWrite.addAndGet(pkt.length);
            }
        } catch (Throwable t) {
            DebugLog.get().logNoMirror(TAG, "writeTcpReply err: " + t);
        }
    }

    private void writeUdpReply(FlowKey key, byte[] payload) {
        try {
            if (magiskMode && rawFd >= 0) {
                byte[] pkt = buildUdpPacket(key, payload);
                if (pkt != null) {
                    nativeWriteTun(rawFd, pkt, pkt.length);
                    totalWrite.addAndGet(pkt.length);
                }
                return;
            }
            byte[] pkt = buildUdpPacket(key, payload);
            if (pkt != null) {
                out.write(pkt);
                out.flush();
                totalWrite.addAndGet(pkt.length);
            }
        } catch (Throwable t) {
            DebugLog.get().logNoMirror(TAG, "writeUdpReply err: " + t);
        }
    }

    /** 构造 IPv4/IPv6 + TCP 段（服务器 → 客户端方向；src/dst 反置） */
    private byte[] buildTcpPacket(FlowKey key, int flags, long seq, long ack, byte[] payload) {
        int payloadLen = payload == null ? 0 : payload.length;
        boolean v6 = key.v6;
        int headerLen = v6 ? 40 : 20;
        int tcpLen = 20;
        int total = headerLen + tcpLen + payloadLen;
        byte[] b = new byte[total];

        if (!v6) {
            // IPv4
            b[0] = 0x45;
            b[2] = (byte) ((total >> 8) & 0xFF);
            b[3] = (byte) (total & 0xFF);
            b[8] = 64; // TTL
            b[9] = 6;  // TCP
            System.arraycopy(key.dst, 0, b, 12, 4); // src = 服务器
            System.arraycopy(key.src, 0, b, 16, 4); // dst = 客户端
            ipChecksum(b, 20);
        } else {
            b[0] = 0x60;
            b[6] = 6;
            int plen = tcpLen + payloadLen;
            b[4] = (byte) ((plen >> 8) & 0xFF);
            b[5] = (byte) (plen & 0xFF);
            b[7] = 64;
            System.arraycopy(key.dst, 0, b, 8, 16);
            System.arraycopy(key.src, 0, b, 24, 16);
        }

        int p = headerLen;
        writeU16(b, p, key.dstPort());      // srcPort = 服务器
        writeU16(b, p + 2, key.srcPort());  // dstPort = 客户端
        writeU32(b, p + 4, seq);
        writeU32(b, p + 8, ack);
        b[p + 12] = 0x50; // dataOffset=5, reserved
        b[p + 13] = (byte) flags;
        // window=0xFFFF, checksum 后补, urgent=0
        if (payloadLen > 0) System.arraycopy(payload, 0, b, p + tcpLen, payloadLen);
        tcpChecksum(b, headerLen, tcpLen, payloadLen, v6);
        return b;
    }

    private byte[] buildUdpPacket(FlowKey key, byte[] payload) {
        boolean v6 = key.v6;
        int headerLen = v6 ? 40 : 20;
        int udpLen = 8 + payload.length;
        int total = headerLen + udpLen;
        byte[] b = new byte[total];

        if (!v6) {
            b[0] = 0x45;
            b[2] = (byte) ((total >> 8) & 0xFF);
            b[3] = (byte) (total & 0xFF);
            b[8] = 64;
            b[9] = 17; // UDP
            System.arraycopy(key.dst, 0, b, 12, 4);
            System.arraycopy(key.src, 0, b, 16, 4);
            ipChecksum(b, 20);
        } else {
            b[0] = 0x60;
            b[6] = 17;
            b[4] = (byte) ((udpLen >> 8) & 0xFF);
            b[5] = (byte) (udpLen & 0xFF);
            b[7] = 64;
            System.arraycopy(key.dst, 0, b, 8, 16);
            System.arraycopy(key.src, 0, b, 24, 16);
        }

        int p = headerLen;
        writeU16(b, p, key.dstPort());
        writeU16(b, p + 2, key.srcPort());
        writeU16(b, p + 4, udpLen);
        // IPv4 UDP checksum 可置 0（合法）；IPv6 必填
        System.arraycopy(payload, 0, b, p + 8, payload.length);
        if (v6) udpChecksum(b, headerLen, udpLen, true);
        return b;
    }

    // ================= checksum =================

    private static void ipChecksum(byte[] b, int hdrLen) {
        long sum = 0;
        int i = 0;
        while (i < hdrLen) {
            sum += ((b[i] & 0xFF) << 8) | (b[i + 1] & 0xFF);
            i += 2;
        }
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        int c = (int) (~sum & 0xFFFF);
        b[10] = (byte) (c >> 8);
        b[11] = (byte) (c & 0xFF);
    }

    private static void tcpChecksum(byte[] b, int headerLen, int tcpLen, int payloadLen, boolean v6) {
        long sum = 0;
        // 伪头
        if (v6) {
            for (int i = 0; i < 16; i += 2) sum += ((b[8 + i] & 0xFF) << 8) | (b[8 + i + 1] & 0xFF);
            for (int i = 0; i < 16; i += 2) sum += ((b[24 + i] & 0xFF) << 8) | (b[24 + i + 1] & 0xFF);
            sum += (tcpLen + payloadLen) & 0xFFFF; // v6 payload len（upper 16 bits = 0）
            sum += 6;
        } else {
            for (int i = 0; i < 4; i += 2) sum += ((b[12 + i] & 0xFF) << 8) | (b[12 + i + 1] & 0xFF);
            for (int i = 0; i < 4; i += 2) sum += ((b[16 + i] & 0xFF) << 8) | (b[16 + i + 1] & 0xFF);
            sum += 6;
            sum += (tcpLen + payloadLen) & 0xFFFF;
        }
        // TCP 头 + payload
        int end = headerLen + tcpLen + payloadLen;
        int i = headerLen;
        while (i + 1 < end) {
            sum += ((b[i] & 0xFF) << 8) | (b[i + 1] & 0xFF);
            i += 2;
        }
        if (i < end) sum += (b[i] & 0xFF) << 8; // 奇数 padding
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        int c = (int) (~sum & 0xFFFF);
        b[headerLen + 16] = (byte) (c >> 8);
        b[headerLen + 17] = (byte) (c & 0xFF);
    }

    private static void udpChecksum(byte[] b, int headerLen, int udpLen, boolean v6) {
        long sum = 0;
        if (v6) {
            for (int i = 0; i < 16; i += 2) sum += ((b[8 + i] & 0xFF) << 8) | (b[8 + i + 1] & 0xFF);
            for (int i = 0; i < 16; i += 2) sum += ((b[24 + i] & 0xFF) << 8) | (b[24 + i + 1] & 0xFF);
            sum += udpLen & 0xFFFF;
            sum += 17;
        }
        int end = headerLen + udpLen;
        int i = headerLen;
        while (i + 1 < end) {
            sum += ((b[i] & 0xFF) << 8) | (b[i + 1] & 0xFF);
            i += 2;
        }
        if (i < end) sum += (b[i] & 0xFF) << 8;
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        int c = (int) (~sum & 0xFFFF);
        b[headerLen + 6] = (byte) (c >> 8);
        b[headerLen + 7] = (byte) (c & 0xFF);
    }

    // ================= 工具 =================

    private static long readU32(byte[] b, int off) {
        return ((long) (b[off] & 0xFF) << 24) | ((b[off + 1] & 0xFF) << 16)
                | ((b[off + 2] & 0xFF) << 8) | (b[off + 3] & 0xFF);
    }

    private static void writeU16(byte[] b, int off, int v) {
        b[off] = (byte) ((v >> 8) & 0xFF);
        b[off + 1] = (byte) (v & 0xFF);
    }

    private static void writeU32(byte[] b, int off, long v) {
        b[off] = (byte) ((v >> 24) & 0xFF);
        b[off + 1] = (byte) ((v >> 16) & 0xFF);
        b[off + 2] = (byte) ((v >> 8) & 0xFF);
        b[off + 3] = (byte) (v & 0xFF);
    }

    private static byte[] copy(byte[] b, int n) {
        byte[] r = new byte[n];
        System.arraycopy(b, 0, r, 0, n);
        return r;
    }

    /** 连接键：四元组 + 协议（v4/v6 区分） */
    private static class FlowKey {
        final boolean v6;
        final int proto;
        final byte[] src;
        final byte[] dst;
        final int srcPort;
        final int dstPort;
        final int hash;

        FlowKey(boolean v6, int proto, byte[] src, byte[] dst, int srcPort, int dstPort) {
            this.v6 = v6;
            this.proto = proto;
            this.src = src;
            this.dst = dst;
            this.srcPort = srcPort;
            this.dstPort = dstPort;
            int h = (v6 ? 1 : 0) ^ proto ^ srcPort ^ dstPort;
            for (byte x : src) h = h * 31 + x;
            for (byte x : dst) h = h * 31 + x;
            this.hash = h;
        }

        static FlowKey v4(int proto, byte[] src, byte[] dst, int sp, int dp) {
            return new FlowKey(false, proto, src, dst, sp, dp);
        }

        static FlowKey v6(int proto, byte[] src, byte[] dst, int sp, int dp) {
            return new FlowKey(true, proto, src, dst, sp, dp);
        }

        String srcStr() { return ipStr(src, v6); }
        String dstStr() { return ipStr(dst, v6); }
        int srcPort() { return srcPort; }
        int dstPort() { return dstPort; }
        String dstIp() { return dstStr(); }
        String shortStr() { return srcStr() + ":" + srcPort + "->" + dstStr() + ":" + dstPort; }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof FlowKey)) return false;
            FlowKey k = (FlowKey) o;
            if (k.v6 != v6 || k.proto != proto || k.srcPort != srcPort || k.dstPort != dstPort) return false;
            if (k.src.length != src.length) return false;
            for (int i = 0; i < src.length; i++) if (k.src[i] != src[i]) return false;
            for (int i = 0; i < dst.length; i++) if (k.dst[i] != dst[i]) return false;
            return true;
        }

        @Override
        public int hashCode() { return hash; }

        private static String ipStr(byte[] b, boolean v6) {
            try {
                return InetAddress.getByAddress(b).getHostAddress();
            } catch (Throwable t) {
                return v6 ? "v6?" : "v4?";
            }
        }
    }

    // ================= native（Magisk raw fd；native_hook.cpp 实现） =================

    public static native int nativeReadTun(int fd, byte[] buf, int len);
    public static native int nativeWriteTun(int fd, byte[] buf, int len);
    public static native void nativeCloseTun(int fd);
}
