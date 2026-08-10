package com.dustinky.spyprobe;

/*
 * v1.39 P0 (r0capture 借鉴): pcap 导出 —— native SSL 明文 → 标准 pcap（Wireshark 直开）
 *
 * 原理：SSL_read/SSL_write 拿到的明文本身没有 IP/TCP 头，但我们有每个 SSL 连接的
 *       socket 四元组（src/dst IP+端口，native 层 SSL_get_fd 取）和方向（isWrite）。
 *       按会话维护伪 seq/ack，把明文包成 IPv4 + TCP 头 → 标准 pcap 记录。
 *       Wireshark 打开即见完整双向明文流（无需 KeyLog 导入密钥）。
 *
 * 架构（v1.32 约定：目标进程不落盘）：
 *   - 目标进程 PcapWriter 内存组装记录（按 SSL 连接会话）
 *   - 连接关闭时把该会话的 pcap 记录字节推主进程 /api/pcap_chunk
 *   - 主进程 PcapStore 落盘 files/spyprobe_pcap/（自己家）
 *   - UI「导出 pcap」读主进程文件合并分享
 *
 * 开关：Config.pcapCapture（默认关，防额外内存/推送开销）
 */
public class PcapWriter {

    private static final String TAG = "SpyProbe.Pcap";
    private static final String HOME_URL = "http://127.0.0.1:9900/api/pcap_chunk";
    private static final int MAX_SESSION = 2 * 1024 * 1024;   // 单会话上限 2MB（视频/大文件只留前段）
    private static final int MAX_TOTAL = 32 * 1024 * 1024;    // 全部会话总上限 32MB（防 OOM，丢最旧）

    private static final PcapWriter INSTANCE = new PcapWriter();
    public static PcapWriter get() { return INSTANCE; }

    // 会话表：connId(ssl 指针) → Session
    private final java.util.Map<Long, Session> sessions = new java.util.concurrent.ConcurrentHashMap<>();
    private volatile String pushToken = "";

    /** v1.37 P0-5: 与 push_logs 同 token 鉴权（目标进程启动时由 ModuleMain 调） */
    public void enablePushHome(String token) {
        this.pushToken = token == null ? "" : token;
        // v1.41 P0: 周期 flush——长连接（不关闭）数据也能推主进程，不依赖连接关闭事件
        ensurePeriodicFlush();
    }

    private volatile boolean flushThreadStarted = false;

    /** v1.41 P0: 每 5s flush 全部活跃会话到主进程（长连接场景 pcap 也能落盘/导出） */
    private synchronized void ensurePeriodicFlush() {
        if (flushThreadStarted) return;
        flushThreadStarted = true;
        Thread t = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(5000);
                    if (Config.get().pcapCapture && !pushToken.isEmpty()) {
                        flushAll();
                    }
                } catch (Throwable ignored) {
                    // 目标进程绝不能崩
                }
            }
        }, "pcap-periodic-flush");
        t.setDaemon(true);
        t.start();
    }

    private static class Session {
        String srcIp = "", dstIp = "";
        int srcPort = 0, dstPort = 0;
        long clientSeq, serverSeq;
        boolean init = false;
        java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream(8192);
        int packets = 0;
        long firstTs = System.currentTimeMillis();
    }

    /** native SSL 明文回调（NativeProbe.onNativeData 调用，仅 isSsl 且 pcapCapture 开） */
    public void feed(long connId, boolean isWrite, byte[] data, String socketInfo) {
        try {
            if (!Config.get().pcapCapture) return;
            if (data == null || data.length == 0) return;
            Session s = sessions.get(connId);
            if (s == null) {
                // 首包：解析四元组定方向。isWrite=true 本地→远端（src=本地 dst=远端）
                s = new Session();
                parseEndpoint(socketInfo, s);
                if (s.srcIp.isEmpty() || s.dstIp.isEmpty()) return; // 无法定位（IPv6/无 info）跳过
                if (!isIpv4(s.srcIp) || !isIpv4(s.dstIp)) return;   // v1.39 仅支持 IPv4 pcap
                long isn = (System.nanoTime() & 0x7fffffff) % 0xffff + 1000;
                s.clientSeq = isn;
                s.serverSeq = isn + 10000;
                s.init = true;
                sessions.put(connId, s);
                enforceTotalLimit();
            }
            if (!s.init) return;
            if (s.buf.size() >= MAX_SESSION) return; // 会话已满，停止追加（防 OOM）
            if (s.packets == 0 && !isWrite) {
                // 首个数据包是下行：方向反了（理论不会，SSL_write 先于 SSL_read），修正四元组
                String tmp = s.srcIp; s.srcIp = s.dstIp; s.dstIp = tmp;
                int tp = s.srcPort; s.srcPort = s.dstPort; s.dstPort = tp;
            }
            byte[] rec = buildRecord(s, isWrite, data);
            synchronized (s.buf) {
                if (s.buf.size() + rec.length > MAX_SESSION) return;
                s.buf.write(rec, 0, rec.length);
                s.packets++;
            }
        } catch (Throwable ignored) {
            // 目标进程绝不能崩
        }
    }

    /** 连接关闭：推送该会话 pcap 记录到主进程，清会话 */
    public void onConnClosed(long connId) {
        try {
            if (!Config.get().pcapCapture) return;
            Session s = sessions.remove(connId);
            if (s == null) return;
            byte[] body;
            synchronized (s.buf) {
                if (s.buf.size() == 0) return;
                body = s.buf.toByteArray();
            }
            flushChunk(body, connId);
        } catch (Throwable ignored) {
        }
    }

    /** 全部会话推主进程（UI「立即导出」用，目标进程在线时兜底） */
    public void flushAll() {
        try {
            if (!Config.get().pcapCapture) return;
            for (Long connId : new java.util.ArrayList<>(sessions.keySet())) {
                Session s = sessions.remove(connId);
                if (s == null) continue;
                byte[] body;
                synchronized (s.buf) {
                    if (s.buf.size() == 0) continue;
                    body = s.buf.toByteArray();
                }
                flushChunk(body, connId);
            }
        } catch (Throwable ignored) {
        }
    }

    // ================= 推送主进程（纯 Socket，同 LogStore.flushPush 模式）=================

    private void flushChunk(byte[] body, long connId) {
        try {
            java.net.Socket sock = new java.net.Socket();
            sock.setTcpNoDelay(true);
            sock.connect(new java.net.InetSocketAddress("127.0.0.1", 9900), 500);
            StringBuilder head = new StringBuilder();
            head.append("POST /api/pcap_chunk?conn=").append(connId).append(" HTTP/1.1\r\n")
                .append("Host: 127.0.0.1:9900\r\n")
                .append("Content-Type: application/octet-stream\r\n")
                .append("Content-Length: ").append(body.length).append("\r\n");
            if (!pushToken.isEmpty()) {
                head.append("X-Spy-Token: ").append(pushToken).append("\r\n");
            }
            head.append("Connection: close\r\n\r\n");
            java.io.OutputStream os = sock.getOutputStream();
            os.write(head.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
            os.write(body);
            os.flush();
            java.io.InputStream is = sock.getInputStream();
            byte[] tmp = new byte[128];
            long deadline = System.currentTimeMillis() + 1000;
            StringBuilder sb = new StringBuilder();
            while (System.currentTimeMillis() < deadline && is.read(tmp) != -1) {
                sb.append(new String(tmp, java.nio.charset.StandardCharsets.UTF_8).trim());
            }
            String resp = sb.toString();
            // v1.41 P0: pcap 推送失败留痕（401 等可诊断；同 push_logs 鉴权问题）
            if (resp.startsWith("HTTP/1.1 401") || resp.contains("401")) {
                try { DebugLog.get().log("PcapPush", "pcap_chunk 401 (token 不匹配/缺失) conn=" + connId); } catch (Throwable ignored) { }
            } else if (resp.startsWith("HTTP/1.1 200") || resp.contains("\"ok\":true")) {
                // ok
            } else {
                try { DebugLog.get().log("PcapPush", "pcap_chunk resp=" + resp); } catch (Throwable ignored) { }
            }
            try { is.close(); } catch (Throwable t2) { }
            try { os.close(); } catch (Throwable t2) { }
            try { sock.close(); } catch (Throwable t2) { }
        } catch (Throwable t) {
            // 主进程不在线：静默丢弃（UI 连目标进程时可重导）；v1.41 加 DebugLog 留痕
            try { DebugLog.get().log("PcapPush", "pcap_chunk fail: " + t.getClass().getSimpleName() + ": " + t.getMessage()); } catch (Throwable ignored) { }
        }
    }

    // ================= pcap 记录构造 =================

    private static long packetId = 0;

    /** 构造一条 pcap 记录（记录头 16B + 伪 IPv4 头 20B + 伪 TCP 头 20B + payload） */
    private static byte[] buildRecord(Session s, boolean isWrite, byte[] payload) {
        int totalLen = 20 + 20 + payload.length;
        byte[] rec = new byte[16 + totalLen];
        java.io.DataOutputStream d = new java.io.DataOutputStream(new java.io.ByteArrayOutputStream());
        // 记录头：时间戳（sec/usec）
        long now = System.currentTimeMillis();
        int tsSec = (int) (now / 1000);
        int tsUsec = (int) ((now % 1000) * 1000);
        putInt(rec, 0, tsSec);
        putInt(rec, 4, tsUsec);
        putInt(rec, 8, totalLen);
        putInt(rec, 12, totalLen);
        int off = 16;
        // ===== IPv4 头（20B）=====
        rec[off] = 0x45;                      // version 4, IHL 5
        rec[off + 1] = 0;                     // TOS
        putShort(rec, off + 2, totalLen);     // total length
        putShort(rec, off + 4, (short) ((packetId++) & 0xffff)); // identification
        putShort(rec, off + 6, 0x4000);       // flags: DF
        rec[off + 8] = 64;                    // TTL
        rec[off + 9] = 6;                     // protocol TCP
        putShort(rec, off + 10, 0);           // checksum（先 0 后算）
        ipToBytes(s.srcIp, rec, off + 12);
        ipToBytes(s.dstIp, rec, off + 16);
        putShort(rec, off + 10, (short) ipChecksum(rec, off, 20));
        off += 20;
        // ===== TCP 头（20B）=====
        int sport = isWrite ? s.srcPort : s.dstPort;
        int dport = isWrite ? s.dstPort : s.srcPort;
        long seq = isWrite ? s.clientSeq : s.serverSeq;
        long ack = isWrite ? s.serverSeq : s.clientSeq;
        putShort(rec, off, (short) sport);
        putShort(rec, off + 2, (short) dport);
        putInt(rec, off + 4, (int) seq);
        putInt(rec, off + 8, (int) ack);
        putShort(rec, off + 12, 0x5018);      // data offset 5, flags PSH|ACK
        putShort(rec, off + 14, 65535);       // window
        putShort(rec, off + 16, 0);           // checksum（后算）
        putShort(rec, off + 18, 0);           // urgent
        // TCP checksum（含伪头）
        putShort(rec, off + 16, (short) tcpChecksum(rec, off, 20 + payload.length,
                s.srcIp, s.dstIp));
        off += 20;
        System.arraycopy(payload, 0, rec, off, payload.length);
        // 更新 seq/ack
        if (isWrite) s.clientSeq += payload.length;
        else s.serverSeq += payload.length;
        return rec;
    }

    private static void putShort(byte[] b, int off, int v) {
        b[off] = (byte) ((v >> 8) & 0xff);
        b[off + 1] = (byte) (v & 0xff);
    }

    private static void putInt(byte[] b, int off, int v) {
        b[off] = (byte) ((v >> 24) & 0xff);
        b[off + 1] = (byte) ((v >> 16) & 0xff);
        b[off + 2] = (byte) ((v >> 8) & 0xff);
        b[off + 3] = (byte) (v & 0xff);
    }

    private static long sum(byte[] b, int off, int len) {
        long sum = 0;
        int i = off, end = off + len;
        while (i + 1 < end) {
            sum += ((b[i] & 0xff) << 8) | (b[i + 1] & 0xff);
            i += 2;
        }
        if (i < end) sum += (b[i] & 0xff) << 8;
        while ((sum >> 16) != 0) sum = (sum & 0xffff) + (sum >> 16);
        return sum;
    }

    private static int ipChecksum(byte[] b, int off, int len) {
        return (int) (0xffff & sum(b, off, len));
    }

    private static int tcpChecksum(byte[] b, int tcpOff, int tcpLen, String srcIp, String dstIp) {
        byte[] sip = ipToBytes(srcIp), dip = ipToBytes(dstIp);
        // 伪头：src(4) + dst(4) + 0 + proto(6) + tcpLen
        long s = 0;
        for (int i = 0; i < 4; i++) s += (sip[i] & 0xff) << 8;
        for (int i = 0; i < 4; i++) s += dip[i] & 0xff;
        s += 6;                    // protocol TCP
        s += tcpLen;               // TCP length
        s += sum(b, tcpOff, tcpLen);
        while ((s >> 16) != 0) s = (s & 0xffff) + (s >> 16);
        return (int) (0xffff & s);
    }

    /** 解析 "ip:port->ip:port" → Session 四元组 */
    private static void parseEndpoint(String socketInfo, Session s) {
        if (socketInfo == null || socketInfo.isEmpty()) return;
        int arrow = socketInfo.indexOf("->");
        if (arrow < 0) {
            // 兼容旧格式 "ip:port"：只能当 dst（远端）
            parseOne(socketInfo, s, false);
            return;
        }
        parseOne(socketInfo.substring(0, arrow), s, true);   // 本地
        parseOne(socketInfo.substring(arrow + 2), s, false); // 远端
    }

    private static void parseOne(String ep, Session s, boolean isLocal) {
        try {
            int colon = ep.lastIndexOf(':');
            if (colon < 0) return;
            String ip = ep.substring(0, colon);
            int port = Integer.parseInt(ep.substring(colon + 1));
            if (isLocal) { s.srcIp = ip; s.srcPort = port; }
            else { s.dstIp = ip; s.dstPort = port; }
        } catch (Throwable ignored) { }
    }

    private static boolean isIpv4(String ip) {
        if (ip == null || ip.isEmpty() || ip.indexOf(':') >= 0) return false;
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return false;
        for (String p : parts) {
            try {
                int v = Integer.parseInt(p);
                if (v < 0 || v > 255) return false;
            } catch (Throwable t) { return false; }
        }
        return true;
    }

    private static byte[] ipToBytes(String ip) {
        byte[] out = new byte[4];
        String[] parts = ip.split("\\.");
        for (int i = 0; i < 4 && i < parts.length; i++) {
            try { out[i] = (byte) Integer.parseInt(parts[i]); } catch (Throwable t) { out[i] = 0; }
        }
        return out;
    }

    private static void ipToBytes(String ip, byte[] out, int off) {
        byte[] b = ipToBytes(ip);
        System.arraycopy(b, 0, out, off, 4);
    }

    private void enforceTotalLimit() {
        // 总字节超限：丢最旧会话（简单策略：遍历移除直到达标）
        int total = 0;
        for (Session s : sessions.values()) total += s.buf.size();
        if (total <= MAX_TOTAL) return;
        long oldestTs = Long.MAX_VALUE;
        Long oldestKey = null;
        for (java.util.Map.Entry<Long, Session> e : sessions.entrySet()) {
            if (e.getValue().firstTs < oldestTs) { oldestTs = e.getValue().firstTs; oldestKey = e.getKey(); }
        }
        if (oldestKey != null) sessions.remove(oldestKey);
    }
}
