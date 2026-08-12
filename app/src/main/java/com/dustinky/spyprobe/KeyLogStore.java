package com.dustinky.spyprobe;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * v1.67: Flutter/libssl keylog 结构化存储
 *
 * BoringSSL keylog 回调输出两种行：
 *   - TLS 1.2:  CLIENT_RANDOM <64hex client_random> <96hex master_secret>
 *   - TLS 1.3:  CLIENT_HANDSHAKE_TRAFFIC_SECRET / SERVER_HANDSHAKE_TRAFFIC_SECRET /
 *               CLIENT_TRAFFIC_SECRET_0 / SERVER_TRAFFIC_SECRET_0 <64hex> <96hex>
 *
 * 用途：
 *   1. TlsDecryptor 内部解密：CLIENT_RANDOM + 密文 → 明文进实时日志
 *   2. 文件导出：标准 keylog 格式，Wireshark 直接导入解密 HTTPS
 */
public class KeyLogStore {
    private static final KeyLogStore INSTANCE = new KeyLogStore();
    public static KeyLogStore get() { return INSTANCE; }

    // client_random(hex) → 会话密钥
    private final Map<String, SessionKeys> sessions = new ConcurrentHashMap<>();
    // 完整原始行（文件导出用）
    private final List<String> rawLines = new ArrayList<>();
    private final Object lock = new Object();

    public static class SessionKeys {
        public String clientRandomHex = "";
        public String masterSecretHex = "";   // TLS 1.2
        public String clientHsTraffic = "";   // TLS 1.3
        public String serverHsTraffic = "";
        public String clientAppTraffic = "";
        public String serverAppTraffic = "";
        public long firstSeen = 0;
    }

    public void feed(String line) {
        if (line == null || line.isEmpty()) return;
        synchronized (lock) {
            rawLines.add(line);
            if (rawLines.size() > 2000) rawLines.remove(0); // 防 OOM
        }
        try {
            String[] parts = line.split(" ");
            if (parts.length < 3) return;
            String type = parts[0];
            String cr = parts[1];
            String secret = parts[2];
            SessionKeys sk = sessions.get(cr);
            if (sk == null) {
                sk = new SessionKeys();
                sk.clientRandomHex = cr;
                sk.firstSeen = System.currentTimeMillis();
                sessions.put(cr, sk);
            }
            switch (type) {
                case "CLIENT_RANDOM":
                    sk.masterSecretHex = secret;
                    break;
                case "CLIENT_HANDSHAKE_TRAFFIC_SECRET":
                    sk.clientHsTraffic = secret;
                    break;
                case "SERVER_HANDSHAKE_TRAFFIC_SECRET":
                    sk.serverHsTraffic = secret;
                    break;
                case "CLIENT_TRAFFIC_SECRET_0":
                    sk.clientAppTraffic = secret;
                    break;
                case "SERVER_TRAFFIC_SECRET_0":
                    sk.serverAppTraffic = secret;
                    break;
            }
        } catch (Throwable ignored) {
        }
    }

    /** 按 client_random 取会话（TlsDecryptor 用） */
    public SessionKeys get(String clientRandomHex) {
        return sessions.get(clientRandomHex);
    }

    public int sessionCount() { return sessions.size(); }
    public int lineCount() {
        synchronized (lock) { return rawLines.size(); }
    }

    /** 标准 keylog 文件内容（Wireshark 直接可导） */
    public String toKeylogFileContent() {
        StringBuilder sb = new StringBuilder();
        sb.append("# SpyProbe v1.67 keylog export\n");
        sb.append("# 导入 Wireshark: 首选项 → Protocols → TLS → (Pre)-Master-Secret log filename 选择本文件\n");
        sb.append("# 然后重新抓包/导入 pcap，HTTPS 明文自动解密\n\n");
        synchronized (lock) {
            for (String line : rawLines) {
                sb.append(line).append('\n');
            }
        }
        return sb.toString();
    }

    /** 导出到文件，返回路径 */
    public File exportToFile() {
        File dir = new File(android.os.Environment.getExternalStorageDirectory(), "SpyProbe");
        if (!dir.exists()) dir.mkdirs();
        File f = new File(dir, "sslkeylog_" + System.currentTimeMillis() + ".log");
        try (FileOutputStream fos = new FileOutputStream(f)) {
            fos.write(toKeylogFileContent().getBytes(StandardCharsets.UTF_8));
            return f;
        } catch (IOException e) {
            return null;
        }
    }

    public void clear() {
        sessions.clear();
        synchronized (lock) { rawLines.clear(); }
    }
}
