package com.dustinky.spyprobe;

import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * v1.67: TLS 1.3 内部解密器（Flutter dart:io BoringSSL 默认 TLS 1.3）
 *
 * 数据流：
 *   libc send/recv 密文（onNativeData isSsl=false，TLS record 层）
 *   + KeyLogStore traffic secrets（nativeKeylog 注入）
 *   → 按连接重组 record → ClientHello 明文解析 client_random → 关联密钥
 *   → TLS 1.3 AEAD 解密应用数据 → 明文 HTTP 喂 TlsHttpParser
 *
 * TLS 1.3 密钥（RFC 8446）：
 *   key = HKDF-Expand-Label(secret, "key", "", key_len)
 *   iv  = HKDF-Expand-Label(secret, "iv",  "", 12)
 *   nonce = fixed_iv XOR seq（seq 每方向从 0 递增，大端 8 字节）
 *   aad  = record header（5 字节：type 23 + 0x0303 + length）
 *   AEAD 输出 = plaintext || tag(16B)，解密后首字节为 inner content type
 *
 * 说明：
 *   - 只解 TLS 1.3 应用流量（CLIENT_TRAFFIC_SECRET_0 / SERVER_TRAFFIC_SECRET_0）
 *   - 加密后的 Finished 也是外层 type=23，解出 inner type=22(handshake) 时忽略（seq 照常+1）
 *   - TLS 1.2 不内部解（需 server_random + 完整握手状态机），keylog 文件导出给 Wireshark
 */
public class TlsDecryptor {
    private static final TlsDecryptor INSTANCE = new TlsDecryptor();
    public static TlsDecryptor get() { return INSTANCE; }

    private static final int RECORD_HEADER_LEN = 5;
    private static final int CONTENT_APPLICATION_DATA = 23;
    private static final int CONTENT_HANDSHAKE = 22;

    // 连接会话状态：connKey = socket fd 或 ssl 指针
    static class ConnSession {
        long connId = 0;
        String socketInfo = "";
        byte[] recvBuf = new byte[0];   // 上行重组缓冲
        byte[] sendBuf = new byte[0];   // 下行重组缓冲
        String clientRandomHex = "";    // 从 ClientHello 解析
        long clientSeq = 0;             // 客户端应用 record 序号
        long serverSeq = 0;
        boolean gotClientHello = false;
        boolean clientKeyReady = false;
        boolean serverKeyReady = false;
        long lastActive = System.currentTimeMillis();
    }

    private final Map<String, ConnSession> conns = new ConcurrentHashMap<>();
    private volatile boolean enabled = false;

    /** 明文回调（NativeProbe 注入，喂 TlsHttpParser） */
    public interface PlaintextListener {
        void onPlaintext(long connId, boolean isWrite, byte[] plain, String socketInfo);
    }

    private PlaintextListener listener = null;

    public void setListener(PlaintextListener l) { listener = l; }
    public void setEnabled(boolean e) { enabled = e; }
    public boolean isEnabled() { return enabled; }

    // ================= 对外入口（NativeProbe.onNativeData 调用） =================

    /**
     * 喂密文 record。connKey 与 TlsHttpParser 一致（id）。
     * isWrite=true 客户端→服务端；false 服务端→客户端。
     */
    public void feed(long connId, boolean isWrite, byte[] data, String socketInfo) {
        if (!enabled && !Config.get().internalDecrypt) return;
        if (data == null || data.length == 0) return;
        enabled = true; // 激活后保持（Config 关闭时由 onNativeData 前置判断拦截）
        try {
            String key = connKeyOf(connId, socketInfo);
            ConnSession cs = conns.get(key);
            if (cs == null) {
                cs = new ConnSession();
                cs.connId = connId;
                cs.socketInfo = socketInfo != null ? socketInfo : "";
                conns.put(key, cs);
                enforceLimit();
            }
            cs.lastActive = System.currentTimeMillis();
            byte[] buf = isWrite ? cs.sendBuf : cs.recvBuf;
            // 追加数据到重组缓冲
            byte[] merged = new byte[buf.length + data.length];
            System.arraycopy(buf, 0, merged, 0, buf.length);
            System.arraycopy(data, 0, merged, buf.length, data.length);
            byte[] out = processRecords(cs, isWrite, merged);
            if (isWrite) cs.sendBuf = out; else cs.recvBuf = out;
        } catch (Throwable ignored) {
        }
    }

    private String connKeyOf(long id, String socketInfo) {
        if (socketInfo != null && !socketInfo.isEmpty()) return socketInfo;
        return "#" + id;
    }

    // ================= record 重组 + 解密 =================

    /**
     * 处理缓冲内完整 record，返回剩余未完成的字节。
     * 解密出的明文（inner type=23）回调 onPlaintext。
     */
    private byte[] processRecords(ConnSession cs, boolean isWrite, byte[] buf) {
        int off = 0;
        while (buf.length - off >= RECORD_HEADER_LEN) {
            int type = buf[off] & 0xFF;
            int len = ((buf[off + 3] & 0xFF) << 8) | (buf[off + 4] & 0xFF);
            if (len > 0x4000) break; // 非法长度，等待更多数据或丢弃
            int total = RECORD_HEADER_LEN + len;
            if (buf.length - off < total) break; // record 不完整，等待
            byte[] record = Arrays.copyOfRange(buf, off, off + total);
            processOneRecord(cs, isWrite, record);
            off += total;
        }
        if (off == 0) return buf;
        return Arrays.copyOfRange(buf, off, buf.length);
    }

    private void processOneRecord(ConnSession cs, boolean isWrite, byte[] record) {
        int type = record[0] & 0xFF;
        int len = ((record[3] & 0xFF) << 8) | (record[4] & 0xFF);
        byte[] payload = Arrays.copyOfRange(record, RECORD_HEADER_LEN, record.length);

        // TLS 1.3 ClientHello 是明文 record（type=22 handshake 且未加密阶段）
        // 但 TLS 1.3 中加密后的握手消息外层 type=23。明文 ClientHello 的特征：
        // type=22, version=0x0303, payload[0]=0x01(ClientHello)
        if (type == CONTENT_HANDSHAKE && payload.length > 4 && (payload[0] & 0xFF) == 0x01) {
            parseClientHello(cs, payload);
            return;
        }
        // 解密应用数据（TLS 1.3：外层 type=23 都是加密的，含加密 Finished + app data）
        if (type == CONTENT_APPLICATION_DATA) {
            boolean clientDir = isWrite;
            if (clientDir) {
                if (cs.clientKeyReady) {
                    byte[] pt = decryptRecord(cs, true, record);
                    if (pt != null) {
                        cs.clientSeq++;
                        handlePlaintext(cs, true, pt);
                    }
                }
            } else {
                if (cs.serverKeyReady) {
                    byte[] pt = decryptRecord(cs, false, record);
                    if (pt != null) {
                        cs.serverSeq++;
                        handlePlaintext(cs, false, pt);
                    }
                }
            }
        }
    }

    // ClientHello: 握手消息头(4B) + version(2B) + random(32B)
    private void parseClientHello(ConnSession cs, byte[] payload) {
        if (payload.length < 4 + 2 + 32) return;
        // payload[0]=1(ClientHello), payload[1..3]=length, payload[4..5]=version(0x0303)
        byte[] random = Arrays.copyOfRange(payload, 6, 6 + 32);
        String crHex = bytesToHex(random);
        cs.clientRandomHex = crHex;
        cs.gotClientHello = true;
        KeyLogStore.SessionKeys keys = KeyLogStore.get().get(crHex);
        if (keys != null) {
            if (keys.clientAppTraffic != null && !keys.clientAppTraffic.isEmpty()) {
                cs.clientKeyReady = prepareKey(keys.clientAppTraffic);
            }
            if (keys.serverAppTraffic != null && !keys.serverAppTraffic.isEmpty()) {
                cs.serverKeyReady = prepareKey(keys.serverAppTraffic);
            }
        }
    }

    // 每连接缓存的密钥（按方向）
    private boolean prepareKey(String secretHex) {
        try {
            byte[] secret = hexToBytes(secretHex);
            return secret.length >= 32;
        } catch (Throwable t) {
            return false;
        }
    }

    private static byte[] hkdfExpandLabel(byte[] secret, String label, int outLen) throws Exception {
        // HKDF-Expand(secret, HkdfLabel, outLen)
        byte[] labelBytes = ("tls13 " + label).getBytes("UTF-8");
        // HkdfLabel = uint16 length || opaque label<7..255> || opaque context<0..255>
        int lblLen = labelBytes.length;
        byte[] info = new byte[2 + 1 + lblLen + 1];
        info[0] = (byte) (outLen >> 8);
        info[1] = (byte) outLen;
        info[2] = (byte) lblLen;
        System.arraycopy(labelBytes, 0, info, 3, lblLen);
        info[3 + lblLen] = 0; // context 空
        // HKDF-Expand = T(1) || T(2) ...; T(i) = HMAC(secret, T(i-1) || info || i)
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret, "HmacSHA256"));
        byte[] t = new byte[0];
        byte[] out = new byte[outLen];
        int o = 0;
        byte counter = 1;
        while (o < outLen) {
            mac.reset();
            mac.update(t);
            mac.update(info);
            mac.update(counter);
            t = mac.doFinal();
            int n = Math.min(t.length, outLen - o);
            System.arraycopy(t, 0, out, o, n);
            o += n;
            counter++;
        }
        return out;
    }

    // 解密一个 TLS 1.3 record。clientDir=true 客户端方向。
    private byte[] decryptRecord(ConnSession cs, boolean clientDir, byte[] record) {
        try {
            String secretHex = clientDir ? KeyLogStore.get().get(cs.clientRandomHex).clientAppTraffic
                                         : KeyLogStore.get().get(cs.clientRandomHex).serverAppTraffic;
            if (secretHex == null || secretHex.isEmpty()) return null;
            byte[] secret = hexToBytes(secretHex);
            long seq = clientDir ? cs.clientSeq : cs.serverSeq;

            // key 长度按 secret 长度：SHA-256 → 32B secret → AES-128-GCM key 16B
            // SHA-384 → 48B secret → AES-256-GCM key 32B
            int keyLen = secret.length >= 48 ? 32 : 16;
            byte[] key = hkdfExpandLabel(secret, "key", keyLen);
            byte[] iv = hkdfExpandLabel(secret, "iv", 12);

            // nonce = iv XOR seq（seq 大端 8 字节，低 8 字节异或）
            byte[] nonce = Arrays.copyOf(iv, iv.length);
            for (int i = 0; i < 8; i++) {
                nonce[nonce.length - 1 - i] ^= (byte) ((seq >> (8 * i)) & 0xFF);
            }

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(128, nonce));
            cipher.updateAAD(record, 0, RECORD_HEADER_LEN); // aad = record header
            byte[] pt = cipher.doFinal(Arrays.copyOfRange(record, RECORD_HEADER_LEN, record.length));
            return pt;
        } catch (Throwable t) {
            return null;
        }
    }

    // 解密后明文处理：首字节 inner content type
    private void handlePlaintext(ConnSession cs, boolean clientDir, byte[] pt) {
        if (pt == null || pt.length < 1) return;
        int innerType = pt[0] & 0xFF;
        if (innerType == CONTENT_HANDSHAKE) return; // 加密 Finished 等，忽略
        if (innerType == CONTENT_APPLICATION_DATA) {
            byte[] app = Arrays.copyOfRange(pt, 1, pt.length);
            if (app.length > 0) {
                onPlaintext(cs, clientDir, app);
            }
        }
    }

    // 明文回调 → 喂 TlsHttpParser（结构化 HttpEntry 链路）
    private void onPlaintext(ConnSession cs, boolean clientDir, byte[] plain) {
        try {
            if (listener != null) {
                listener.onPlaintext(cs.connId, clientDir, plain, cs.socketInfo);
            }
        } catch (Throwable ignored) {
        }
    }

    private long csKeyToId(ConnSession cs) {
        return cs.connId;
    }

    private void enforceLimit() {
        if (conns.size() > 128) {
            // 淘汰最旧
            long oldest = Long.MAX_VALUE;
            String oldestKey = null;
            for (Map.Entry<String, ConnSession> e : conns.entrySet()) {
                if (e.getValue().lastActive < oldest) {
                    oldest = e.getValue().lastActive;
                    oldestKey = e.getKey();
                }
            }
            if (oldestKey != null) conns.remove(oldestKey);
        }
    }

    public void clear() {
        conns.clear();
    }

    // ================= 工具 =================

    private static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(Character.forDigit((x >> 4) & 0xF, 16));
            sb.append(Character.forDigit(x & 0xF, 16));
        }
        return sb.toString();
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        if (len % 2 != 0) return new byte[0];
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    | Character.digit(hex.charAt(i + 1), 16));
        }
        return out;
    }
}
