package com.dustinky.spyprobe;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * v7x: ClientHello SNI 嗅探（透明代理用）
 *
 * 透明模式（iptables REDIRECT）下客户端不知道有代理，直接发 TLS ClientHello。
 * 代理必须先读 ClientHello 提取 SNI（域名），才能签发对应证书。
 *
 * sniff() 读取第一个 TLS 记录（ClientHello），返回：
 *   - consumed: 已读的原始字节（回喂 SSLSocketFactory.createSocket(consumed)，
 *     避免重复读取）
 *   - sni: server_name 扩展里的域名；无 SNI 返回 null（用 SO_ORIGINAL_DST IP 兜底）
 *
 * 解析规则（RFC 8446/5246）：
 *   TLSRecord: type(1)=22 + version(2) + length(2)
 *   Handshake: msg_type(1)=1 + length(3) + client_version(2) + random(32)
 *              + session_id(1+len) + cipher_suites(2+len) + compression(1+len)
 *              + extensions(2+len) [TLS1.2/1.3]
 *   extension: type(2) + len(2) + data；type=0(server_name) → list(2) + name_type(1)=0 + name(2+len)
 */
public class TlsSniffer {

    public static class Result {
        public final byte[] consumed;
        public final String sni;
        public Result(byte[] consumed, String sni) {
            this.consumed = consumed;
            this.sni = sni;
        }
    }

    /** 读第一个 TLS 记录并解析 SNI。EOF/非 ClientHello 返回 null。 */
    public static Result sniff(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(512);
        int type = in.read();
        if (type == -1) return null;
        buf.write(type);
        if (type != 22) return null; // 不是 handshake 记录
        byte[] hdr = new byte[4];
        if (readFully(in, hdr) < 4) return null; // version(2) + length(2)
        buf.write(hdr, 0, 4);
        int len = ((hdr[2] & 0xff) << 8) | (hdr[3] & 0xff);
        if (len <= 0 || len > 64 * 1024) return null;
        byte[] body = new byte[len];
        if (readFully(in, body) < len) return null;
        buf.write(body, 0, len);

        if ((body[0] & 0xff) != 1) return null; // msg_type != ClientHello

        // v1.74.13 P0-15: TLS 1.3 ClientHello 分片（RFC 8446 4.2.3，最多 2 个 record）。
        //   根因实锤（NAS Conscrypt 2.5.2 复刻）：msgLen 字段 = payload 长度（不含 4B header）。
        //   record 1 只含消息开头（msgLen > have）→ Conscrypt unwrap 后 NEED_UNWRAP 等 record 2
        //   → TlsSniffer 只读 record 1 → 握手挂死/EOF（真机 254B ClientHello = 分片 record 1）。
        //   修复：读 record 2 → 合并 payload → 重写为单 record（len = 4+msgLen）。
        //   Conscrypt 对完整单 record ClientHello 正常处理（NEED_WRAP + ServerHello）。
        int msgLen = ((body[1] & 0xff) << 16) | ((body[2] & 0xff) << 8) | (body[3] & 0xff);
        int have = body.length - 4;
        if (msgLen > have) {
            // need = 剩余 payload = msgLen - have（record 1 已读 payload）
            int need = msgLen - have;
            // 读第二个 record（合法分片：type=22，body 含剩余 payload）
            int type2 = in.read();
            if (type2 == 22) {
                byte[] hdr2 = new byte[4];
                if (readFully(in, hdr2) == 4) {
                    int len2 = ((hdr2[2] & 0xff) << 8) | (hdr2[3] & 0xff);
                    if (len2 >= need && len2 <= 64 * 1024) {
                        byte[] body2 = new byte[len2];
                        if (readFully(in, body2) == len2) {
                            // 合并 payload（record1 body[4:] + body2 前 need 字节）
                            byte[] payload = new byte[msgLen];
                            System.arraycopy(body, 4, payload, 0, body.length - 4);
                            System.arraycopy(body2, 0, payload, body.length - 4, need);
                            // 重写为单 record：22 + ver + len(4+msgLen) + header(4) + payload(msgLen)
                            int newLen = 4 + msgLen;
                            buf.reset();
                            buf.write(22);
                            buf.write(hdr[0]); buf.write(hdr[1]); // 保持 record1 的 version
                            buf.write((newLen >> 8) & 0xff); buf.write(newLen & 0xff);
                            buf.write(body, 0, 4);   // handshake header（msgLen 字段不变）
                            buf.write(payload, 0, msgLen);
                            byte[] merged = new byte[newLen];
                            System.arraycopy(body, 0, merged, 0, 4);
                            System.arraycopy(payload, 0, merged, 4, msgLen);
                            body = merged;
                        }
                    }
                }
            }
        } else if (msgLen < have) {
            // handshake payload < record1 body 剩余：record 1 含多个消息（正常，不处理）
        }
        if (msgLen > have) {
            MitmLog.log("TlsSniffer ClientHello fragmented msgLen=" + msgLen + " body1=" + have
                    + " -> single=" + (4 + msgLen));
        } else {
            MitmLog.log("TlsSniffer ClientHello msgLen=" + msgLen + " body=" + have + " (not fragmented)");
        }
        int pos = 4 + 2 + 32; // handshake hdr(4) + client_version(2) + random(32)
        if (pos >= body.length) return null;
        int sidLen = body[pos] & 0xff; pos += 1;
        if (pos + sidLen > body.length) return null;
        pos += sidLen;
        if (pos + 2 > body.length) return null;
        int csLen = ((body[pos] & 0xff) << 8) | (body[pos + 1] & 0xff); pos += 2;
        if (pos + csLen > body.length) return null;
        pos += csLen;
        if (pos + 1 > body.length) return null;
        int cmLen = body[pos] & 0xff; pos += 1;
        if (pos + cmLen > body.length) return null;
        pos += cmLen;
        if (pos + 2 > body.length) return null;
        int extLen = ((body[pos] & 0xff) << 8) | (body[pos + 1] & 0xff); pos += 2;
        int end = Math.min(pos + extLen, body.length);

        String sni = null;
        while (pos + 4 <= end) {
            int extType = ((body[pos] & 0xff) << 8) | (body[pos + 1] & 0xff); pos += 2;
            int dataLen = ((body[pos] & 0xff) << 8) | (body[pos + 1] & 0xff); pos += 2;
            if (pos + dataLen > end) break;
            if (extType == 0 && dataLen >= 5) { // server_name
                int listLen = ((body[pos] & 0xff) << 8) | (body[pos + 1] & 0xff);
                int p2 = pos + 2;
                if (p2 + 3 <= end && listLen >= 3) {
                    int nameType = body[p2] & 0xff; p2 += 1;
                    int nameLen = ((body[p2] & 0xff) << 8) | (body[p2 + 1] & 0xff); p2 += 2;
                    if (nameType == 0 && p2 + nameLen <= end && nameLen > 0) {
                        sni = new String(body, p2, nameLen, StandardCharsets.US_ASCII);
                    }
                }
            }
            pos += dataLen;
        }
        return new Result(buf.toByteArray(), sni);
    }

    private static int readFully(InputStream in, byte[] b) throws IOException {
        int off = 0;
        while (off < b.length) {
            int n = in.read(b, off, b.length - off);
            if (n == -1) break;
            off += n;
        }
        return off;
    }
}
