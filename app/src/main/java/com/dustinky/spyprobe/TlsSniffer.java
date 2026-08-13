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
