package com.dustinky.spyprobe;

import java.lang.reflect.Method;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.MessageDigest;

import io.github.libxposed.api.XposedModule;

/**
 * v1.38 P0-4: 双向认证证书 dump（hooker keystore_dump.js 借鉴）
 *
 * 场景：目标 App 做 mTLS（双向认证）时使用客户端证书（KeyStore alias 里的私钥+证书链），
 * 抓包需要拿到该证书才能还原/重放客户端身份。
 *
 * 能力：
 *   - hook KeyStore.getPrivateKey(alias)     → 记 alias + 密钥算法
 *   - hook KeyStore.getCertificate(alias)    → 记证书（主题/签发者/有效期/SHA-256 指纹）
 *   - hook KeyStore.getCertificateChain(alias) → 记证书链（每张证书摘要）
 *
 * 说明：完整导出 p12 需要 KeyStore 访问密码（应用私密存储，模块无权限），
 * 本模块先 dump 证书信息到日志供人工分析；指纹可用来比对 adb 导出的 p12。
 * 开关：Config.keystoreCapture（默认关，防刷屏——证书访问频率低但每次日志较长）。
 */
public class KeystoreProbe {

    static final String TAG = "SpyProbe.Keystore";

    private final XposedModule module;

    public KeystoreProbe(XposedModule module) {
        this.module = module;
    }

    public void install(String phase) {
        if (!Config.get().keystoreCapture) {
            DebugLog.get().logNoMirror("Keystore", "install(" + phase + ") skipped: keystoreCapture == false");
            return;
        }
        try {
            // getPrivateKey(String alias) —— 客户端私钥访问
            try {
                Method m = KeyStore.class.getMethod("getPrivateKey", String.class);
                module.hook(m).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().keystoreCapture && r instanceof Key) {
                        try {
                            Key k = (Key) r;
                            logCertEvent("getPrivateKey", String.valueOf(chain.getArg(0)),
                                    "algo=" + k.getAlgorithm() + " format=" + k.getFormat(),
                                    MethodProbe.stack(8));
                        } catch (Throwable t) { }
                    }
                    return r;
                });
                DebugLog.get().logNoMirror(TAG, "[" + phase + "] hooked KeyStore.getPrivateKey");
            } catch (Throwable t) { }

            // getCertificate(String alias) —— 单证书
            try {
                Method m = KeyStore.class.getMethod("getCertificate", String.class);
                module.hook(m).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().keystoreCapture && r instanceof X509Certificate) {
                        try {
                            X509Certificate c = (X509Certificate) r;
                            logCertEvent("getCertificate", String.valueOf(chain.getArg(0)),
                                    certOneLine(c), certSummary(c));
                        } catch (Throwable t) { }
                    }
                    return r;
                });
                DebugLog.get().logNoMirror(TAG, "[" + phase + "] hooked KeyStore.getCertificate");
            } catch (Throwable t) { }

            // getCertificateChain(String alias) —— 证书链
            try {
                Method m = KeyStore.class.getMethod("getCertificateChain", String.class);
                module.hook(m).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().keystoreCapture && r instanceof java.security.cert.Certificate[]) {
                        try {
                            java.security.cert.Certificate[] arr = (java.security.cert.Certificate[]) r;
                            StringBuilder sb = new StringBuilder("len=").append(arr.length);
                            for (int i = 0; i < arr.length && i < 5; i++) {
                                if (arr[i] instanceof X509Certificate) {
                                    sb.append("\n  #").append(i).append(" ").append(certOneLine((X509Certificate) arr[i]));
                                }
                            }
                            logCertEvent("getCertificateChain", String.valueOf(chain.getArg(0)),
                                    "chain len=" + arr.length, sb.toString());
                        } catch (Throwable t) { }
                    }
                    return r;
                });
                DebugLog.get().logNoMirror(TAG, "[" + phase + "] hooked KeyStore.getCertificateChain");
            } catch (Throwable t) { }

            DebugLog.get().logNoMirror(TAG, "[" + phase + "] KeystoreProbe installed (mTLS 证书 dump)");
        } catch (Throwable t) {
            DebugLog.get().logNoMirror(TAG, "[" + phase + "] KeystoreProbe install fail: " + t);
        }
    }

    /** v1.58: mTLS 证书访问 → 结构化 CERT 事件（卡片 + 详情页）。
     *  抓包价值：双向认证需要客户端证书，dump 证书信息供人工分析/比对 adb p12。 */
    private static void logCertEvent(String op, String alias, String summary, String detail) {
        try {
            long eid = EventStore.get().nextId();
            String msg = "[EVT#" + eid + "][" + op + "] alias=" + alias
                    + (summary == null || summary.isEmpty() ? "" : " " + summary);
            LogStore.get().log(TAG, msg);
            org.json.JSONObject payload = new org.json.JSONObject();
            payload.put("op", op == null ? "" : op);
            payload.put("alias", alias == null ? "" : alias);
            payload.put("summary", summary == null ? "" : summary);
            payload.put("detail", detail == null ? "" : detail);
            String title = op + " alias=" + alias;
            if (title.length() > 90) title = title.substring(0, 90) + "…";
            EventStore.get().add(new SpyEvent("CERT", eid, System.currentTimeMillis(),
                    title, payload, msg, ""));
        } catch (Throwable t) { /* 结构化失败不影响文本日志 */ }
    }

    /** 证书完整摘要（主题/签发者/有效期/指纹） */
    private static String certSummary(X509Certificate c) {
        StringBuilder sb = new StringBuilder();
        try { sb.append("  subject=").append(c.getSubjectX500Principal().getName()).append("\n"); } catch (Throwable t) { }
        try { sb.append("  issuer=").append(c.getIssuerX500Principal().getName()).append("\n"); } catch (Throwable t) { }
        try { sb.append("  valid=").append(c.getNotBefore()).append(" ~ ").append(c.getNotAfter()).append("\n"); } catch (Throwable t) { }
        try { sb.append("  serial=").append(c.getSerialNumber()).append("\n"); } catch (Throwable t) { }
        try { sb.append("  sha256=").append(sha256(c.getEncoded())); } catch (Throwable t) { }
        return sb.toString();
    }

    /** 单行摘要（链展示用） */
    private static String certOneLine(X509Certificate c) {
        StringBuilder sb = new StringBuilder();
        try { sb.append(c.getSubjectX500Principal().getName()); } catch (Throwable t) { sb.append("?"); }
        try {
            sb.append(" sha256=").append(sha256(c.getEncoded()));
        } catch (Throwable t) { }
        return sb.toString();
    }

    /** 证书 SHA-256 指纹（hex，冒号分隔） */
    private static String sha256(byte[] der) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(der);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < d.length; i++) {
                if (i > 0) sb.append(':');
                sb.append(String.format("%02X", d[i]));
            }
            return sb.toString();
        } catch (Throwable t) {
            return "?";
        }
    }
}
