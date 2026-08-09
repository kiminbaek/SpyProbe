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
            DebugLog.get().log("Keystore", "install(" + phase + ") skipped: keystoreCapture == false");
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
                            LogStore.get().log(TAG, "[getPrivateKey] alias=" + chain.getArg(0)
                                    + " algo=" + k.getAlgorithm()
                                    + " format=" + k.getFormat());
                            LogStore.get().log(TAG, "[stack]\n" + MethodProbe.stack(8));
                        } catch (Throwable t) { }
                    }
                    return r;
                });
                LogStore.get().log(TAG, "[" + phase + "] hooked KeyStore.getPrivateKey");
            } catch (Throwable t) { }

            // getCertificate(String alias) —— 单证书
            try {
                Method m = KeyStore.class.getMethod("getCertificate", String.class);
                module.hook(m).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().keystoreCapture && r instanceof X509Certificate) {
                        try {
                            LogStore.get().log(TAG, "[getCertificate] alias=" + chain.getArg(0) + "\n"
                                    + certSummary((X509Certificate) r));
                        } catch (Throwable t) { }
                    }
                    return r;
                });
                LogStore.get().log(TAG, "[" + phase + "] hooked KeyStore.getCertificate");
            } catch (Throwable t) { }

            // getCertificateChain(String alias) —— 证书链
            try {
                Method m = KeyStore.class.getMethod("getCertificateChain", String.class);
                module.hook(m).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().keystoreCapture && r instanceof java.security.cert.Certificate[]) {
                        try {
                            java.security.cert.Certificate[] arr = (java.security.cert.Certificate[]) r;
                            StringBuilder sb = new StringBuilder("[getCertificateChain] alias=")
                                    .append(chain.getArg(0)).append(" len=").append(arr.length);
                            for (int i = 0; i < arr.length && i < 5; i++) {
                                if (arr[i] instanceof X509Certificate) {
                                    sb.append("\n  #").append(i).append(" ").append(certOneLine((X509Certificate) arr[i]));
                                }
                            }
                            LogStore.get().log(TAG, sb.toString());
                        } catch (Throwable t) { }
                    }
                    return r;
                });
                LogStore.get().log(TAG, "[" + phase + "] hooked KeyStore.getCertificateChain");
            } catch (Throwable t) { }

            LogStore.get().log(TAG, "[" + phase + "] KeystoreProbe installed (mTLS 证书 dump)");
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] KeystoreProbe install fail: " + t);
        }
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
