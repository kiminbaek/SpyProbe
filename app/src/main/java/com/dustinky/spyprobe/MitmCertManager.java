package com.dustinky.spyprobe;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.ConcurrentHashMap;

/**
 * v7x: MITM 动态证书管理器（BouncyCastle 实现）
 *
 * 职责：
 *   - 首次启动生成自签 CA（RSA 2048 / 10 年 / CN=SpyProbe MITM CA）
 *   - 为每个目标 host 动态签发叶子证书（RSA 2048 / 30 天 / SAN=host）
 *   - 持久化：mitm_ca/{ca_key.pem, ca_cert.pem, hosts/<host>.p12}
 *   - 导出 CA PEM（装系统 CA / 生成 Magisk 模块用）
 *
 * 设计约束：
 *   - 纯 Java + BouncyCastle（bcprov-jdk18on + bcpkix-jdk18on），不依赖 Android API
 *     → 可在 NAS JVM 直接编译冒烟
 *   - 不调用 Security.addProvider（Android 自带旧版 BC 的 "BC" 会冲突）；
 *     全部走 builder API 传显式 provider 实例
 *   - 线程安全：host 证书缓存 ConcurrentHashMap，生成加 per-host 锁
 */
public class MitmCertManager {

    private static final String TAG = "SpyProbe.MitmCert";
    private static final String PROVIDER_NAME = "BC";

    // CA 配置
    private static final String CA_CN = "SpyProbe MITM CA";
    private static final int CA_YEARS = 10;
    // 叶子证书
    private static final int LEAF_DAYS = 30;
    private static final int KEY_BITS = 2048;

    private final File dir;          // files/mitm_ca/
    private final File hostsDir;     // files/mitm_ca/hosts/
    private final File caKeyPem;
    private final File caCertPem;

    private PrivateKey caKey;
    private X509Certificate caCert;
    private final ConcurrentHashMap<String, KeyStore> hostStoreCache = new ConcurrentHashMap<>();

    /** 单例（主进程） */
    private static volatile MitmCertManager instance;

    public static MitmCertManager get() {
        return instance;
    }

    public static MitmCertManager init(File filesDir) {
        instance = new MitmCertManager(new File(filesDir, "mitm_ca"));
        return instance;
    }

    public MitmCertManager(File dir) {
        this.dir = dir;
        this.hostsDir = new File(dir, "hosts");
        this.caKeyPem = new File(dir, "ca_key.pem");
        this.caCertPem = new File(dir, "ca_cert.pem");
    }

    // ===== 初始化 =====

    /** 确保 CA 存在（不存在则生成）。失败返回 false，调用方应禁用代理并提示。 */
    public synchronized boolean ensureCa() {
        try {
            if (caKey != null && caCert != null) return true;
            if (caKeyPem.exists() && caCertPem.exists()) {
                loadCaFromDisk();
                return true;
            }
            generateCa();
            saveCaToDisk();
            return true;
        } catch (Throwable t) {
            MitmLog.log(TAG + " ensureCa FAIL: " + t);
            return false;
        }
    }

    /** CA 是否就绪（有内存态或磁盘态） */
    public boolean isReady() {
        return (caKey != null && caCert != null) || (caKeyPem.exists() && caCertPem.exists());
    }

    public X509Certificate caCert() {
        ensureCa();
        return caCert;
    }

    public File caDir() {
        return dir;
    }

    // ===== 证书生成 =====

    private void generateCa() throws Exception {
        KeyPair kp = genKeyPair();
        Date notBefore = new Date(System.currentTimeMillis() - 24 * 3600 * 1000L);
        Date notAfter = new Date(System.currentTimeMillis() + (long) CA_YEARS * 365L * 24 * 3600 * 1000L);
        X500Name name = new X500Name("CN=" + CA_CN + ",O=SpyProbe");
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                name, randSerial(), notBefore, notAfter, name, kp.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        b.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(new BouncyCastleProvider()).build(kp.getPrivate());
        X509CertificateHolder holder = b.build(signer);
        this.caKey = kp.getPrivate();
        this.caCert = new JcaX509CertificateConverter()
                .setProvider(new BouncyCastleProvider()).getCertificate(holder);
        caCert.verify(caCert.getPublicKey()); // 自签校验
    }

    /** 为目标 host 生成（或取缓存）叶子证书 KeyStore（PKCS12，含私钥+证书链） */
    public KeyStore hostKeyStore(String host) throws Exception {
        String key = host.toLowerCase();
        KeyStore cached = hostStoreCache.get(key);
        if (cached != null) return cached;
        synchronized (this) {
            cached = hostStoreCache.get(key);
            if (cached != null) return cached;
            KeyStore ks = loadOrCreateHostStore(key);
            hostStoreCache.put(key, ks);
            return ks;
        }
    }

    private KeyStore loadOrCreateHostStore(String host) throws Exception {
        File p12 = new File(hostsDir, host + ".p12");
        if (p12.exists()) {
            try {
                KeyStore ks = KeyStore.getInstance("PKCS12");
                try (FileInputStream fis = new FileInputStream(p12)) {
                    ks.load(fis, HOST_STORE_PASS);
                }
                java.security.cert.Certificate[] chain = ks.getCertificateChain("leaf");
                if (chain != null && chain.length >= 2) {
                    ((X509Certificate) chain[0]).verify(chain[1].getPublicKey());
                    return ks; // 链有效
                }
                MitmLog.log(TAG + " load host store bad chain, regen: " + host);
            } catch (Throwable t) {
                MitmLog.log(TAG + " load host store corrupt, regen: " + host + " err=" + t);
                // fallthrough regen
            }
        }
        ensureCa();
        KeyPair kp = genKeyPair();
        Date notBefore = new Date(System.currentTimeMillis() - 60 * 1000L);
        Date notAfter = new Date(System.currentTimeMillis() + (long) LEAF_DAYS * 24 * 3600 * 1000L);
        // 关键：issuer 必须用 CA subject 的原始 DER 编码，否则 DN 编码不一致 → PKCS12 链匹配失败
        // ("Certificate chain is not valid")。字符串往返（getName() → new X500Name()）会重排/重编码。
        X500Name issuer = X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded());
        X500Name subject = new X500Name("CN=" + host);
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                issuer, randSerial(), notBefore, notAfter, subject, kp.getPublic());
        // SAN：只签具体 host（不需要 *.host）
        GeneralNames san = new GeneralNames(new GeneralName(GeneralName.dNSName, host));
        b.addExtension(Extension.subjectAlternativeName, false, san);
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        b.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        b.addExtension(Extension.extendedKeyUsage, false,
                new org.bouncycastle.asn1.x509.ExtendedKeyUsage(
                        org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_serverAuth));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(new BouncyCastleProvider()).build(caKey);
        X509CertificateHolder holder = b.build(signer);
        X509Certificate leaf = new JcaX509CertificateConverter()
                .setProvider(new BouncyCastleProvider()).getCertificate(holder);
        leaf.verify(caCert.getPublicKey());

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("leaf", kp.getPrivate(), HOST_STORE_PASS,
                new java.security.cert.Certificate[]{leaf, caCert});
        if (!hostsDir.exists()) hostsDir.mkdirs();
        try (FileOutputStream fos = new FileOutputStream(p12)) {
            ks.store(fos, HOST_STORE_PASS);
        }
        return ks;
    }

    // ===== 导出 =====

    /** 导出 CA 证书 PEM（装系统 CA / 生成 Magisk 模块用）。返回文件，失败返回 null。 */
    public File exportCaCertPem() {
        try {
            ensureCa();
            File out = new File(dir, "export_ca.pem");
            try (JcaPEMWriter w = new JcaPEMWriter(new FileWriter(out))) {
                w.writeObject(caCert);
            }
            return out;
        } catch (Throwable t) {
            MitmLog.log(TAG + " exportCaCertPem FAIL: " + t);
            return null;
        }
    }

    // ===== 内部 =====

    private static final char[] HOST_STORE_PASS = "spyprobe".toCharArray();

    private void loadCaFromDisk() throws Exception {
        // PEM 读取：用 BC PEMParser 读 key + cert
        java.io.Reader r1 = new java.io.FileReader(caKeyPem);
        Object keyObj = new org.bouncycastle.openssl.PEMParser(r1).readObject();
        r1.close();
        if (keyObj instanceof org.bouncycastle.openssl.PEMKeyPair) {
            caKey = new org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter()
                    .setProvider(new BouncyCastleProvider())
                    .getKeyPair((org.bouncycastle.openssl.PEMKeyPair) keyObj).getPrivate();
        } else if (keyObj instanceof org.bouncycastle.openssl.PEMEncryptedKeyPair) {
            throw new IOException("encrypted CA key not supported");
        } else {
            throw new IOException("unexpected CA key PEM: " + keyObj);
        }
        java.io.Reader r2 = new java.io.FileReader(caCertPem);
        Object certObj = new org.bouncycastle.openssl.PEMParser(r2).readObject();
        r2.close();
        if (certObj instanceof X509CertificateHolder) {
            caCert = new JcaX509CertificateConverter()
                    .setProvider(new BouncyCastleProvider())
                    .getCertificate((X509CertificateHolder) certObj);
        } else {
            throw new IOException("unexpected CA cert PEM: " + certObj);
        }
    }

    private void saveCaToDisk() throws Exception {
        if (!dir.exists()) dir.mkdirs();
        try (JcaPEMWriter w = new JcaPEMWriter(new FileWriter(caKeyPem))) {
            w.writeObject(caKey);
        }
        try (JcaPEMWriter w = new JcaPEMWriter(new FileWriter(caCertPem))) {
            w.writeObject(caCert);
        }
    }

    private KeyPair genKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(KEY_BITS, new SecureRandom());
        return kpg.generateKeyPair();
    }

    private BigInteger randSerial() {
        return new BigInteger(64, new SecureRandom());
    }

    // 防混淆删除（release 未开混淆，此引用仅为显式声明依赖）
    @SuppressWarnings("unused")
    private static void noop() {
        Security.removeProvider(PROVIDER_NAME);
    }
}
