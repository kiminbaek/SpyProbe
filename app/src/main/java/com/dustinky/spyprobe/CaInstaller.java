package com.dustinky.spyprobe;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * v7x: CA 安装器 —— 4 种方式把 SpyProbe MITM CA 装进系统信任库（多选项，不绑手机）
 *
 * Android 系统 CA 目录：
 *   - Android 14+ : /apex/com.android.conscrypt/cacerts/（只读 APEX，需 bind-mount / Magisk）
 *   - Android <14  : /system/etc/security/cacerts/
 *   - Magisk 模块 : /data/adb/modules/<id>/system/etc/security/cacerts/
 *
 * 4 种方式（用户可多选）：
 *   1. root 直接装（remount /system 或 bind-mount APEX，目标机有 root 时最省事）
 *   2. 导出 Magisk 模块 zip → 用户自己刷（无 root 或不想用 su 的场景）
 *   3. root 帮装 Magisk 模块（/data/adb/modules/ 直接写入，Magisk 重启自动生效）
 *   4. 用户 CA（Android 7+ 默认不信任，仅 hook sslBypass 兜底 / 老设备可用）
 *
 * 文件名 = subject_hash_old（MD5(subject DER) 前 4 字节大端）+ ".0"
 */
public class CaInstaller {

    public static final String TAG = "SpyProbe.CaInstall";
    private static final String MODULE_ID = "spyprobe-mitm";
    private static final String MODULE_NAME = "SpyProbe MITM CA";

    private CaInstaller() {}

    // ===== 通用 =====

    /** 计算 subject_hash_old（openssl -subject_hash_old 同算法） */
    public static String subjectHashOld(X509Certificate cert) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] der = cert.getSubjectX500Principal().getEncoded();
            byte[] digest = md.digest(der);
            return String.format("%08x",
                    ((digest[0] & 0xff) << 24) | ((digest[1] & 0xff) << 16)
                            | ((digest[2] & 0xff) << 8) | (digest[3] & 0xff));
        } catch (Throwable t) {
            return null;
        }
    }

    private static X509Certificate loadCert(File pem) {
        try {
            try (InputStream in = new FileInputStream(pem)) {
                return (X509Certificate) CertificateFactory.getInstance("X.509")
                        .generateCertificate(in);
            }
        } catch (Throwable t) {
            return null;
        }
    }

    /** 判断 CA 是否已在系统信任库（查两个已知目录） */
    public static boolean isSystemInstalled(File caPem) {
        X509Certificate cert = loadCert(caPem);
        if (cert == null) return false;
        String hash = subjectHashOld(cert);
        if (hash == null) return false;
        File[] dirs = {
                new File("/system/etc/security/cacerts"),
                new File("/apex/com.android.conscrypt/cacerts"),
        };
        for (File d : dirs) {
            if (new File(d, hash + ".0").exists()) return true;
        }
        return false;
    }

    /** 执行 su 命令（无输出）；失败抛异常 */
    private static void su(String cmd) throws Exception {
        Process p = new ProcessBuilder("su", "-c", cmd).redirectErrorStream(true).start();
        try (InputStream is = p.getInputStream()) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[1024];
            int n;
            while ((n = is.read(buf)) > 0) bos.write(buf, 0, n);
        }
        int rc = p.waitFor();
        if (rc != 0) throw new RuntimeException("su rc=" + rc + " cmd=" + cmd);
    }

    // ===== 方式 1：root 直接装（remount /system，Android <14） =====

    public static String installToSystemRoot(File caPem) {
        X509Certificate cert = loadCert(caPem);
        if (cert == null) return "CA PEM 解析失败";
        String hash = subjectHashOld(cert);
        if (hash == null) return "hash 计算失败";
        try {
            su("mount -o rw,remount /system");
            String dst = "/system/etc/security/cacerts/" + hash + ".0";
            su("cp '" + caPem.getAbsolutePath() + "' " + dst + " && chmod 644 " + dst);
            return "OK 已写入 " + dst + "（部分设备需重启生效）";
        } catch (Throwable t) {
            return "root 直接装失败: " + t;
        }
    }

    // ===== 方式 2/3：Magisk 模块（zip 导出 / root 直装） =====

    /**
     * 生成 Magisk 模块 zip（写入 outFile）。
     * 结构：module.prop + system/etc/security/cacerts/<hash>.0
     * （Magisk 会自动 merge system 目录，无需 post-fs-data.sh）
     */
    public static String exportMagiskModule(File caPem, File outFile) throws Exception {
        X509Certificate cert = loadCert(caPem);
        if (cert == null) throw new RuntimeException("CA PEM 解析失败");
        String hash = subjectHashOld(cert);
        if (hash == null) throw new RuntimeException("hash 计算失败");

        try (FileOutputStream fos = new FileOutputStream(outFile);
             ZipOutputStream zos = new ZipOutputStream(fos)) {
            String prop = "id=" + MODULE_ID + "\n"
                    + "name=" + MODULE_NAME + "\n"
                    + "version=v7x\n"
                    + "versionCode=1\n"
                    + "author=SpyProbe\n"
                    + "description=Install SpyProbe MITM CA into system trust store\n";
            zos.putNextEntry(new ZipEntry("module.prop"));
            zos.write(prop.getBytes("UTF-8"));
            zos.closeEntry();

            byte[] pem = readAll(caPem);
            zos.putNextEntry(new ZipEntry("system/etc/security/cacerts/" + hash + ".0"));
            zos.write(pem);
            zos.closeEntry();
        }
        return hash;
    }

    /** root 直接装到 Magisk 模块目录（重启生效） */
    public static String installMagiskModuleRoot(File caPem) {
        try {
            File tmp = new File(caPem.getParentFile(), "spyprobe_magisk.zip");
            String hash = exportMagiskModule(caPem, tmp);
            String dst = "/data/adb/modules/" + MODULE_ID + "/system/etc/security/cacerts/";
            su("mkdir -p " + dst
                    + " && cp '" + tmp.getAbsolutePath() + "' /data/local/tmp/spyprobe_magisk.zip"
                    + " && cd /data/local/tmp && unzip -o -q spyprobe_magisk.zip -d /data/adb/modules/" + MODULE_ID
                    + " && rm -f /data/local/tmp/spyprobe_magisk.zip");
            tmp.delete();
            return "OK Magisk 模块已写入 " + MODULE_ID + "（hash=" + hash + "，重启后生效）";
        } catch (Throwable t) {
            return "Magisk 直装失败: " + t;
        }
    }

    // ===== 工具 =====

    private static byte[] readAll(File f) throws Exception {
        try (InputStream in = new FileInputStream(f)) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
            return bos.toByteArray();
        }
    }
}
