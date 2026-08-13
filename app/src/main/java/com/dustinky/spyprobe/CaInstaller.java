package com.dustinky.spyprobe;

import com.dustinky.spyprobe.util.UiLog;

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
 * v1.73: 通用自适应 —— 应用运行时自动检测 Android 版本(getprop) + root 管理器
 *   （/data/adb/ksu=KernelSU / /data/adb/ap=APatch / /data/adb/magisk=Magisk），
 *   自动选择 bind-mount / remount 分支，不针对任何特定设备定制。
 *   所有操作 UiLog 留痕（失败原因可在「发送调试日志」里看到）。
 *
 * Android 系统 CA 目录：
 *   - Android 14+ : /apex/com.android.conscrypt/cacerts/（只读 APEX，用 bind-mount 挂副本）
 *   - Android <14  : /system/etc/security/cacerts/
 *   - Magisk/KernelSU 模块 : /data/adb/modules/<id>/（含 post-fs-data.sh 做 bind-mount，双兼容）
 *
 * 4 种方式（用户可多选）：
 *   1. root 直接装（自动选 bind-mount / remount，目标机有 root 时最省事）
 *   2. 导出 Magisk/KernelSU 模块 zip → 用户自己刷（无 root 或不想用 su 的场景）
 *   3. root 帮装 Magisk/KernelSU 模块（/data/adb/modules/ 直接写入，重启自动生效）
 *   4. 用户 CA（Android 7+ 默认不信任，仅 hook sslBypass 兜底 / 老设备可用）
 *
 * 文件名 = subject_hash_old（MD5(subject DER) 前 4 字节大端）+ ".0"
 */
public class CaInstaller {

    public static final String TAG = "SpyProbe.CaInstall";
    private static final String MODULE_ID = "spyprobe-mitm";
    private static final String MODULE_NAME = "SpyProbe MITM CA";
    private static final String MODULE_VERSION = "v1.73";

    /**
     * 通用 bind-mount 脚本（Magisk/KernelSU 均可；不依赖 KernelSU metamodule）。
     * 在 post-fs-data 阶段：把系统 CA 目录复制到 tmpfs 副本 + 追加本模块证书，再 bind-mount 回去。
     * Android 14+ 走 APEX；<14 走 /system。
     */
    private static final String POST_FS_DATA_SH =
            "#!/system/bin/sh\n" +
            "# SpyProbe MITM CA - universal bind-mount (Magisk/KernelSU, no metamodule needed)\n" +
            "MODDIR=${0%/*}\n" +
            "CERT_DIR=$MODDIR/system/etc/security/cacerts\n" +
            "TMP=/data/local/tmp/spyprobe-cacerts\n" +
            "rm -rf $TMP\n" +
            "mkdir -p $TMP\n" +
            "if [ -d /apex/com.android.conscrypt/cacerts ]; then\n" +
            "  cp -f /apex/com.android.conscrypt/cacerts/* $TMP/ 2>/dev/null\n" +
            "  cp -f $CERT_DIR/*.0 $TMP/ 2>/dev/null\n" +
            "  chmod 644 $TMP/* 2>/dev/null\n" +
            "  mount --bind $TMP /apex/com.android.conscrypt/cacerts\n" +
            "else\n" +
            "  cp -f /system/etc/security/cacerts/* $TMP/ 2>/dev/null\n" +
            "  cp -f $CERT_DIR/*.0 $TMP/ 2>/dev/null\n" +
            "  chmod 644 $TMP/* 2>/dev/null\n" +
            "  mount --bind $TMP /system/etc/security/cacerts\n" +
            "fi\n" +
            "exit 0\n";

    private CaInstaller() {}

    // ===== 环境检测（应用自己判断，不绑设备） =====

    /** Android SDK 版本（getprop，保持纯 Java 可在 NAS JVM 冒烟） */
    public static int sdkInt() {
        try {
            Process p = new ProcessBuilder("getprop", "ro.build.version.sdk").redirectErrorStream(true).start();
            String s = new String(readAll(p.getInputStream()), "UTF-8").trim();
            p.waitFor();
            return Integer.parseInt(s);
        } catch (Throwable t) {
            return 0;
        }
    }

    /** root 管理器类型：KernelSU / APatch / Magisk / unknown（探测各管理器目录） */
    public static String detectRootManager() {
        if (new File("/data/adb/ksu").exists()) return "KernelSU";
        if (new File("/data/adb/ap").exists()) return "APatch";
        if (new File("/data/adb/magisk").exists()) return "Magisk";
        return "unknown";
    }

    /** 是否 Android 14+（APEX cacerts 只读，需 bind-mount） */
    public static boolean isApexCacerts() {
        return new File("/apex/com.android.conscrypt/cacerts").isDirectory();
    }

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

    /** 判断 CA 是否已在系统信任库（查 APEX + /system 两个目录） */
    public static boolean isSystemInstalled(File caPem) {
        X509Certificate cert = loadCert(caPem);
        if (cert == null) return false;
        String hash = subjectHashOld(cert);
        if (hash == null) return false;
        File[] dirs = {
                new File("/apex/com.android.conscrypt/cacerts"),
                new File("/system/etc/security/cacerts"),
        };
        for (File d : dirs) {
            if (new File(d, hash + ".0").exists()) return true;
        }
        return false;
    }

    /** 执行 su 命令并返回 stdout；失败抛异常（含 rc） */
    private static String suOut(String cmd) throws Exception {
        Process p = new ProcessBuilder("su", "-c", cmd).redirectErrorStream(true).start();
        String out = new String(readAll(p.getInputStream()), "UTF-8");
        int rc = p.waitFor();
        if (rc != 0) throw new RuntimeException("su rc=" + rc + " cmd=" + cmd + " out=" + out);
        return out;
    }

    /** 执行 su 命令（无输出）；失败抛异常 */
    private static void su(String cmd) throws Exception {
        suOut(cmd);
    }

    // ===== bind-mount 核心（通用：APEX / system 二选一，立即生效） =====

    /**
     * 把 CA bind-mount 进系统信任库（立即生效）。
     * 原理：复制系统 CA 目录到 /data/local/tmp/spyprobe-cacerts，追加我们的证书，再 bind-mount 回去。
     * 不 remount /system、不依赖 metamodule；Magisk/KernelSU/APatch 通用。
     * 注意：bind-mount 是非持久挂载，重启后需模块（post-fs-data.sh）重新挂。
     */
    private static boolean bindMountCa(File caPem, String hash, boolean apex) throws Exception {
        String sysDir = apex ? "/apex/com.android.conscrypt/cacerts" : "/system/etc/security/cacerts";
        String tmp = "/data/local/tmp/spyprobe-cacerts";
        UiLog.log(TAG + " bindMountCa apex=" + apex + " hash=" + hash);
        // v1.74.11 P0-14: 修复重复安装清空系统 CA 的致命 bug。
        //   旧实现每次都 `rm -rf tmp`——若 tmp 已 bind-mount 到 sysDir，删除源目录内容
        //   = 系统 CA 视图文件全部消失 → 所有 App 无法验证任何证书 → 无网（重启才恢复）。
        //   已挂载：只追加我们的 CA（绝不动其他系统 CA）；未挂载：完整复制后再挂载。
        boolean mounted = isMounted(tmp, sysDir);
        if (mounted) {
            su("cp -f '" + caPem.getAbsolutePath() + "' " + tmp + "/" + hash + ".0");
            su("chmod 644 " + tmp + "/" + hash + ".0");
        } else {
            su("rm -rf " + tmp);
            su("mkdir -p " + tmp);
            su("cp -f " + sysDir + "/* " + tmp + "/");
            su("cp -f '" + caPem.getAbsolutePath() + "' " + tmp + "/" + hash + ".0");
            su("chmod 644 " + tmp + "/*");
            su("mount --bind " + tmp + " " + sysDir);
        }
        boolean ok = new File(sysDir + "/" + hash + ".0").exists();
        UiLog.log(TAG + " bindMountCa mounted=" + mounted + " " + (ok ? "OK" : "verify FAIL") + " -> " + sysDir + "/" + hash + ".0");
        return ok;
    }

    /** 检查 tmp 是否已 bind-mount 到 sysDir（/proc/mounts：source + mountpoint） */
    private static boolean isMounted(String src, String dst) throws Exception {
        String out = suOut("cat /proc/mounts");
        return out.contains(src + " " + dst);
    }

    // ===== 方式 1：root 直接装（自动选 APEX bind-mount / system remount / system bind-mount） =====

    public static String installToSystemRoot(File caPem) {
        X509Certificate cert = loadCert(caPem);
        if (cert == null) return "CA PEM 解析失败";
        String hash = subjectHashOld(cert);
        if (hash == null) return "hash 计算失败";
        boolean apex = isApexCacerts();
        String rm = detectRootManager();
        UiLog.log(TAG + " installToSystemRoot sdk=" + sdkInt() + " rootManager=" + rm + " apex=" + apex);
        try {
            // Android 14+（APEX）：bind-mount（不 remount，通用）
            if (apex) {
                boolean ok = bindMountCa(caPem, hash, true);
                return ok
                        ? "OK 已 bind-mount 到 APEX 系统 CA（立即生效；重启后需装模块保持）"
                        : "bind-mount 后验证失败（详见调试日志）";
            }
            // Android <14：先试 remount /system 直写（传统），失败回退 bind-mount
            try {
                su("mount -o rw,remount /system");
                String dst = "/system/etc/security/cacerts/" + hash + ".0";
                su("cp '" + caPem.getAbsolutePath() + "' " + dst + " && chmod 644 " + dst);
                UiLog.log(TAG + " installToSystemRoot remount OK: " + dst);
                return "OK 已写入 " + dst + "（部分设备需重启生效）";
            } catch (Throwable t) {
                UiLog.log(TAG + " remount fail -> fallback bind-mount: " + t);
                boolean ok = bindMountCa(caPem, hash, false);
                return ok
                        ? "remount 失败，已改用 bind-mount 生效（立即生效；重启后需装模块保持）"
                        : "remount + bind-mount 均失败（详见调试日志）";
            }
        } catch (Throwable t) {
            UiLog.log(TAG + " installToSystemRoot FAIL: " + t);
            return "root 直接装失败: " + t;
        }
    }

    // ===== 方式 2/3：Magisk/KernelSU 模块（zip 导出 / root 直装） =====

    /**
     * 生成 Magisk/KernelSU 通用模块 zip（写入 outFile）。
     * 结构：module.prop + post-fs-data.sh(通用 bind-mount) + system/etc/security/cacerts/<hash>.0
     *  - Magisk：magic mount 会 merge system/ 目录（无需 metamodule）
     *  - KernelSU：post-fs-data.sh 做 bind-mount（不依赖 metamodule）
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
                    + "version=" + MODULE_VERSION + "\n"
                    + "versionCode=1\n"
                    + "author=SpyProbe\n"
                    + "description=Install SpyProbe MITM CA into system trust store\n";
            zos.putNextEntry(new ZipEntry("module.prop"));
            zos.write(prop.getBytes("UTF-8"));
            zos.closeEntry();

            zos.putNextEntry(new ZipEntry("post-fs-data.sh"));
            zos.write(POST_FS_DATA_SH.getBytes("UTF-8"));
            zos.closeEntry();

            byte[] pem = readAll(caPem);
            zos.putNextEntry(new ZipEntry("system/etc/security/cacerts/" + hash + ".0"));
            zos.write(pem);
            zos.closeEntry();
        }
        UiLog.log(TAG + " exportMagiskModule OK: " + outFile.getAbsolutePath() + " hash=" + hash);
        return hash;
    }

    /** v1.74.6 P0-9: 是否已装 Magisk/KernelSU 模块（/data/adb/modules/spyprobe-mitm 存在） */
    public static boolean hasModule() {
        return new File("/data/adb/modules/" + MODULE_ID).isDirectory();
    }

    /** root 直接装到模块目录（重启生效；KernelSU 下额外尝试即时 bind-mount） */
    public static String installMagiskModuleRoot(File caPem) {
        String rm = detectRootManager();
        UiLog.log(TAG + " installMagiskModuleRoot rootManager=" + rm);
        try {
            File tmp = new File(caPem.getParentFile(), "spyprobe_magisk.zip");
            String hash = exportMagiskModule(caPem, tmp);
            String dst = "/data/adb/modules/" + MODULE_ID + "/system/etc/security/cacerts/";
            su("mkdir -p " + dst
                    + " && cp '" + tmp.getAbsolutePath() + "' /data/local/tmp/spyprobe_magisk.zip"
                    + " && cd /data/local/tmp && unzip -o -q spyprobe_magisk.zip -d /data/adb/modules/" + MODULE_ID
                    + " && chmod 755 /data/adb/modules/" + MODULE_ID + "/post-fs-data.sh"
                    + " && rm -f /data/local/tmp/spyprobe_magisk.zip");
            tmp.delete();
            UiLog.log(TAG + " module files written to /data/adb/modules/" + MODULE_ID);
            boolean apex = isApexCacerts();
            // KernelSU/APatch：尝试即时 bind-mount（立即生效，不等重启）；Magisk 走 magic mount 重启生效
            if ("KernelSU".equals(rm) || "APatch".equals(rm)) {
                try {
                    boolean ok = bindMountCa(caPem, hash, apex);
                    return ok
                            ? "OK 模块已写入 " + MODULE_ID + "，并已即时 bind-mount（hash=" + hash + "，立即生效，重启后仍保持）"
                            : "OK 模块已写入 " + MODULE_ID + "（hash=" + hash + "，即时 bind-mount 验证失败，重启后生效）";
                } catch (Throwable t) {
                    UiLog.log(TAG + " instant bind-mount fail: " + t);
                    return "OK 模块已写入 " + MODULE_ID + "（hash=" + hash + "，即时挂载失败: " + t + "，重启后生效）";
                }
            }
            return "OK Magisk 模块已写入 " + MODULE_ID + "（hash=" + hash + "，重启后生效）";
        } catch (Throwable t) {
            UiLog.log(TAG + " installMagiskModuleRoot FAIL: " + t);
            return "Magisk 直装失败: " + t;
        }
    }

    // ===== 工具 =====

    private static byte[] readAll(File f) throws Exception {
        try (InputStream in = new FileInputStream(f)) {
            return readAll(in);
        }
    }

    private static byte[] readAll(InputStream in) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
        return bos.toByteArray();
    }
}
