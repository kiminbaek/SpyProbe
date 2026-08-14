package com.dustinky.spyprobe;

import java.io.File;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArraySet;

/**
 * v7x: MITM 代理主进程管理器
 *
 * 职责：
 *   - 初始化 MitmCertManager + MitmProxy（filesDir/mitm_ca 持久化 CA）
 *   - 按 Config 启停代理（mitmEnabled / mitmTransparent / mitmPort）
 *   - 透明模式：iptables REDIRECT 规则（自定义链 SPYPROBE_MITM，按目标 UID 过滤，
 *     排除自身 UID 防回环）
 *   - 明文融合：每连接一个 TlsHttpParser → HttpEntry → HttpStore（复用现有结构化全链路）
 *   - 目标 UID 注册：目标进程启动时上报（SpyHomeServer /api/target_uid）
 */
public class MitmManager {

    private static volatile MitmManager instance;

    private final MitmCertManager cert;
    private final MitmProxy proxy;
    private final File filesDir;
    private final ConcurrentHashMap<Integer, TlsHttpParser> parsers = new ConcurrentHashMap<>();
    private final CopyOnWriteArraySet<Integer> targetUids = new CopyOnWriteArraySet<>();
    private volatile boolean iptablesApplied = false;

    public static MitmManager get() {
        return instance;
    }

    /** 主进程 onCreate 调用（幂等） */
    public static synchronized MitmManager init(File filesDir) {
        if (instance == null) {
            instance = new MitmManager(filesDir);
        }
        return instance;
    }

    private MitmManager(File filesDir) {
        this.filesDir = filesDir;
        this.cert = MitmCertManager.init(filesDir);
        this.proxy = new MitmProxy(cert);
        MitmLog.setSink(msg -> DebugLog.get().log("Mitm", msg));
    }

    public MitmCertManager certManager() {
        return cert;
    }

    public MitmProxy proxy() {
        return proxy;
    }

    // ===== 启停 =====

    /** 设置页/启动时调用：按 Config 决定启动或停止代理 */
    public synchronized void applyConfig() {
        Config cfg = Config.get();
        boolean want = cfg.mitmEnabled;
        // v1.74.0 P0-2: 状态双写 UiLog（UI 进程，导出可见）——MITM 是否被触发、为何没触发一次到位
        com.dustinky.spyprobe.util.UiLog.log("MitmManager.applyConfig want=" + want
                + " running=" + proxy.isRunning() + " transparent=" + cfg.mitmTransparent + " port=" + cfg.mitmPort);
        if (want && !proxy.isRunning()) {
            startProxy();
        } else if (!want && proxy.isRunning()) {
            stopProxy();
        }
    }

    private void startProxy() {
        try {
            // v1.74.6 P0-9: 启动代理前自动检查 CA 指纹——用户清除应用数据后 mitm_ca 重新生成新 CA，
            // 系统信任库还是旧 CA → dart:io 校验证书失败 → 目标 App TLS 握手挂起（一直连线中）。
            ensureCaInstalled();
            int port = Config.get().mitmPort;
            boolean transparent = Config.get().mitmTransparent;
            proxy.start(port, this::onPlain, transparent);
            DebugLog.get().log("Mitm", "proxy started port=" + port + " transparent=" + transparent);
            com.dustinky.spyprobe.util.UiLog.log("MitmManager proxy started port=" + port + " transparent=" + transparent);
            if (transparent) applyIptables();
        } catch (Throwable t) {
            DebugLog.get().log("Mitm", "start FAIL: " + t);
            com.dustinky.spyprobe.util.UiLog.log("MitmManager proxy start FAIL: " + t);
        }
    }

    private void stopProxy() {
        try { proxy.stop(); } catch (Throwable ignored) {}
        clearIptables();
        parsers.clear();
    }

    /**
     * v1.74.6 P0-9: 检查当前 CA 是否已装进系统信任库，不匹配则自动 root 重装（bind-mount 立即生效，无需重启）。
     * 已装 Magisk/KernelSU 模块时同步更新模块内 CA（否则重启手机后模块挂旧 CA 又失配）。
     */
    private void ensureCaInstalled() {
        try {
            File pem = cert.caCertPem();
            if (pem == null || !pem.exists()) {
                DebugLog.get().log("Mitm", "CA pem missing, skip auto-install");
                return;
            }
            boolean hasMod = CaInstaller.hasModule();
            if (hasMod) {
                // v1.74.11 P0-14: 模块已装 → 优先更新模块内 CA 文件（模块 post-fs-data 已挂载时
                //   更新即生效；KernelSU 分支内部会再安全 bind-mount）。避免旧顺序：先 bind-mount
                //   再同步模块 → 两次 bindMountCa 的 rm -rf 清空系统 CA 视图 → App 无网。
                try {
                    String r2 = CaInstaller.installMagiskModuleRoot(pem);
                    DebugLog.get().log("Mitm", "CA module update: " + r2);
                    com.dustinky.spyprobe.util.UiLog.log("MitmManager CA module update: " + r2);
                } catch (Throwable t2) {
                    DebugLog.get().log("Mitm", "CA module update FAIL: " + t2);
                }
            }
            if (CaInstaller.isSystemInstalled(pem)) {
                // v1.74.17 P0-17: isSystemInstalled=true 只代表当前进程 namespace 视图里有 CA 文件，
                //   **不代表 zygote fork 的目标 App 进程可见**（旧 mount 只落在执行 su 的进程 ns）。
                //   必须无条件传播到 zygote namespace（幂等），否则目标 App 证书校验失败 → EOF（连线中）。
                CaInstaller.propagateToZygote();
                DebugLog.get().log("Mitm", "CA already in system store -> propagated to zygote ns");
                DebugLog.get().log("Mitm", CaInstaller.caDiagnostics(pem));
                return;
            }
            DebugLog.get().log("Mitm", "CA mismatch -> auto reinstall (clear-data case)");
            String r = CaInstaller.installToSystemRoot(pem);
            DebugLog.get().log("Mitm", "CA auto-install: " + r);
            DebugLog.get().log("Mitm", CaInstaller.caDiagnostics(pem));
            com.dustinky.spyprobe.util.UiLog.log("MitmManager CA auto-install: " + r);
        } catch (Throwable t) {
            DebugLog.get().log("Mitm", "CA ensure FAIL: " + t);
            com.dustinky.spyprobe.util.UiLog.log("MitmManager CA ensure FAIL: " + t);
        }
    }

    // ===== 明文融合 → TlsHttpParser → HttpStore =====

    private void onPlain(int connId, int dir, String host, byte[] data, int len) {
        try {
            TlsHttpParser p = parsers.get(connId);
            if (p == null) {
                // socketInfo "src->dst"（src 为主进程环回，dst 为目标）
                p = new TlsHttpParser(connId, "127.0.0.1:0->" + host + ":443");
                TlsHttpParser old = parsers.putIfAbsent(connId, p);
                if (old != null) p = old;
            }
            p.feed(dir == 0, data, len);
        } catch (Throwable t) {
            DebugLog.get().log("Mitm", "parse err: " + t);
        }
    }

    private void onConnClosed(int connId) {
        TlsHttpParser p = parsers.remove(connId);
        if (p != null) {
            try { p.close(); } catch (Throwable ignored) {}
        }
    }

    // ===== 目标 UID 注册（iptables 过滤用） =====

    /** 目标进程启动时上报 uid（SpyHomeServer /api/target_uid 回调） */
    public void registerTargetUid(int uid) {
        if (uid <= 0) return;
        boolean isNew = targetUids.add(uid);
        DebugLog.get().log("Mitm", "register uid=" + uid + " total=" + targetUids.size());
        com.dustinky.spyprobe.util.UiLog.log("MitmManager register uid=" + uid + " total=" + targetUids.size()
                + " running=" + proxy.isRunning() + " transparent=" + Config.get().mitmTransparent);
        // v1.74.19 P0-18: 目标 App 进程若先于 CA 安装/代理启动，其进程内 TrustManager /
        //   native SSL_CTX 的 X509_STORE 缓存没有新 CA → ServerHello 后证书校验失败 →
        //   客户端 1ms 内关闭 → 握手 EOF（「连线中」）。
        //   首次注册且代理已在运行 = 目标 App 大概率先于 CA 启动 → force-stop 强制重启目标应用，
        //   新进程重新加载系统 CA（UiLog 提示用户重新打开）。
        if (isNew && proxy.isRunning() && Config.get().mitmTransparent) {
            restartTargetAppForCa(uid);
        }
        if (proxy.isRunning() && Config.get().mitmTransparent) {
            applyIptables();
        }
    }

    /** P0-18: force-stop 目标应用，让新进程重新加载系统 CA（幂等：重开后 uid 已存在不再杀） */
    private void restartTargetAppForCa(int uid) {
        try {
            String pkg = packageForUid(uid);
            if (pkg == null) {
                DebugLog.get().log("Mitm", "restartTargetApp: no pkg for uid=" + uid);
                return;
            }
            DebugLog.get().log("Mitm", "P0-18: CA 需新进程加载 → force-stop " + pkg);
            execRoot("am force-stop " + pkg);
            com.dustinky.spyprobe.util.UiLog.log("MitmManager 已自动重启目标应用 " + pkg
                    + "（系统 CA 需新进程加载），请重新打开应用");
        } catch (Throwable t) {
            DebugLog.get().log("Mitm", "restartTargetApp FAIL: " + t);
        }
    }

    /** 通过 uid 找包名（root pm） */
    private String packageForUid(int uid) {
        try {
            String out = execRootOut("pm list packages --uid " + uid);
            if (out != null) {
                for (String line : out.split("\n")) {
                    String t = line.trim();
                    if (t.startsWith("package:")) return t.substring("package:".length()).trim();
                }
            }
        } catch (Throwable t) {
            DebugLog.get().log("Mitm", "packageForUid FAIL: " + t);
        }
        return null;
    }

    /** root 执行并返回标准输出（首 4KB） */
    private String execRootOut(String cmd) throws Exception {
        Process p = Runtime.getRuntime().exec(new String[]{"su", "-c", cmd});
        java.io.InputStream is = p.getInputStream();
        byte[] buf = new byte[4096];
        int n = is.read(buf);
        p.waitFor();
        if (n > 0) return new String(buf, 0, n, java.nio.charset.StandardCharsets.UTF_8);
        return null;
    }

    // ===== iptables 规则（透明模式，需 root） =====

    private void applyIptables() {
        try {
            int port = Config.get().mitmPort;
            String self = Integer.toString(android.os.Process.myUid());
            StringBuilder sb = new StringBuilder();
            sb.append("iptables -t nat -F SPYPROBE_MITM; ");
            sb.append("iptables -t nat -D OUTPUT -j SPYPROBE_MITM 2>/dev/null; ");
            sb.append("iptables -t nat -N SPYPROBE_MITM 2>/dev/null; ");
            if (!targetUids.isEmpty()) {
                for (int uid : targetUids) {
                    sb.append("iptables -t nat -A SPYPROBE_MITM -p tcp --dport 443 ")
                      .append("-m owner --uid-owner ").append(uid)
                      .append(" -j REDIRECT --to-ports ").append(port).append("; ");
                }
                // 钩到 OUTPUT，排除自身（防回环）
                sb.append("iptables -t nat -A OUTPUT -p tcp --dport 443 ")
                  .append("-m owner ! --uid-owner ").append(self)
                  .append(" -j SPYPROBE_MITM; ");
            }
            execRoot(sb.toString());
            iptablesApplied = true;
            DebugLog.get().log("Mitm", "iptables applied uids=" + targetUids + " port=" + port);
            com.dustinky.spyprobe.util.UiLog.log("MitmManager iptables applied uids=" + targetUids + " port=" + port);
        } catch (Throwable t) {
            DebugLog.get().log("Mitm", "iptables FAIL: " + t);
            com.dustinky.spyprobe.util.UiLog.log("MitmManager iptables FAIL: " + t);
        }
    }

    private void clearIptables() {
        if (!iptablesApplied) return;
        try {
            execRoot("iptables -t nat -F SPYPROBE_MITM 2>/dev/null; "
                    + "iptables -t nat -D OUTPUT -j SPYPROBE_MITM 2>/dev/null; "
                    + "iptables -t nat -X SPYPROBE_MITM 2>/dev/null");
            iptablesApplied = false;
            com.dustinky.spyprobe.util.UiLog.log("MitmManager iptables cleared");
        } catch (Throwable t) {
            DebugLog.get().log("Mitm", "iptables clear FAIL: " + t);
            com.dustinky.spyprobe.util.UiLog.log("MitmManager iptables clear FAIL: " + t);
        }
    }

    private void execRoot(String cmd) throws Exception {
        Process p = Runtime.getRuntime().exec(new String[]{"su", "-c", cmd});
        p.waitFor();
    }

    // 供调试/UI 显示
    public String status() {
        return "running=" + proxy.isRunning() + " uids=" + targetUids + " iptables=" + iptablesApplied;
    }
}
