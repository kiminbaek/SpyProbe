package com.dustinky.spyprobe;

import java.io.File;

/**
 * v8x: Magisk/KernelSU TUN 后端（TUN 模式 2 —— root 全局接管）
 *
 * 借鉴 Clash MIX 4.0 `Scripts/Clash.Service` 状态机：
 *   - 启动：建 tun 设备（ip tuntap add）→ 配地址 → up → 默认路由接管 → FORWARD 放行
 *   - 停止：删路由 → 删 iptables FORWARD → 删 tun 设备（全量清理，无内核规则残留）
 *
 * 与 Clash MIX 差异（设计决策）：
 *   - 设备名 spy0（固定，避免与 Clash MIX 的 Meta 冲突）
 *   - 不设 fake-ip：直接改默认路由全量接管，PacketLoop 用户态转发（观察透传）
 *   - stop 恢复原默认路由（记录启动前路由表）
 *
 * fd 获取：Java 无公开 ioctl，加 native 辅助 {@link #nativeOpenTun}（native_hook.cpp）。
 */
public class MagiskTun {

    private static final String TAG = "SpyProbe.MagiskTun";

    private String dev = "spy0";
    private String oldDefaultRoute = null;

    public MagiskTun() {
        String d = Config.get().tunDevice;
        if (d != null && !d.isEmpty()) dev = d;
    }

    /** root 执行命令；返回 null=成功，非 null=错误信息（含 stderr） */
    private String su(String cmd) {
        try {
            Process p = new ProcessBuilder("su", "-c", cmd)
                    .redirectErrorStream(true)
                    .start();
            StringBuilder sb = new StringBuilder();
            byte[] buf = new byte[4096];
            java.io.InputStream is = p.getInputStream();
            int n;
            while ((n = is.read(buf)) > 0) sb.append(new String(buf, 0, n));
            int code = p.waitFor();
            String out = sb.toString().trim();
            if (code != 0) return "exit=" + code + " " + out;
            return null;
        } catch (Throwable t) {
            return "su 不可用: " + t;
        }
    }

    /** 启动 TUN；返回 null=成功，非 null=错误 */
    public synchronized String start() {
        // 1. 设备是否已存在（幂等）
        String exists = su("ip link show " + dev);
        if (exists != null) {
            // 建设备（需 root + tun 模块；KernelSU/Magisk 内置）
            String r = su("ip tuntap add dev " + dev + " mode tun");
            if (r != null) return "建 TUN 设备失败: " + r;
        }
        // 2. 配地址 + up
        String r = su("ip addr add 10.77.0.1/24 dev " + dev + " 2>/dev/null; ip link set " + dev + " up");
        if (r != null) return "配置 TUN 地址失败: " + r;
        // 3. 记录原默认路由（恢复用）
        String route = su("ip route show default");
        if (route != null && !route.isEmpty()) oldDefaultRoute = route.split("\n")[0].trim();
        // 4. 默认路由接管（全量 TUN）
        r = su("ip route add default dev " + dev + " table 100 2>/dev/null; "
                + "ip rule add pref 100 from all lookup 100 2>/dev/null; "
                + "ip route flush cache");
        if (r != null) {
            // 非致命：接管失败则直接清掉刚建的
            su("ip link del " + dev);
            return "路由接管失败: " + r;
        }
        // 5. FORWARD 放行（热点共享/系统转发；借鉴 Clash MIX Clash.Service）
        su("iptables -C FORWARD -i " + dev + " -j ACCEPT 2>/dev/null || iptables -I FORWARD -i " + dev + " -j ACCEPT; "
                + "iptables -C FORWARD -o " + dev + " -j ACCEPT 2>/dev/null || iptables -I FORWARD -o " + dev + " -j ACCEPT");
        DebugLog.get().logNoMirror(TAG, "start ok dev=" + dev + " oldRoute=" + oldDefaultRoute);
        return null;
    }

    /** 全量清理：路由 → iptables → 设备（幂等，可重复调用） */
    public synchronized String stop() {
        // 1. 删接管路由/规则（先删规则再删路由，避免中断瞬间流量走 TUN）
        su("ip rule del pref 100 from all lookup 100 2>/dev/null; "
                + "ip route del default dev " + dev + " table 100 2>/dev/null; "
                + "ip route flush cache");
        // 2. 恢复原默认路由（若被我们动过）
        if (oldDefaultRoute != null && !oldDefaultRoute.isEmpty()) {
            su("ip route add " + oldDefaultRoute + " 2>/dev/null");
            oldDefaultRoute = null;
        }
        // 3. 删 iptables FORWARD
        su("iptables -D FORWARD -i " + dev + " -j ACCEPT 2>/dev/null; "
                + "iptables -D FORWARD -o " + dev + " -j ACCEPT 2>/dev/null");
        // 4. 删设备
        su("ip link del " + dev + " 2>/dev/null");
        DebugLog.get().logNoMirror(TAG, "stop ok dev=" + dev);
        return null;
    }

    /**
     * native 打开 TUN 设备（open /dev/net/tun + ioctl TUNSETIFF name=dev）
     * @return fd（>=0 成功），-1 失败
     * 实现见 native_hook.cpp nativeOpenTun
     */
    public static native int nativeOpenTun(String devName);
}
