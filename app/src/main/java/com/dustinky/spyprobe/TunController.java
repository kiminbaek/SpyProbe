package com.dustinky.spyprobe;

import android.content.Context;
import android.content.Intent;

/**
 * v8x: TUN 双模式统一控制器（Clash MIX 借鉴 —— TUN 透明接管抓 dart:io/Flutter 流量）
 *
 * 背景：MITM 透明代理方案（v7x）在 91aw 等 dart:io/Flutter App 上连续失败（手机卡死/升温、
 * CA 信任链、握手分片），2026-08-14 用户拍板终止 MITM，改走 TUN 接管。
 * TUN 在系统网络栈层面接管流量，不依赖 CA、不依赖 hook 时机，天然覆盖 Flutter/dart:io。
 *
 * 模式：
 *   0 = 关（默认）
 *   1 = VpnService（无 root，系统弹授权；SpyVpnService）
 *   2 = Magisk/KernelSU（root 建 spy0 TUN；MagiskTun）
 *
 * 两种模式共用 PacketLoop（读 TUN fd → 五元组解析 → 记录 → 简化用户态转发透传）。
 *
 * 设计约束（铁律 1/3/5）：
 *   - 只观察不改 payload：TUN 流量原样转发（PCAPDroid 式简化 L4 转发），App 无感知
 *   - 启停幂等：重复 applyConfig 不重复建 TUN；stop 全量清理（TUN 设备/路由/iptables）
 *   - 失败不盲重试：建 TUN 失败立即上报状态，UI 显示原因
 */
public class TunController {

    public static final int MODE_OFF = 0;
    public static final int MODE_VPN = 1;
    public static final int MODE_MAGISK = 2;

    private static final String TAG = "SpyProbe.Tun";

    private static TunController INSTANCE;

    private Context appContext;
    /** 当前实际运行模式（0=未运行） */
    private volatile int runningMode = MODE_OFF;
    private PacketLoop loop;
    private MagiskTun magisk;
    /** v8x: 目标 App 包名（ModuleMain 上报；状态/日志标注用） */
    private volatile String targetPkg = "";

    public static TunController get() { return INSTANCE; }

    /** v8x: 目标 App 包名上报（hook 进程 ModuleMain 调用，主进程状态显示） */
    public void setTargetPkg(String pkg) {
        this.targetPkg = pkg == null ? "" : pkg;
        DebugLog.get().logNoMirror(TAG, "target pkg = " + this.targetPkg);
    }

    public String targetPkg() { return targetPkg; }

    /** 主进程启动时调用（MainActivity.onCreate），幂等 */
    public static synchronized void init(Context ctx) {
        if (INSTANCE == null) {
            INSTANCE = new TunController();
            INSTANCE.appContext = ctx.getApplicationContext();
            DebugLog.get().logNoMirror(TAG, "init");
        }
    }

    private TunController() { }

    public boolean isRunning() { return runningMode != MODE_OFF; }
    public int runningMode() { return runningMode; }
    public PacketLoop loop() { return loop; }

    /** 按 Config 意图启停（幂等；设置页/启动时调用） */
    public synchronized String applyConfig() {
        if (!Config.get().tunEnabled) {
            if (runningMode != MODE_OFF) return stop();
            return "TUN 关闭";
        }
        int want = Config.get().tunMode;
        if (want == MODE_OFF) {
            if (runningMode != MODE_OFF) return stop();
            return "TUN 关闭";
        }
        if (runningMode != MODE_OFF) {
            if (runningMode == want) return "TUN 运行中（模式 " + modeName(want) + "）";
            // 模式切换：先停旧的再启新的
            stop();
        }
        if (want == MODE_VPN) {
            // VpnService 需要 UI 层先 prepare（弹授权），这里只负责启动服务；
            // 授权未通过时 SpyVpnService.onStartCommand 会立即 stopSelf，runningMode 保持 OFF
            try {
                Intent i = new Intent(appContext, SpyVpnService.class);
                i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                appContext.startForegroundService(i); // minSdk 26 直接用
                DebugLog.get().logNoMirror(TAG, "start VpnService intent sent");
                return "VpnService 启动中…（确认系统授权弹窗）";
            } catch (Throwable t) {
                DebugLog.get().logNoMirror(TAG, "start VpnService FAIL: " + t);
                return "VpnService 启动失败: " + t;
            }
        }
        if (want == MODE_MAGISK) {
            return startMagisk();
        }
        return "未知模式 " + want;
    }

    /** VpnService 的 fd 建立成功后由 SpyVpnService 回调（runningMode 置 VPN） */
    public synchronized void onVpnFdReady(PacketLoop l) {
        this.loop = l;
        this.runningMode = MODE_VPN;
        DebugLog.get().logNoMirror(TAG, "VpnService fd ready, TUN 运行");
    }

    /** VpnService 失败/停止时回调 */
    public synchronized void onVpnStopped() {
        if (runningMode == MODE_VPN) {
            stopLoop();
            runningMode = MODE_OFF;
            DebugLog.get().logNoMirror(TAG, "VpnService stopped");
        }
    }

    private synchronized String startMagisk() {
        if (magisk == null) magisk = new MagiskTun();
        String err = magisk.start();
        if (err != null) {
            DebugLog.get().logNoMirror(TAG, "MagiskTun start FAIL: " + err);
            return "Magisk TUN 启动失败: " + err;
        }
        // fd 打开（root 已建好设备）
        int fd = MagiskTun.nativeOpenTun(Config.get().tunDevice);
        if (fd < 0) {
            magisk.stop();
            return "打开 TUN fd 失败（fd=" + fd + "），已回滚设备";
        }
        loop = PacketLoop.forRawFd(fd, null); // Magisk 模式无需 protect
        String err2 = loop.start();
        if (err2 != null) {
            magisk.stop();
            return "PacketLoop 启动失败: " + err2;
        }
        runningMode = MODE_MAGISK;
        DebugLog.get().logNoMirror(TAG, "Magisk TUN running (fd=" + fd + ")");
        return "Magisk TUN 运行中（设备 " + Config.get().tunDevice + "）";
    }

    /** 停止（幂等；所有模式） */
    public synchronized String stop() {
        if (runningMode == MODE_MAGISK && magisk != null) {
            try { magisk.stop(); } catch (Throwable t) {
                DebugLog.get().logNoMirror(TAG, "magisk stop FAIL: " + t);
            }
        }
        stopLoop();
        if (runningMode == MODE_VPN) {
            // 通知 VpnService 停止（stopSelf 由 Service 内部处理）
            try {
                appContext.stopService(new Intent(appContext, SpyVpnService.class));
            } catch (Throwable t) { }
        }
        runningMode = MODE_OFF;
        DebugLog.get().logNoMirror(TAG, "TUN stopped");
        return "TUN 已停止";
    }

    private void stopLoop() {
        if (loop != null) {
            try { loop.close(); } catch (Throwable t) { }
            loop = null;
        }
    }

    /** 状态文本（设置页显示） */
    public synchronized String status() {
        if (runningMode == MODE_OFF) return "未运行";
        if (loop == null) return "运行中（" + modeName(runningMode) + "，数据面未就绪）";
        return "运行中（" + modeName(runningMode) + "），连接 " + loop.connCount()
                + "，读 " + loop.readBytes() + " B，写 " + loop.writeBytes() + " B";
    }

    public static String modeName(int mode) {
        switch (mode) {
            case MODE_VPN: return "VpnService";
            case MODE_MAGISK: return "Magisk TUN";
            default: return "关";
        }
    }
}
