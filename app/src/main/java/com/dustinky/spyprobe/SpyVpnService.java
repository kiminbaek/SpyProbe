package com.dustinky.spyprobe;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;

/**
 * v8x: VpnService 后端（TUN 模式 1 —— 无 root 首选）
 *
 * 建立 VpnService 虚拟接口（tun），路由 0.0.0.0/0 + ::/0 全量接管，
 * fd 交给 PacketLoop 做"读包 → 五元组解析 → 记录 → 简化转发透传"。
 * 出口 socket 通过 {@link #protect} 防回环（VpnService.protect）。
 *
 * 授权流程（UI 层 SettingsScreen 处理）：
 *   1. VpnService.prepare(context) 非 null → 弹系统授权（startActivityForResult）
 *   2. 授权通过 → startForegroundService → onStartCommand → establish()
 *
 * 失败处理：establish() 返回 null（用户取消授权）→ 立即 stopSelf + TunController.onVpnStopped()。
 */
public class SpyVpnService extends VpnService {

    private static final String CHANNEL_ID = "spyprobe_tun";
    private static final int NOTIF_ID = 0x5455; // "TU"

    private ParcelFileDescriptor vpnFd;
    private PacketLoop loop;
    private volatile boolean running = false;

    @Override
    public void onCreate() {
        super.onCreate();
        DebugLog.get().logNoMirror("SpyVpnService", "onCreate");
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        DebugLog.get().logNoMirror("SpyVpnService", "onStartCommand");
        try {
            startForegroundCompat();
        } catch (Throwable t) {
            DebugLog.get().logNoMirror("SpyVpnService", "startForeground FAIL: " + t);
        }
        if (running) return START_STICKY;
        try {
            establish();
        } catch (Throwable t) {
            DebugLog.get().logNoMirror("SpyVpnService", "establish FAIL: " + t);
            stopSelf();
            TunController c = TunController.get();
            if (c != null) c.onVpnStopped();
        }
        return START_STICKY;
    }

    private void establish() {
        Builder b = new Builder();
        b.setSession("SpyProbe TUN 抓包");
        // v8x: 客户端虚拟地址 10.77.0.2（Clash MIX 固定热点 IP 思想——虚拟网段固定便于排障）
        b.addAddress("10.77.0.2", 32);
        b.addRoute("0.0.0.0", 0);
        if (Build.VERSION.SDK_INT >= 21) {
            try {
                // IPv6 双栈（dart:io App 常走 v6；失败不阻塞——有些设备无 v6 地址）
                b.addAddress("fd77:0:0:2::2", 128);
                b.addRoute("::", 0);
            } catch (Throwable t) {
                DebugLog.get().logNoMirror("SpyVpnService", "v6 addr/route FAIL: " + t);
            }
        }
        vpnFd = b.establish();
        if (vpnFd == null) {
            DebugLog.get().logNoMirror("SpyVpnService", "establish() = null（用户未授权？）");
            stopSelf();
            TunController c = TunController.get();
            if (c != null) c.onVpnStopped();
            return;
        }
        running = true;
        // VpnService 官方模式：FileInputStream/FileOutputStream 读写 fd
        loop = new PacketLoop(new java.io.FileInputStream(vpnFd.getFileDescriptor()),
                new java.io.FileOutputStream(vpnFd.getFileDescriptor()),
                new ProtectorImpl());
        String err = loop.start();
        if (err != null) {
            DebugLog.get().logNoMirror("SpyVpnService", "PacketLoop start FAIL: " + err);
            try { vpnFd.close(); } catch (Throwable t) { }
            vpnFd = null;
            running = false;
            stopSelf();
            TunController c = TunController.get();
            if (c != null) c.onVpnStopped();
            return;
        }
        TunController c = TunController.get();
        if (c != null) c.onVpnFdReady(loop);
        DebugLog.get().logNoMirror("SpyVpnService", "TUN established, PacketLoop running");
    }

    /** 出口 socket 防回环（PacketLoop 调用） */
    private class ProtectorImpl implements PacketLoop.Protector {
        @Override
        public void protect(java.net.Socket s) {
            try { SpyVpnService.this.protect(s); } catch (Throwable t) { }
        }

        @Override
        public void protect(java.net.DatagramSocket s) {
            try { SpyVpnService.this.protect(s); } catch (Throwable t) { }
        }
    }

    @Override
    public void onDestroy() {
        DebugLog.get().logNoMirror("SpyVpnService", "onDestroy");
        running = false;
        if (loop != null) {
            try { loop.close(); } catch (Throwable t) { }
            loop = null;
        }
        if (vpnFd != null) {
            try { vpnFd.close(); } catch (Throwable t) { }
            vpnFd = null;
        }
        try { stopForeground(true); } catch (Throwable t) { }
        TunController c = TunController.get();
        if (c != null) c.onVpnStopped();
        super.onDestroy();
    }

    private void startForegroundCompat() {
        NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel ch = new NotificationChannel(CHANNEL_ID, "SpyProbe TUN",
                    NotificationManager.IMPORTANCE_LOW);
            nm.createNotificationChannel(ch);
        }
        Intent i = new Intent(this, com.dustinky.spyprobe.MainActivity.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, i,
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        // minSdk 26：Notification.Builder(context, channel) 直用
        Notification n = new Notification.Builder(this, CHANNEL_ID)
                .setContentTitle("SpyProbe TUN 抓包中")
                .setContentText("记录目标 App 网络流量（观察透传，不改数据）")
                .setSmallIcon(android.R.drawable.ic_menu_compass)
                .setContentIntent(pi)
                .build();
        startForeground(NOTIF_ID, n);
    }
}
