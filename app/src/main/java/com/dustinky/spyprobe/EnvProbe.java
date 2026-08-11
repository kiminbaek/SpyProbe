package com.dustinky.spyprobe;

import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.view.Window;
import android.view.WindowManager;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import io.github.libxposed.api.XposedModule;

/**
 * v1.9: 环境检测探测 —— 记录目标 App 在"检测什么"
 *
 * 借鉴 AdClose（HideEnvi / HideVPNStatus / DisableShakeAd / DisableFlagSecure /
 * AntiEmulatorDetection），把"隐藏环境"反转成"探测记录"：
 * 反编译/逆向时，知道 app 调用过哪些检测 API，就知道要绕过什么。
 *
 * 覆盖：
 *  1. File.exists 敏感路径            -> Root / Magisk / Xposed 检测
 *  2. Runtime.exec 命令               -> su / which / getprop / magisk 探测
 *  3. System.getProperty / SystemProperties.get -> ro.debuggable / ro.secure / 代理 / magisk / xposed
 *  4. NetworkInterface + NetworkInfo + NetworkCapabilities -> VPN 检测
 *  5. SensorManager.registerListener   -> 摇一摇/加速度计广告跳转检测
 *  6. Window / Dialog / LayoutParams   -> FLAG_SECURE 防截屏
 *  7. ClipboardManager.getPrimaryClip  -> 剪贴板读取
 *  8. TelephonyManager 设备指纹        -> getDeviceId / getLine1Number / getSimOperator ...
 *
 * 默认随 Config.envCapture 开关（默认 true，仅敏感命中才记录，不刷屏）。
 */
public class EnvProbe {

    static final String TAG = "SpyProbe.Env";
    static final int FLAG_SECURE = 0x00002000;

    private final XposedModule module;
    private final ClassLoader appCl;

    // v1.54 P2: 传感器日志限频（同 type 5s 内只记一次）
    private static final java.util.Map<Integer, Long> sensorLastLog = new java.util.concurrent.ConcurrentHashMap<>();

    public EnvProbe(XposedModule module, ClassLoader appCl) {
        this.module = module;
        this.appCl = appCl;
    }

    // ===== Root / Magisk / Xposed 敏感路径（AdClose SENSITIVE_PATHS + 补充）=====
    private static final Set<String> SENSITIVE_PATHS = new HashSet<>(Arrays.asList(
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
            "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su",
            "/system/bin/.ext/.su", "/data/adb/magisk", "/data/adb/lspd",
            "/system/usr/we-need-root/", "/system/app/Superuser.apk",
            "/system/etc/init.d/99SuperSUDaemon", "/data/adb/ksu",
            "/system/xbin/which", "/system/app/magisk.apk",
            "/data/local/tmp/frida", "/data/local/tmp/frida-server"
    ));

    // ===== System.getProperty / SystemProperties 敏感键 =====
    private static final Set<String> SENSITIVE_PROPS = new HashSet<>(Arrays.asList(
            "ro.debuggable", "ro.secure", "ro.build.tags", "ro.build.type",
            "http.proxyHost", "http.proxyPort", "https.proxyHost", "https.proxyPort"
    ));

    // ===== VPN 接口名（tun/ppp 开头）=====
    private static boolean isVpnInterface(String name) {
        return name != null && (name.startsWith("tun") || name.startsWith("ppp") || name.startsWith("wg"));
    }

    public void install(String phase) {
        // v1.37 P0-1: 惰性安装——开关关闭时完全不装 hook（借鉴 Guise activeHookFeatures，
        //   用户关闭的探测项在目标进程零 hook 存在，减少崩溃面 + 更隐蔽 + 启动更快）
        if (!Config.get().envCapture) {
            DebugLog.get().logNoMirror("Env", "install(" + phase + ") skipped: Config.get().envCapture == false");
            return;
        }
        installFileExists(phase);
        installRuntimeExec(phase);
        installSystemProperties(phase);
        installVpnDetection(phase);
        installSensorListener(phase);
        installFlagSecure(phase);
        installClipboard(phase);
        installTelephony(phase);
    }

    // ===== 1. File.exists 敏感路径 =====
    private void installFileExists(String phase) {
        try {
            final Method exists = java.io.File.class.getMethod("exists");
            module.hook(exists).intercept(chain -> {
                boolean r = (Boolean) chain.proceed();
                // v1.15 P1-6: 去掉 "&& r" —— app 检测 su 返回 false（正常环境）也要记录检测行为本身
                if (Config.get().envCapture) {
                    Object f = chain.getThisObject();
                    if (f instanceof java.io.File) {
                        String path = ((java.io.File) f).getAbsolutePath();
                        for (String sp : SENSITIVE_PATHS) {
                            if (path.contains(sp)) {
                                logDetectEvent("Root检测", "File.exists: " + path + " -> " + r);
                                break;
                            }
                        }
                    }
                }
                return r;
            });
            DebugLog.get().logNoMirror(TAG, "[" + phase + "] hooked File.exists");
        } catch (Throwable t) {
            DebugLog.get().logNoMirror(TAG, "[" + phase + "] File.exists hook fail: " + t);
        }
    }

    // ===== 2. Runtime.exec 命令探测 =====
    private void installRuntimeExec(String phase) {
        try {
            Class<?> rt = Runtime.class;
            int hooked = 0;
            for (Method m : rt.getDeclaredMethods()) {
                if (!m.getName().equals("exec")) continue;
                module.hook(m).intercept(chain -> {
                    Object r;
                    try {
                        r = chain.proceed();
                    } catch (Throwable t) {
                        if (Config.get().envCapture && isSuspiciousCommand(chain.getArg(0))) {
                            logDetectEvent("命令探测", "Runtime.exec FAIL: "
                                    + commandToString(chain.getArg(0)) + " -> " + t);
                        }
                        throw t;
                    }
                    if (Config.get().envCapture && isSuspiciousCommand(chain.getArg(0))) {
                        logDetectEvent("命令探测", "Runtime.exec: " + commandToString(chain.getArg(0)));
                    }
                    return r;
                });
                hooked++;
            }
            DebugLog.get().logNoMirror(TAG, "[" + phase + "] hooked Runtime.exec x" + hooked);
        } catch (Throwable t) {
            DebugLog.get().logNoMirror(TAG, "[" + phase + "] Runtime.exec hook fail: " + t);
        }
    }

    private static boolean isSuspiciousCommand(Object arg) {
        if (arg == null) return false;
        String cmd = commandToString(arg).toLowerCase();
        return cmd.contains("su ") || cmd.contains(" su") || cmd.startsWith("su")
                || cmd.contains("which") || cmd.contains("getprop")
                || cmd.contains("magisk") || cmd.contains("mount")
                || cmd.contains("/system/bin/") || cmd.contains("/system/xbin/");
    }

    private static String commandToString(Object arg) {
        if (arg instanceof String[]) {
            return String.join(" ", (String[]) arg);
        }
        return String.valueOf(arg);
    }

    // ===== 3. System.getProperty + SystemProperties.get =====
    private void installSystemProperties(String phase) {
        try {
            final Method gp = System.class.getMethod("getProperty", String.class);
            module.hook(gp).intercept(chain -> {
                Object r = chain.proceed();
                if (Config.get().envCapture) {
                    Object key = chain.getArg(0);
                    if (key instanceof String && SENSITIVE_PROPS.contains(key)) {
                        logDetectEvent("属性探测", "System.getProperty(" + key + ") = " + r);
                    }
                }
                return r;
            });
            DebugLog.get().logNoMirror(TAG, "[" + phase + "] hooked System.getProperty");
        } catch (Throwable t) {
            DebugLog.get().logNoMirror(TAG, "[" + phase + "] System.getProperty hook fail: " + t);
        }

        // android.os.SystemProperties 是 @hide，反射加载
        try {
            Class<?> sp = Class.forName("android.os.SystemProperties", false, appCl);
            int hooked = 0;
            for (Method m : sp.getDeclaredMethods()) {
                if (!m.getName().equals("get") && !m.getName().equals("getInt") && !m.getName().equals("getBoolean")) continue;
                module.hook(m).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().envCapture) {
                        Object key = chain.getArg(0);
                        String ks = String.valueOf(key).toLowerCase();
                        if (ks.contains("debuggable") || ks.contains("secure")
                                || ks.contains("magisk") || ks.contains("xposed")
                                || ks.contains("frida") || ks.contains("proxy")) {
                            logDetectEvent("属性探测", "SystemProperties." + chain.getExecutable().getName()
                                    + "(" + key + ") = " + r);
                        }
                    }
                    return r;
                });
                hooked++;
            }
            DebugLog.get().logNoMirror(TAG, "[" + phase + "] hooked SystemProperties x" + hooked);
        } catch (Throwable t) {
            DebugLog.get().logNoMirror(TAG, "[" + phase + "] SystemProperties hook fail: " + t);
        }
    }

    // ===== 4. VPN 检测（NetworkInterface / NetworkInfo / NetworkCapabilities）=====
    private void installVpnDetection(String phase) {
        try {
            // NetworkInterface.isUp() / getName() / isVirtual()
            Class<?> ni = java.net.NetworkInterface.class;
            for (Method m : ni.getDeclaredMethods()) {
                if (m.getName().equals("isUp") || m.getName().equals("getName") || m.getName().equals("isVirtual")) {
                    module.hook(m).intercept(chain -> {
                        Object r = chain.proceed();
                        if (Config.get().envCapture) {
                            Object self = chain.getThisObject();
                            String nm = null;
                            try {
                                // v1.16 P1-1: 修递归——此前 getName() hook 内再调 getName() 无限递归（栈溢出被吞→VPN 检测失效）
                                if (m.getName().equals("getName")) {
                                    // r 就是接口名（原始实现返回值），直接用
                                    nm = r != null ? String.valueOf(r) : null;
                                } else {
                                    // isUp/isVirtual：反射读 NetworkInterface.name 字段，不再调用被 hook 的 getName()
                                    java.lang.reflect.Field f = java.net.NetworkInterface.class.getDeclaredField("name");
                                    f.setAccessible(true);
                                    Object v = f.get(self);
                                    nm = v != null ? String.valueOf(v) : null;
                                }
                            } catch (Throwable t) { }

                            if (isVpnInterface(nm)) {
                                logDetectEvent("VPN检测", "NetworkInterface." + m.getName()
                                        + "(" + nm + ") = " + r);
                            }
                        }
                        return r;
                    });
                }
            }
            DebugLog.get().logNoMirror(TAG, "[" + phase + "] hooked NetworkInterface");
        } catch (Throwable t) {
            DebugLog.get().logNoMirror(TAG, "[" + phase + "] NetworkInterface hook fail: " + t);
        }

        try {
            // NetworkInfo.getType() -> TYPE_VPN(17)
            Class<?> ni = Class.forName("android.net.NetworkInfo", false, appCl);
            for (Method m : ni.getDeclaredMethods()) {
                if (m.getName().equals("getType")) {
                    module.hook(m).intercept(chain -> {
                        Object r = chain.proceed();
                        if (Config.get().envCapture && r instanceof Integer
                                && (Integer) r == android.net.ConnectivityManager.TYPE_VPN) {
                            logDetectEvent("VPN检测", "NetworkInfo.getType() = TYPE_VPN (17)");
                        }
                        return r;
                    });
                }
            }
            DebugLog.get().logNoMirror(TAG, "[" + phase + "] hooked NetworkInfo.getType");
        } catch (Throwable t) {
            DebugLog.get().logNoMirror(TAG, "[" + phase + "] NetworkInfo hook fail: " + t);
        }

        try {
            // NetworkCapabilities.hasTransport(TRANSPORT_VPN=4)
            Class<?> nc = Class.forName("android.net.NetworkCapabilities", false, appCl);
            for (Method m : nc.getDeclaredMethods()) {
                if (m.getName().equals("hasTransport")) {
                    module.hook(m).intercept(chain -> {
                        Object r = chain.proceed();
                        if (Config.get().envCapture && r instanceof Boolean
                                && (Boolean) r) {
                            Object arg = chain.getArg(0);
                            if (arg instanceof Integer && (Integer) arg == 4) {
                                logDetectEvent("VPN检测", "NetworkCapabilities.hasTransport(TRANSPORT_VPN)");
                            }
                        }
                        return r;
                    });
                }
            }
            DebugLog.get().logNoMirror(TAG, "[" + phase + "] hooked NetworkCapabilities.hasTransport");
        } catch (Throwable t) {
            DebugLog.get().logNoMirror(TAG, "[" + phase + "] NetworkCapabilities hook fail: " + t);
        }
    }

    // ===== 5. 传感器监听（摇一摇/加速度计）=====
    private void installSensorListener(String phase) {
        try {
            Class<?> sm = SensorManager.class;
            int hooked = 0;
            for (Method m : sm.getDeclaredMethods()) {
                if (!m.getName().equals("registerListener")) continue;
                module.hook(m).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().envCapture && chain.getArgs().size() >= 2) {
                        Object sensor = chain.getArg(1);
                        if (sensor instanceof Sensor) {
                            int type = ((Sensor) sensor).getType();
                            if (type == Sensor.TYPE_ACCELEROMETER
                                    || type == Sensor.TYPE_GYROSCOPE
                                    || type == Sensor.TYPE_GRAVITY
                                    || type == Sensor.TYPE_ROTATION_VECTOR) {
                                // v1.54 P2: 同 type 5s 限频（多次 registerListener 同传感器 → 刷屏）
                                long now = System.currentTimeMillis();
                                Long prev = sensorLastLog.get(type);
                                if (prev == null || now - prev >= 5000) {
                                    sensorLastLog.put(type, now);
                                    logDetectEvent("传感器探测", "registerListener type=" + type
                                            + " (摇一摇/方向广告跳转?)");
                                }
                            }
                        }
                    }
                    return r;
                });
                hooked++;
            }
            DebugLog.get().logNoMirror(TAG, "[" + phase + "] hooked SensorManager.registerListener x" + hooked);
        } catch (Throwable t) {
            DebugLog.get().logNoMirror(TAG, "[" + phase + "] SensorManager hook fail: " + t);
        }
    }

    // ===== 6. FLAG_SECURE 防截屏探测 =====
    private void installFlagSecure(String phase) {
        try {
            for (Method m : Window.class.getDeclaredMethods()) {
                if (m.getName().equals("setFlags") || m.getName().equals("addFlags")) {
                    module.hook(m).intercept(chain -> {
                        Object r = chain.proceed();
                        if (Config.get().envCapture) {
                            Object arg0 = chain.getArg(0);
                            if (arg0 instanceof Integer && ((Integer) arg0 & FLAG_SECURE) != 0) {
                                logDetectEvent("防截屏探测", "Window." + m.getName() + " FLAG_SECURE(0x2000)");
                            }
                        }
                        return r;
                    });
                }
            }
            // Dialog.setFlags
            for (Method m : android.app.Dialog.class.getDeclaredMethods()) {
                if (m.getName().equals("setFlags") || m.getName().equals("addFlags")) {
                    module.hook(m).intercept(chain -> {
                        Object r = chain.proceed();
                        if (Config.get().envCapture) {
                            Object arg0 = chain.getArg(0);
                            if (arg0 instanceof Integer && ((Integer) arg0 & FLAG_SECURE) != 0) {
                                logDetectEvent("防截屏探测", "Dialog." + m.getName() + " FLAG_SECURE(0x2000)");
                            }
                        }
                        return r;
                    });
                }
            }
            DebugLog.get().logNoMirror(TAG, "[" + phase + "] hooked Window/Dialog flags");
        } catch (Throwable t) {
            DebugLog.get().logNoMirror(TAG, "[" + phase + "] Window flags hook fail: " + t);
        }
    }

    // ===== 7. 剪贴板读取 =====
    private void installClipboard(String phase) {
        try {
            final Method gpc = android.content.ClipboardManager.class.getMethod("getPrimaryClip");
            module.hook(gpc).intercept(chain -> {
                Object r = chain.proceed();
                if (Config.get().envCapture && r != null) {
                    String content = "";
                    try {
                        if (r instanceof android.content.ClipData) {
                            android.content.ClipData cd = (android.content.ClipData) r;
                            if (cd.getItemCount() > 0) {
                                CharSequence cs = null;
                                // ActivityThread 是 @hide，编译 classpath 没有 → 反射拿 context（coerceToText 需要）
                                try {
                                    java.lang.reflect.Method cur = Class.forName("android.app.ActivityThread")
                                            .getMethod("currentApplication");
                                    android.content.Context ctx = (android.content.Context) cur.invoke(null);
                                    if (ctx != null) cs = cd.getItemAt(0).coerceToText(ctx);
                                } catch (Throwable t) { }
                                if (cs == null) cs = cd.getItemAt(0).getText();
                                if (cs != null) content = cs.toString();
                            }
                        }
                    } catch (Throwable t) { }
                    logClipEvent(content);
                }
                return r;
            });
            DebugLog.get().logNoMirror(TAG, "[" + phase + "] hooked ClipboardManager.getPrimaryClip");
        } catch (Throwable t) {
            DebugLog.get().logNoMirror(TAG, "[" + phase + "] Clipboard hook fail: " + t);
        }
    }

    // ===== 8. TelephonyManager 设备指纹 =====
    private void installTelephony(String phase) {
        try {
            Class<?> tm = android.telephony.TelephonyManager.class;
            Set<String> targets = new HashSet<>(Arrays.asList(
                    "getDeviceId", "getLine1Number", "getSimOperator", "getSimOperatorName",
                    "getSubscriberId", "getNetworkOperator", "getNetworkCountryIso", "getSimSerialNumber"
            ));
            int hooked = 0;
            for (Method m : tm.getDeclaredMethods()) {
                if (!targets.contains(m.getName())) continue;
                module.hook(m).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().envCapture && r != null) {
                        String val = String.valueOf(r);
                        if (val.length() > 24) val = val.substring(0, 24) + "...";
                        logDetectEvent("设备指纹", "TelephonyManager." + m.getName() + " = " + val);
                    }
                    return r;
                });
                hooked++;
            }
            DebugLog.get().logNoMirror(TAG, "[" + phase + "] hooked TelephonyManager x" + hooked);
        } catch (Throwable t) {
            DebugLog.get().logNoMirror(TAG, "[" + phase + "] TelephonyManager hook fail: " + t);
        }
    }

    /** v1.58: 环境检测命中 → 结构化 DETECT 事件（卡片 + 详情页）。
     *  反编译价值：知道 app 检测什么（root/xposed/VPN/防截屏/设备指纹）= 知道要绕过什么。
     *  payload: what/kind/detail/stack */
    private static void logDetectEvent(String kind, String detail) {
        try {
            long eid = EventStore.get().nextId();
            String msg = "[EVT#" + eid + "][" + kind + "] " + detail;
            LogStore.get().log(TAG, msg);
            org.json.JSONObject payload = new org.json.JSONObject();
            payload.put("kind", kind == null ? "" : kind);
            payload.put("detail", detail == null ? "" : detail);
            String stack = StackUtil.getCompact(10);
            EventStore.get().add(new SpyEvent("DETECT", eid, System.currentTimeMillis(),
                    kind, payload, msg, stack));
        } catch (Throwable t) { /* 结构化失败不影响文本日志 */ }
    }

    /** v1.58: 剪贴板读取 → 结构化 CLIP 事件（内容 + 调用栈）。 */
    private static void logClipEvent(String content) {
        try {
            long eid = EventStore.get().nextId();
            String msg = "[EVT#" + eid + "][剪贴板探测] 有内容" + (content == null || content.isEmpty() ? "" : ": " + content);
            LogStore.get().log(TAG, msg);
            org.json.JSONObject payload = new org.json.JSONObject();
            payload.put("content", content == null ? "" : content);
            String stack = StackUtil.getCompact(10);
            String title = content == null || content.isEmpty() ? "剪贴板读取" : content;
            if (title.length() > 90) title = title.substring(0, 90) + "…";
            EventStore.get().add(new SpyEvent("CLIP", eid, System.currentTimeMillis(),
                    title, payload, msg, stack));
        } catch (Throwable t) { /* 结构化失败不影响文本日志 */ }
    }
}
