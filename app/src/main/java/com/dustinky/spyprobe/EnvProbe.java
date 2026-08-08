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
                if (Config.get().envCapture && r) {
                    Object f = chain.getThisObject();
                    if (f instanceof java.io.File) {
                        String path = ((java.io.File) f).getAbsolutePath();
                        for (String sp : SENSITIVE_PATHS) {
                            if (path.contains(sp)) {
                                LogStore.get().log(TAG, "[Root检测] File.exists: " + path
                                        + " <- " + StackUtil.getCompact());
                                break;
                            }
                        }
                    }
                }
                return r;
            });
            LogStore.get().log(TAG, "[" + phase + "] hooked File.exists");
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] File.exists hook fail: " + t);
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
                            LogStore.get().log(TAG, "[命令探测] Runtime.exec FAIL: "
                                    + commandToString(chain.getArg(0)) + " -> " + t);
                        }
                        throw t;
                    }
                    if (Config.get().envCapture && isSuspiciousCommand(chain.getArg(0))) {
                        LogStore.get().log(TAG, "[命令探测] Runtime.exec: "
                                + commandToString(chain.getArg(0)) + " <- " + StackUtil.getCompact());
                    }
                    return r;
                });
                hooked++;
            }
            LogStore.get().log(TAG, "[" + phase + "] hooked Runtime.exec x" + hooked);
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] Runtime.exec hook fail: " + t);
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
                        LogStore.get().log(TAG, "[属性探测] System.getProperty(" + key + ") = " + r
                                + " <- " + StackUtil.getCompact());
                    }
                }
                return r;
            });
            LogStore.get().log(TAG, "[" + phase + "] hooked System.getProperty");
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] System.getProperty hook fail: " + t);
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
                            LogStore.get().log(TAG, "[属性探测] SystemProperties." + chain.getExecutable().getName()
                                    + "(" + key + ") = " + r + " <- " + StackUtil.getCompact());
                        }
                    }
                    return r;
                });
                hooked++;
            }
            LogStore.get().log(TAG, "[" + phase + "] hooked SystemProperties x" + hooked);
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] SystemProperties hook fail: " + t);
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
                                nm = self instanceof java.net.NetworkInterface
                                        ? ((java.net.NetworkInterface) self).getName() : null;
                            } catch (Throwable t) { }
                            if (isVpnInterface(nm)) {
                                LogStore.get().log(TAG, "[VPN检测] NetworkInterface." + m.getName()
                                        + "(" + nm + ") = " + r + " <- " + StackUtil.getCompact());
                            }
                        }
                        return r;
                    });
                }
            }
            LogStore.get().log(TAG, "[" + phase + "] hooked NetworkInterface");
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] NetworkInterface hook fail: " + t);
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
                            LogStore.get().log(TAG, "[VPN检测] NetworkInfo.getType() = TYPE_VPN (17)"
                                    + " <- " + StackUtil.getCompact());
                        }
                        return r;
                    });
                }
            }
            LogStore.get().log(TAG, "[" + phase + "] hooked NetworkInfo.getType");
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] NetworkInfo hook fail: " + t);
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
                                LogStore.get().log(TAG, "[VPN检测] NetworkCapabilities.hasTransport(TRANSPORT_VPN)"
                                        + " <- " + StackUtil.getCompact());
                            }
                        }
                        return r;
                    });
                }
            }
            LogStore.get().log(TAG, "[" + phase + "] hooked NetworkCapabilities.hasTransport");
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] NetworkCapabilities hook fail: " + t);
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
                                LogStore.get().log(TAG, "[传感器探测] registerListener type=" + type
                                        + " (摇一摇/方向广告跳转?) <- " + StackUtil.getCompact());
                            }
                        }
                    }
                    return r;
                });
                hooked++;
            }
            LogStore.get().log(TAG, "[" + phase + "] hooked SensorManager.registerListener x" + hooked);
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] SensorManager hook fail: " + t);
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
                                LogStore.get().log(TAG, "[防截屏探测] Window." + m.getName()
                                        + " FLAG_SECURE(0x2000) <- " + StackUtil.getCompact());
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
                                LogStore.get().log(TAG, "[防截屏探测] Dialog." + m.getName()
                                        + " FLAG_SECURE(0x2000) <- " + StackUtil.getCompact());
                            }
                        }
                        return r;
                    });
                }
            }
            LogStore.get().log(TAG, "[" + phase + "] hooked Window/Dialog flags");
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] Window flags hook fail: " + t);
        }
    }

    // ===== 7. 剪贴板读取 =====
    private void installClipboard(String phase) {
        try {
            final Method gpc = android.content.ClipboardManager.class.getMethod("getPrimaryClip");
            module.hook(gpc).intercept(chain -> {
                Object r = chain.proceed();
                if (Config.get().envCapture && r != null) {
                    LogStore.get().log(TAG, "[剪贴板探测] getPrimaryClip() 有内容 <- " + StackUtil.getCompact());
                }
                return r;
            });
            LogStore.get().log(TAG, "[" + phase + "] hooked ClipboardManager.getPrimaryClip");
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] Clipboard hook fail: " + t);
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
                        LogStore.get().log(TAG, "[设备指纹] TelephonyManager." + m.getName()
                                + " = " + val + " <- " + StackUtil.getCompact());
                    }
                    return r;
                });
                hooked++;
            }
            LogStore.get().log(TAG, "[" + phase + "] hooked TelephonyManager x" + hooked);
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] TelephonyManager hook fail: " + t);
        }
    }
}
