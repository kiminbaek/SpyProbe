package com.dustinky.spyprobe;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import io.github.libxposed.api.XposedModule;

/**
 * 类加载探测（v1.2 新增）：
 * hook ClassLoader.loadClass(String) 记录目标 App 加载的类名。
 * 用途：反编译时知道 app 加载了哪些类 = 核心逻辑在哪。
 */
public class ClassLoadProbe {

    static final String TAG = "SpyProbe.Cls";

    private static final int MAX_CLASSES = 5000;
    // v1.16 P1-2: LinkedHashSet + 全同步锁 → ConcurrentHashMap.newKeySet（loadClass 超高频，避免启动期全部串行化）
    private final Set<String> loaded = ConcurrentHashMap.newKeySet();

    private final XposedModule module;
    private final ClassLoader appCl;
    // v1.19 探测 b: 自动 hook 联动（类加载时调 MethodProbe.hookClassAuto）
    private final MethodProbe mth;

    public ClassLoadProbe(XposedModule module, ClassLoader appCl, MethodProbe mth) {
        this.module = module;
        this.appCl = appCl;
        this.mth = mth;
    }

    public synchronized void install(String phase) {
        // v1.37 P0-1: 惰性安装——开关关闭时完全不装 hook（借鉴 Guise activeHookFeatures，
        //   用户关闭的探测项在目标进程零 hook 存在，减少崩溃面 + 更隐蔽 + 启动更快）
        if (!Config.get().classCapture) {
            DebugLog.get().logNoMirror("ClassLoad", "install(" + phase + ") skipped: Config.get().classCapture == false");
            return;
        }
        // hook 基类 ClassLoader.loadClass(String)（子类会继承，hook 基类一次覆盖所有 loader）
        // v1.19 P2-4: 1 参重载是 2 参的包装（loadClass(name) 内部调 loadClass(name,false)），
        //   两个 hook 都 record 会每条刷 2 次 —— 1 参只 proceed，统一由 2 参记录
        try {
            final Method loadClass = ClassLoader.class.getDeclaredMethod("loadClass", String.class);
            loadClass.setAccessible(true);
            module.hook(loadClass).intercept(chain -> chain.proceed());
            LogStore.get().log(TAG, "[" + phase + "] hooked ClassLoader.loadClass(String)");
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] ClassLoader.loadClass hook fail: " + t);
        }

        // hook 带 resolve 的重载（部分加载路径走这个；也是 1 参的内部实现 → 统一在此记录）
        try {
            final Method loadClass2 = ClassLoader.class.getDeclaredMethod("loadClass", String.class, boolean.class);
            loadClass2.setAccessible(true);
            module.hook(loadClass2).intercept(chain -> {
                Object r = chain.proceed();
                if (Config.get().classCapture) {
                    Object name = chain.getArg(0);
                    if (name instanceof String) {
                        record((String) name);
                    }
                }
                return r;
            });
            LogStore.get().log(TAG, "[" + phase + "] hooked ClassLoader.loadClass(String,boolean)");
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] ClassLoader.loadClass(String,boolean) hook fail: " + t);
        }
    }

    /** v1.58: 类加载 → 结构化 CLASS 事件（卡片 + 详情页，仅 classLogAll 开启时）。
     *  反编译价值：知道 app 加载了哪些类 = 核心逻辑在哪。 */
    private static void logClassEvent(String name) {
        try {
            long eid = EventStore.get().nextId();
            String msg = "[EVT#" + eid + "][class] " + name;
            LogStore.get().log(TAG, msg);
            org.json.JSONObject payload = new org.json.JSONObject();
            payload.put("name", name == null ? "" : name);
            EventStore.get().add(new SpyEvent("CLASS", eid, System.currentTimeMillis(),
                    name, payload, msg, ""));
        } catch (Throwable t) { /* 结构化失败不影响文本日志 */ }
    }

    /** 记录类名（匹配过滤器才记录；不匹配也做去重统计） */
    public void record(String name) {
        // v1.16 P1-2: 去 synchronized（loadClass 超高频，避免目标 app 启动期类加载全部串行化）；
        // filter/内部符号判断放锁外，无锁只做 ConcurrentHashMap 写
        if (name == null || name.isEmpty()) return;
        // v1.7: 只过滤真正的 JVM 内部符号，不再误杀 L 开头的正常类：
        //   "[Lxxx;" / "[I" —— 数组描述符
        //   "Lcom/foo/Bar;" —— 内部描述符（L 开头且分号结尾）
        //   "com/foo/Bar"   —— 斜杠格式
        // 注意：LocationManager/ListView/LinearLayout 等以 L 开头的规范类名必须保留
        if (name.startsWith("[") || (name.startsWith("L") && name.endsWith(";")) || name.indexOf('/') >= 0) return;
        String filter = Config.get().classFilter;
        if (filter != null && !filter.isEmpty()) {
            // 过滤非匹配项，只保留含关键字的类（记录到日志，帮助定位）
            if (name.contains(filter)) {
                loaded.add(name);
                if (Config.get().classLogAll) {
                    logClassEvent(name);
                }
            }
        } else {
            // v1.47 P2-21: 无过滤模式下默认剔除纯系统类——android.*/java.* 平台类会占满
            //   MAX_CLASSES 5000 上限，随机淘汰一半时目标 App 自己的类可能被挤掉。
            //   第三方库类（okhttp3/gson 等）保留：逆向同样有价值。
            if (isSystemClass(name)) return;
            // 无过滤：只入库不刷屏（最多 MAX_CLASSES）
            loaded.add(name);
        }
        // v1.19 探测 b: 全自动探测 —— 类加载时自动 hook 该类全部方法（类名已过滤内部符号）
        if (Config.get().autoProbe && mth != null) {
            String af = Config.get().autoProbeFilter;
            if (af != null && !af.isEmpty()) {
                if (name.contains(af)) mth.hookClassAuto(name);
            } else {
                mth.hookClassAuto(name); // hookClassAuto 内部过滤系统类/接口
            }
        }
        // 防无限增长（无序集合，随机淘汰一半；类名仅日志/查询用途，顺序不敏感）
        if (loaded.size() > MAX_CLASSES) {
            int drop = loaded.size() / 2;
            java.util.Iterator<String> it = loaded.iterator();
            while (drop-- > 0 && it.hasNext()) {
                it.next();
                it.remove();
            }
        }
    }

    // v1.47 P2-21: 纯系统平台类前缀（这些类 100% 不是目标 App 核心逻辑，无过滤模式下剔除）
    private static boolean isSystemClass(String name) {
        return name.startsWith("android.") || name.startsWith("java.")
                || name.startsWith("javax.") || name.startsWith("sun.")
                || name.startsWith("jdk.") || name.startsWith("dalvik.")
                || name.startsWith("kotlin.") || name.startsWith("kotlinx.")
                || name.startsWith("com.android.");
    }

    /** 当前记录的类名（可选关键字过滤，返回 JSON：count/total/classes 数组） */    public String list(String filter) {
        // v1.16 P1-2: CHM 弱一致并发读，先快照再排序（输出稳定，替代 LinkedHashSet 顺序）
        List<String> snapshot = new ArrayList<>(loaded);
        Collections.sort(snapshot);
        org.json.JSONArray arr = new org.json.JSONArray();
        for (String c : snapshot) {
            if (filter != null && !filter.isEmpty() && !c.contains(filter)) continue;
            arr.put(c);
        }
        org.json.JSONObject o = new org.json.JSONObject();
        try {
            o.put("ok", true);
            o.put("count", arr.length());
            o.put("total", loaded.size());
            o.put("classes", arr);
        } catch (Throwable t) { }
        return o.toString();
    }

    public int size() {
        return loaded.size();
    }
}
