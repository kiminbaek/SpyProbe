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

    public ClassLoadProbe(XposedModule module, ClassLoader appCl) {
        this.module = module;
        this.appCl = appCl;
    }

    public synchronized void install(String phase) {
        // hook 基类 ClassLoader.loadClass(String)（子类会继承，hook 基类一次覆盖所有 loader）
        try {
            final Method loadClass = ClassLoader.class.getDeclaredMethod("loadClass", String.class);
            loadClass.setAccessible(true);
            module.hook(loadClass).intercept(chain -> {
                Object r = chain.proceed();
                if (Config.get().classCapture) {
                    Object name = chain.getArg(0);
                    if (name instanceof String) {
                        record((String) name);
                    }
                }
                return r;
            });
            LogStore.get().log(TAG, "[" + phase + "] hooked ClassLoader.loadClass(String)");
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] ClassLoader.loadClass hook fail: " + t);
        }

        // hook 带 resolve 的重载（部分加载路径走这个）
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
                    LogStore.get().log(TAG, "[class] " + name);
                }
            }
        } else {
            // 无过滤：只入库不刷屏（最多 MAX_CLASSES）
            loaded.add(name);
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

    /** 当前记录的类名（可选关键字过滤，返回 JSON：count/total/classes 数组） */
    public String list(String filter) {
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
