package com.dustinky.spyprobe;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import io.github.libxposed.api.XposedModule;

/**
 * 类加载探测（v1.2 新增）：
 * hook ClassLoader.loadClass(String) 记录目标 App 加载的类名。
 * 配合关键字过滤（Config.classFilter），可快速定位核心逻辑类。
 *
 * 用途：反编译时知道 app 加载了哪些类 = 核心逻辑在哪。
 */
public class ClassLoadProbe {

    static final String TAG = "SpyProbe.Cls";

    private static final int MAX_CLASSES = 5000;
    private final Set<String> loaded = new LinkedHashSet<>(); // 有序去重

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
    public synchronized void record(String name) {
        if (name == null || name.isEmpty()) return;
        // v1.6: 过滤数组类/内部符号（"[Lxxx;"/"xxx/yyy"），只保留规范类名
        if (name.startsWith("[") || name.startsWith("L") || name.indexOf('/') >= 0) return;
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
        // 防无限增长
        if (loaded.size() > MAX_CLASSES) {
            // 淘汰最早一半
            List<String> all = new ArrayList<>(loaded);
            loaded.clear();
            for (int i = all.size() / 2; i < all.size(); i++) {
                loaded.add(all.get(i));
            }
        }
    }

    /** 当前记录的类名（可选关键字过滤，返回 JSON：count/total/classes 数组） */
    public synchronized String list(String filter) {
        org.json.JSONArray arr = new org.json.JSONArray();
        for (String c : loaded) {
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

    public synchronized int size() {
        return loaded.size();
    }
}
