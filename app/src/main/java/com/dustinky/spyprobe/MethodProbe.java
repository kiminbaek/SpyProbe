package com.dustinky.spyprobe;

import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.List;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;

/**
 * 函数探测：
 * 1. scanClass(cl) —— 反射枚举类的全部方法（含构造器）+ 字段，返回 JSON
 * 2. hookMethod(cl, name, params) —— 动态 hook 指定方法，打印参数/返回值/调用栈
 */
public class MethodProbe {

    static final String TAG = "SpyProbe.Mth";

    private final XposedModule module;
    private final ClassLoader appCl;

    // v1.19: 全自动探测已处理类集合（防类加载时重复 hook 刷屏 skip 日志）
    private final java.util.Set<String> autoHooked = java.util.concurrent.ConcurrentHashMap.newKeySet();

    public MethodProbe(XposedModule module, ClassLoader appCl) {
        this.module = module;
        this.appCl = appCl;
    }

    /** 枚举类方法（UI 探测用），返回 JSONArray */
    public String scanClass(String className) throws Exception {
        try {
            Class<?> cls = Class.forName(className, false, appCl);
            JSONArray arr = new JSONArray();
            // 构造器
            for (Constructor<?> c : cls.getDeclaredConstructors()) {
                arr.put(describeConstructor(c));
            }
            // 方法（声明 + 继承，去重）
            for (Method m : cls.getDeclaredMethods()) {
                arr.put(describeMethod(m));
            }
            for (Method m : cls.getMethods()) {
                boolean dup = false;
                try {
                    cls.getDeclaredMethod(m.getName(), m.getParameterTypes());
                    dup = true;
                } catch (NoSuchMethodException e) { }
                if (!dup) arr.put(describeMethod(m));
            }
            // P1: 字段枚举（声明 + 继承去重）
            for (Field f : cls.getDeclaredFields()) {
                arr.put(describeField(f));
            }
            for (Field f : cls.getFields()) {
                boolean dup = false;
                try {
                    cls.getDeclaredField(f.getName());
                    dup = true;
                } catch (NoSuchFieldException e) { }
                if (!dup) arr.put(describeField(f));
            }
            JSONObject out = new JSONObject();
            out.put("ok", true);
            out.put("className", className);
            out.put("methods", arr);
            return out.toString();
        } catch (ClassNotFoundException e) {
            JSONObject out = new JSONObject();
            out.put("ok", false);
            out.put("error", "class not found: " + className);
            return out.toString();
        } catch (Throwable t) {
            JSONObject out = new JSONObject();
            out.put("ok", false);
            out.put("error", t.toString());
            return out.toString();
        }
    }

    private JSONObject describeConstructor(Constructor<?> c) {
        JSONObject o = new JSONObject();
        try {
            StringBuilder sig = new StringBuilder(c.getDeclaringClass().getSimpleName()).append("(");
            StringBuilder params = new StringBuilder();
            Class<?>[] pt = c.getParameterTypes();
            for (int i = 0; i < pt.length; i++) {
                if (i > 0) { sig.append(", "); params.append(","); }
                sig.append(typeName(pt[i]));
                params.append(typeName(pt[i]));
            }
            sig.append(")");
            o.put("kind", "constructor");
            o.put("name", c.getDeclaringClass().getSimpleName());
            o.put("signature", sig.toString());
            o.put("params", params.toString());
            o.put("modifiers", Modifier.toString(c.getModifiers()));
            o.put("isStatic", Modifier.isStatic(c.getModifiers()));
        } catch (Throwable t) { }
        return o;
    }

    private JSONObject describeMethod(Method m) {
        JSONObject o = new JSONObject();
        try {
            StringBuilder sig = new StringBuilder(m.getName()).append("(");
            StringBuilder params = new StringBuilder();
            Class<?>[] pt = m.getParameterTypes();
            for (int i = 0; i < pt.length; i++) {
                if (i > 0) { sig.append(", "); params.append(","); }
                sig.append(typeName(pt[i]));
                params.append(typeName(pt[i]));
            }
            sig.append(")");
            o.put("kind", "method");
            o.put("name", m.getName());
            o.put("signature", sig.toString());
            o.put("params", params.toString());
            o.put("returnType", typeName(m.getReturnType()));
            o.put("modifiers", Modifier.toString(m.getModifiers()));
            o.put("isStatic", Modifier.isStatic(m.getModifiers()));
            o.put("isFinal", Modifier.isFinal(m.getModifiers()));
            o.put("isNative", Modifier.isNative(m.getModifiers())); // v1.5: native 方法标记（hook 不到内部，只能 hook 边界）
        } catch (Throwable t) { }
        return o;
    }

    private JSONObject describeField(Field f) {
        JSONObject o = new JSONObject();
        try {
            o.put("kind", "field");
            o.put("name", f.getName());
            o.put("type", typeName(f.getType()));
            o.put("modifiers", Modifier.toString(f.getModifiers()));
            o.put("isStatic", Modifier.isStatic(f.getModifiers()));
            o.put("isFinal", Modifier.isFinal(f.getModifiers()));
            // v1.2: 静态字段读当前值（常量/URL/密钥等反编译直接可用）
            if (Modifier.isStatic(f.getModifiers())) {
                try {
                    f.setAccessible(true);
                    Object v = f.get(null);
                    o.put("value", str(v, 200));
                } catch (Throwable t) {
                    o.put("value", "<unreadable>");
                }
            }
        } catch (Throwable t) { }
        return o;
    }

    /** 可读类型名（int[] → "int[]" 而不是 "[I"） */
    static String typeName(Class<?> c) {
        if (c == null) return "null";
        if (!c.isArray()) return c.getName();
        int dim = 0;
        Class<?> base = c;
        while (base.isArray()) { dim++; base = base.getComponentType(); }
        return base.getName() + "[]".repeat(dim);
    }

    /** hook 指定方法。paramTypes 为空 = hook 全部同名重载 */
    public String hookMethod(String className, String methodName, String paramTypes) throws Exception {
        try {
            Class<?> cls = Class.forName(className, false, appCl);
            if (methodName.equals("<init>")) {
                return hookConstructors(cls, paramTypes);
            }
            return hookMethods(cls, methodName, paramTypes);
        } catch (ClassNotFoundException e) {
            JSONObject out = new JSONObject();
            out.put("ok", false);
            out.put("error", "class not found: " + className);
            return out.toString();
        } catch (Throwable t) {
            JSONObject out = new JSONObject();
            out.put("ok", false);
            out.put("error", t.toString());
            return out.toString();
        }
    }

    private String hookConstructors(Class<?> cls, String paramTypes) throws Throwable {
        int hooked = 0;
        java.util.List<String> candidates = null; // v1.19 P2-3: 0 命中时给候选签名提示
        for (Constructor<?> c : cls.getDeclaredConstructors()) {
            // v1.28 P1: paramTypes 语义统一交给 matchParams —— null=全部重载，""=无参精确，签名串=精确匹配
            if (!matchParams(c.getParameterTypes(), paramTypes)) {
                if (candidates == null) candidates = new java.util.ArrayList<>();
                candidates.add("<init>(" + joinParams(c.getParameterTypes()) + ")");
                continue;
            }
            // v1.7: 句柄 key 用具体签名（防重载全部 hook 时只挂第一个）；paramTypes 仅作 UI 过滤
            String sigKey = joinParams(c.getParameterTypes());
            if (Config.get().hasHandle(cls.getName(), "<init>", sigKey)) {
                LogStore.get().log(TAG, "[hook] skip (already hooked): " + cls.getName() + " <init>(" + sigKey + ")");
                continue;
            }
            XposedInterface.HookHandle h = module.hook(c).intercept(MethodProbe::onInvoke);
            Config.get().addHandle(cls.getName(), "<init>", sigKey, h);
            hooked++;
        }
        JSONObject out = new JSONObject();
        out.put("ok", true);
        out.put("hooked", hooked);
        if (hooked == 0 && candidates != null && !candidates.isEmpty()) {
            // v1.19 P2-3: 参数类型不匹配 → 返回候选重载签名
            StringBuilder note = new StringBuilder("参数不匹配，候选重载: ");
            for (int i = 0; i < candidates.size() && i < 8; i++) {
                if (i > 0) note.append("  ");
                note.append(candidates.get(i));
            }
            if (candidates.size() > 8) note.append(" ... 共 ").append(candidates.size()).append(" 个");
            out.put("note", note.toString());
            LogStore.get().log(TAG, "[hook] <init> 0 match, candidates: " + candidates.size());
        } else {
            out.put("note", cls.getName() + " <init>");
            LogStore.get().log(TAG, "[hook] <init> x" + hooked + " " + cls.getName());
        }
        return out.toString();
    }

    private String hookMethods(Class<?> cls, String methodName, String paramTypes) throws Throwable {
        int hooked = 0;
        // v1.14: 方法名 "*" = hook 类内全部方法（借鉴 SimpleHook findAllMethods 通配）
        boolean allMethods = methodName.equals("*");
        java.util.List<String> candidates = null; // v1.19 P2-3: 0 命中时给候选签名提示
        for (Method m : cls.getDeclaredMethods()) {
            if (!allMethods && !m.getName().equals(methodName)) continue;
            // v1.28 P1: 同上，null=全部重载，""=无参精确
            if (!matchParams(m.getParameterTypes(), paramTypes)) {
                if (candidates == null) candidates = new java.util.ArrayList<>();
                candidates.add(m.getName() + "(" + joinParams(m.getParameterTypes()) + ")");
                continue;
            }
            // v1.7: 句柄 key 用具体签名（防重载全部 hook 时只挂第一个）
            // v1.19 P1-2: key 用真实方法名 m.getName() —— 通配 "*" 时 methodName="*"，
            //   若用它做 key 则 hasHandle 永远查不到已 hook 句柄 → 重复 hook 无限叠加
            String sigKey = joinParams(m.getParameterTypes());
            if (Config.get().hasHandle(cls.getName(), m.getName(), sigKey)) {
                LogStore.get().log(TAG, "[hook] skip (already hooked): " + cls.getName() + "." + m.getName() + "(" + sigKey + ")");
                continue;
            }
            XposedInterface.HookHandle h = module.hook(m).intercept(MethodProbe::onInvoke);
            Config.get().addHandle(cls.getName(), m.getName(), sigKey, h);
            hooked++;
        }
        JSONObject out = new JSONObject();
        out.put("ok", true);
        out.put("hooked", hooked);
        if (hooked == 0 && candidates != null && !candidates.isEmpty()) {
            // v1.19 P2-3: 参数类型不匹配 → 返回候选重载签名
            StringBuilder note = new StringBuilder("参数不匹配，候选重载: ");
            for (int i = 0; i < candidates.size() && i < 8; i++) {
                if (i > 0) note.append("  ");
                note.append(candidates.get(i));
            }
            if (candidates.size() > 8) note.append(" ... 共 ").append(candidates.size()).append(" 个");
            out.put("note", note.toString());
            LogStore.get().log(TAG, "[hook] " + cls.getName() + "." + methodName + " 0 match, candidates: " + candidates.size());
        } else {
            out.put("note", cls.getName() + "." + methodName + "(" + (paramTypes == null ? "" : paramTypes) + ")");
            LogStore.get().log(TAG, "[hook] " + cls.getName() + "." + methodName + " x" + hooked);
        }
        return out.toString();
    }

    /** v1.19 探测 b: 全自动 hook 类全部方法（类加载时由 ClassLoadProbe 触发）。
     *  跳过系统类 / 接口 / Object 继承方法；autoHooked 去重防类重复加载时重复 hook。 */
    public String hookClassAuto(String className) {
        try {
            if (!autoHooked.add(className)) return null; // 已处理过（防 skip 日志刷屏）
            Class<?> cls = Class.forName(className, false, appCl);
            if (cls.isInterface()) return null;
            String n = cls.getName();
            if (n.startsWith("java.") || n.startsWith("javax.") || n.startsWith("android.")
                    || n.startsWith("sun.") || n.startsWith("kotlin.") || n.startsWith("kotlinx.")) {
                return null; // 系统类不自动 hook
            }
            int hooked = 0;
            int skipped = 0;
            for (Method m : cls.getDeclaredMethods()) {
                // 跳过 Object 继承的通用方法（equals/hashCode/toString 高频低价值）
                String mn = m.getName();
                if ((mn.equals("equals") || mn.equals("hashCode") || mn.equals("toString")
                        || mn.equals("getClass") || mn.equals("clone") || mn.equals("finalize")) &&
                        m.getParameterCount() <= 1) {
                    skipped++;
                    continue;
                }
                String sigKey = joinParams(m.getParameterTypes());
                if (Config.get().hasHandle(cls.getName(), mn, sigKey)) { skipped++; continue; }
                try {
                    XposedInterface.HookHandle h = module.hook(m).intercept(MethodProbe::onInvoke);
                    Config.get().addHandle(cls.getName(), mn, sigKey, h);
                    hooked++;
                } catch (Throwable t) {
                    skipped++;
                }
            }
            for (Constructor<?> c : cls.getDeclaredConstructors()) {
                String sigKey = joinParams(c.getParameterTypes());
                if (Config.get().hasHandle(cls.getName(), "<init>", sigKey)) { skipped++; continue; }
                try {
                    XposedInterface.HookHandle h = module.hook(c).intercept(MethodProbe::onInvoke);
                    Config.get().addHandle(cls.getName(), "<init>", sigKey, h);
                    hooked++;
                } catch (Throwable t) {
                    skipped++;
                }
            }
            if (hooked > 0) {
                LogStore.get().log(TAG, "[auto] hook " + n + " x" + hooked + " (skip " + skipped + ")");
            }
            JSONObject out = new JSONObject();
            out.put("ok", true);
            out.put("auto", true);
            out.put("className", n);
            out.put("hooked", hooked);
            out.put("skipped", skipped);
            return out.toString();
        } catch (ClassNotFoundException e) {
            return null;
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[auto] hook fail " + className + ": " + t);
            return null;
        }
    }

    /** 卸载 hook（unhook 内存句柄 + 清 Config.hooks 记录） */
    public String unhookMethod(String className, String methodName, String paramTypes) throws Exception {
        try {
            int n = Config.get().unhookHandles(className, methodName, paramTypes == null ? "" : paramTypes);
            JSONObject out = new JSONObject();
            out.put("ok", true);
            out.put("unhooked", n);
            out.put("note", className + "." + methodName + " unhooked=" + n);
            return out.toString();
        } catch (Throwable t) {
            JSONObject out = new JSONObject();
            out.put("ok", false);
            out.put("error", t.toString());
            return out.toString();
        }
    }

    /** v1.28 P1: 参数签名匹配 —— paramTypes==null = 全部重载；"" = 仅无参（精确）；"int,String" = 精确匹配 */
    private static boolean matchParams(Class<?>[] types, String paramTypes) {
        if (paramTypes == null) return true;               // 全部重载
        if (paramTypes.isEmpty()) return types.length == 0; // 无参精确
        String[] want = paramTypes.split(",");
        if (want.length != types.length) return false;
        for (int i = 0; i < types.length; i++) {
            String w = want[i].trim();
            if (!typeName(types[i]).equals(w)) return false;
        }
        return true;
    }

    /** 通用调用拦截：劫持检查(v1.4) + 打印方法 + 参数 + 实例字段值(v1.2) + 返回值 + 调用栈 */
    private static Object onInvoke(io.github.libxposed.api.XposedInterface.Chain chain) throws Throwable {
        // v1.12: Hook 失败隔离（借鉴 Guise 原则）—— 最外层兜底，探测逻辑任何异常都不拖垮目标方法
        try {
            return onInvokeInner(chain);
        } catch (Throwable t) {
            try {
                LogStore.get().log(TAG, "[invoke] probe fail (isolated): " + t);
            } catch (Throwable ignored) { }
            return chain.proceed(); // 探测异常不影响原方法执行
        }
    }

    private static Object onInvokeInner(io.github.libxposed.api.XposedInterface.Chain chain) throws Throwable {
        Object thiz = chain.getThisObject();
        List<Object> args = chain.getArgs();
        String caller = thiz != null ? thiz.getClass().getName() : "<static>";

        // v1.14: 记录模式待记返回值（proceed 后由调用方记录）
        final Config.HijackRule[] recordRule = new Config.HijackRule[1];

        // v1.4/v1.13/v1.14: hook 规则（7 模式：返回值/参数值/拦截执行/静态变量/记录参数/记录返回值/记录两者）
        try {
            java.lang.reflect.Executable exe = chain.getExecutable();
            if (exe instanceof java.lang.reflect.Method) {
                java.lang.reflect.Method m = (java.lang.reflect.Method) exe;
                Config.HijackRule rule = Config.get().findHijack(
                        m.getDeclaringClass().getName(), m.getName(), joinParams(m.getParameterTypes()));
                if (rule != null) {
                    switch (rule.mode) {
                        case Config.MODE_RETURN: {
                            // v1.28 P1: RandomReturn 定时刷新缓存 key 按调用点隔离（默认 "rnd" 会导致多个规则互相覆盖缓存）
                            Object forced = coerceReturn(m.getReturnType(), rule.returnValue,
                                    m.getDeclaringClass().getName() + "." + m.getName() + "(" + joinParams(m.getParameterTypes()) + ")");
                            String ft = forced == null ? "null" : forced.getClass().getSimpleName();
                            LogStore.get().log(TAG, "[RULE:return] " + m.getDeclaringClass().getName() + "." + m.getName()
                                    + "(" + joinParams(m.getParameterTypes()) + ") -> " + rule.returnValue + " (" + ft + ")");
                            return forced;
                        }
                        case Config.MODE_BLOCK: {
                            LogStore.get().log(TAG, "[RULE:block] " + m.getDeclaringClass().getName() + "." + m.getName()
                                    + "(" + joinParams(m.getParameterTypes()) + ") 已拦截执行（不执行原方法）");
                            return nullFor(m.getReturnType());
                        }
                        case Config.MODE_PARAM: {
                            LogStore.get().log(TAG, "[RULE:param] " + m.getDeclaringClass().getName() + "." + m.getName()
                                    + "(" + joinParams(m.getParameterTypes()) + ") 改参数: " + rule.paramValue);
                            applyParamValues(args, rule.paramValue);
                            // 参数修改后继续执行原方法
                            break;
                        }
                        case Config.MODE_STATIC: {
                            boolean ok = setStaticField(m.getDeclaringClass(), rule.fieldName, rule.fieldType, rule.fieldValue);
                            LogStore.get().log(TAG, "[RULE:static] " + m.getDeclaringClass().getName() + "." + rule.fieldName
                                    + " = " + rule.fieldValue + " ok=" + ok);
                            // 静态字段写完后照常执行原方法
                            break;
                        }
                        case Config.MODE_RECORD_PARAMS: {
                            StringBuilder rb = new StringBuilder("[RULE:recordParams] ")
                                    .append(m.getDeclaringClass().getName()).append(".").append(m.getName())
                                    .append("(").append(joinParams(m.getParameterTypes())).append(") args=");
                            for (int i = 0; i < args.size(); i++) {
                                if (i > 0) rb.append(", ");
                                rb.append(str(args.get(i), 300));
                            }
                            LogStore.get().log(TAG, rb.toString());
                            break; // 纯观测，继续执行原方法
                        }
                        case Config.MODE_RECORD_RETURN:
                        case Config.MODE_RECORD_BOTH: {
                            if (rule.mode == Config.MODE_RECORD_BOTH) {
                                StringBuilder rb = new StringBuilder("[RULE:recordBoth] ")
                                        .append(m.getDeclaringClass().getName()).append(".").append(m.getName())
                                        .append("(").append(joinParams(m.getParameterTypes())).append(") args=");
                                for (int i = 0; i < args.size(); i++) {
                                    if (i > 0) rb.append(", ");
                                    rb.append(str(args.get(i), 300));
                                }
                                LogStore.get().log(TAG, rb.toString());
                            }
                            recordRule[0] = rule; // proceed 后记录返回值
                            break;
                        }
                    }
                }
            }
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[rule] check fail: " + t);
        }

        // v1.6: 轻量模式（关详细）只记参数摘要，跳过字段快照+调用栈（hook 高频方法时性能关键）
        boolean detail = Config.get().detailMode;

        StringBuilder sb = new StringBuilder();
        sb.append("[invoke] ").append(caller).append("(");
        int shown = 0;
        for (int i = 0; i < args.size(); i++) {
            if (i > 0) sb.append(", ");
            // 轻量模式最多显示前 4 个参数（防参数巨大刷屏）
            if (!detail && shown >= 4) {
                sb.append("...");
                break;
            }
            sb.append(str(args.get(i), detail ? 300 : 100));
            shown++;
        }
        sb.append(")");
        LogStore.get().log(TAG, sb.toString());

        // v1.2: 实例字段值快照（最多 8 个字段，每个 100 字符）—— 详细模式才做
        if (detail && thiz != null) {
            try {
                StringBuilder fs = new StringBuilder("[fields] ");
                java.lang.reflect.Field[] fields = fieldsOf(thiz.getClass());
                int fshown = 0;
                for (java.lang.reflect.Field f : fields) {
                    if (fshown >= 8) break;
                    if (java.lang.reflect.Modifier.isStatic(f.getModifiers())) continue;
                    try {
                        f.setAccessible(true);
                        if (fshown > 0) fs.append("; ");
                        fs.append(f.getName()).append("=").append(str(f.get(thiz), 100));
                        fshown++;
                    } catch (Throwable t) { }
                }
                if (fshown > 0) LogStore.get().log(TAG, fs.toString());
            } catch (Throwable t) { }
        }

        // 调用栈（详细模式才做，getStackTrace 开销大）
        // v1.15 P2-1: stack()/log 加独立 try —— 若抛异常不拖垮 proceed（外层兜底会执行原方法但返回值记录丢失）
        if (detail) {
            try {
                LogStore.get().log(TAG, "[stack]\n" + stack(14));
            } catch (Throwable t) { }
        }

        Object result = chain.proceed();
        try {
            LogStore.get().log(TAG, "[return] " + str(result, detail ? 300 : 100));
        } catch (Throwable t) { }
        // v1.14: 记录模式（RECORD_RETURN / RECORD_BOTH）proceed 后记返回值
        if (recordRule[0] != null) {
            try {
                LogStore.get().log(TAG, "[RULE:recordReturn] " + recordRule[0].className + "." + recordRule[0].methodName
                        + "(" + recordRule[0].paramTypes + ") -> " + str(result, 300));
            } catch (Throwable t) { }
        }
        return result;
    }

    /** v1.6: 字段反射缓存（WeakHashMap 防泄漏，getDeclaredFields 每次调用很贵）
     *  v1.16 P2-2: synchronizedMap 包装（hook 回调多线程并发 get/put 原本不安全） */
    private static final java.util.Map<Class<?>, java.lang.reflect.Field[]> FIELD_CACHE =
            java.util.Collections.synchronizedMap(new java.util.WeakHashMap<>());

    private static java.lang.reflect.Field[] fieldsOf(Class<?> c) {
        java.lang.reflect.Field[] f = FIELD_CACHE.get(c);
        if (f == null) {
            try {
                f = c.getDeclaredFields();
            } catch (Throwable t) {
                f = new java.lang.reflect.Field[0];
            }
            FIELD_CACHE.put(c, f);
        }
        return f;
    }

    /** v1.13: 基础类型返回 null/0（MODE_BLOCK 拦截执行时用） */
    private static Object nullFor(Class<?> rt) {
        if (rt == boolean.class) return Boolean.FALSE;
        if (rt == int.class) return Integer.valueOf(0);
        if (rt == long.class) return Long.valueOf(0L);
        if (rt == float.class) return Float.valueOf(0f);
        if (rt == double.class) return Double.valueOf(0d);
        if (rt == short.class) return Short.valueOf((short) 0);
        if (rt == byte.class) return Byte.valueOf((byte) 0);
        if (rt == char.class) return Character.valueOf('\0');
        return null;
    }

    /** v1.13: 按 "0:值,1:值" 格式改写方法入参（MODE_PARAM） */
    private static void applyParamValues(List<Object> args, String spec) {
        if (spec == null || spec.isEmpty()) return;
        String[] pairs = spec.split(",");
        for (String pair : pairs) {
            String[] kv = pair.split(":", 2);
            if (kv.length != 2) continue;
            try {
                int idx = Integer.parseInt(kv[0].trim());
                if (idx < 0 || idx >= args.size()) continue;
                Object cur = args.get(idx);
                Object val = coerceValue(cur == null ? Object.class : cur.getClass(), kv[1].trim());
                args.set(idx, val);
            } catch (Throwable t) {
                LogStore.get().log(TAG, "[rule:param] parse fail: " + pair + " : " + t);
            }
        }
    }

    /** v1.13: 写静态字段（MODE_STATIC），支持 int/long/boolean/float/double/String 等基础类型 */
    private static boolean setStaticField(Class<?> cls, String fieldName, String fieldType, String fieldValue) {
        if (cls == null || fieldName == null || fieldName.isEmpty()) return false;
        try {
            java.lang.reflect.Field f = cls.getDeclaredField(fieldName);
            f.setAccessible(true);
            if (!java.lang.reflect.Modifier.isStatic(f.getModifiers())) {
                LogStore.get().log(TAG, "[rule:static] " + cls.getName() + "." + fieldName + " 不是静态字段，跳过");
                return false;
            }
            Class<?> ft = f.getType();
            Object val = coerceValue(ft, fieldValue == null ? "" : fieldValue.trim());
            f.set(null, val);
            return true;
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[rule:static] set fail " + cls.getName() + "." + fieldName + " : " + t);
            return false;
        }
    }

    /** v1.13: 按目标类型解析字符串值（参数/静态字段共用） */
    private static Object coerceValue(Class<?> target, String val) {
        try {
            if (target == boolean.class || target == Boolean.class) return Boolean.parseBoolean(val);
            if (target == int.class || target == Integer.class) return Integer.parseInt(val);
            if (target == long.class || target == Long.class) return Long.parseLong(val);
            if (target == float.class || target == Float.class) return Float.parseFloat(val);
            if (target == double.class || target == Double.class) return Double.parseDouble(val);
            if (target == short.class || target == Short.class) return Short.parseShort(val);
            if (target == byte.class || target == Byte.class) return Byte.parseByte(val);
            if (target == char.class || target == Character.class) return val.isEmpty() ? '\0' : val.charAt(0);
            if (target == String.class) return val;
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[rule] coerce fail (" + target.getSimpleName() + ", \"" + val + "\"): " + t);
        }
        return null;
    }

    /** v1.4: 按返回类型把字符串强制值转成返回值；ctx = 调用点（类#方法签名），用于 RandomReturn 缓存隔离 */
    private static Object coerceReturn(Class<?> rt, String val, String ctx) {
        if (rt == void.class) return null;
        if (val == null || "null".equalsIgnoreCase(val.trim())) return null;
        String v = val.trim();
        // v1.14: RandomReturn 随机返回值（借鉴 SimpleHook applyRandomReturnRule）——
        //   格式 {"random":"seed","length":10} 生成随机串；可选 "updateTime":秒 定时刷新
        //   v1.16 P2-1: 刷新缓存用进程内 Map（RND_TIME/RND_VAL），不存 SharedPreferences（注释同步）
        //   v1.28 P1: 缓存 key 默认带调用点上下文，多个规则不指定 key 时互不干扰
        if (rt == String.class && v.startsWith("{") && v.contains("\"random\"")) {
            try {
                JSONObject jo = new JSONObject(v);
                String seed = jo.optString("random", "abcdefghijklmnopqrstuvwxyz0123456789");
                int len = jo.optInt("length", 10);
                long updateTime = jo.optLong("updateTime", -1L);
                String key = (ctx == null ? "" : ctx + "#") + jo.optString("key", "rnd");
                String defaultValue = jo.optString("defaultValue", "");
                if (updateTime == -1L) {
                    return randomString(seed, len);
                }
                // 定时刷新用进程内缓存（libxposed 静态方法无 module 引用，进程存活期间有效）
                long now = System.currentTimeMillis() / 1000;
                Long last = RND_TIME.get(key);
                String cached = RND_VAL.get(key);
                if (last == null || cached == null || (now - last) >= updateTime) {
                    String fresh = randomString(seed, len);
                    RND_TIME.put(key, now);
                    RND_VAL.put(key, fresh);
                    return fresh;
                }
                return cached;
            } catch (Throwable t) {
                LogStore.get().log(TAG, "[hijack] randomReturn parse fail: " + t);
            }
        }
        try {
            if (rt == boolean.class || rt == Boolean.class) return Boolean.parseBoolean(v);
            if (rt == int.class || rt == Integer.class) return Integer.parseInt(v);
            if (rt == long.class || rt == Long.class) return Long.parseLong(v);
            if (rt == float.class || rt == Float.class) return Float.parseFloat(v);
            if (rt == double.class || rt == Double.class) return Double.parseDouble(v);
            if (rt == short.class || rt == Short.class) return Short.parseShort(v);
            if (rt == byte.class || rt == Byte.class) return Byte.parseByte(v);
            if (rt == char.class || rt == Character.class) return v.isEmpty() ? '\0' : v.charAt(0);
            if (rt == String.class) return v;
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[hijack] coerce fail (" + rt.getSimpleName() + ", \"" + v + "\"): " + t);
        }
        // 其它对象类型：返回 null（无法凭空构造实例）
        return null;
    }

    /** v1.14: RandomReturn 定时刷新缓存（进程内） */
    private static final java.util.Map<String, Long> RND_TIME = new java.util.concurrent.ConcurrentHashMap<>();
    private static final java.util.Map<String, String> RND_VAL = new java.util.concurrent.ConcurrentHashMap<>();

    /** v1.14: 从种子字符集生成随机字符串（RandomReturn 用） */
    private static String randomString(String seed, int len) {
        java.util.Random r = new java.util.Random();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; i++) {
            sb.append(seed.charAt(r.nextInt(seed.length())));
        }
        return sb.toString();
    }

    /** 参数类型拼接成 "java.lang.String,int" 形式（与 hook key 一致） */
    private static String joinParams(Class<?>[] types) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < types.length; i++) {
            if (i > 0) sb.append(",");
            sb.append(typeName(types[i]));
        }
        return sb.toString();
    }

    static String str(Object o, int max) {
        if (o == null) return "null";
        try {
            if (o instanceof byte[]) {
                byte[] b = (byte[]) o;
                return "byte[" + b.length + "] " + hex(b, Math.min(b.length, 64));
            }
            String s = String.valueOf(o);
            if (s.length() > max) s = s.substring(0, max) + "...(" + s.length() + ")";
            return s;
        } catch (Throwable t) {
            return "<" + o.getClass().getName() + ">";
        }
    }

    static String hex(byte[] b, int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) {
            sb.append(String.format("%02x", b[i]));
        }
        return sb.toString();
    }

    static String stack(int maxFrames) {
        StringBuilder sb = new StringBuilder();
        StackTraceElement[] st = Thread.currentThread().getStackTrace();
        // 0=getStackTrace 1=stack 2=onInvoke 3=实际调用方
        int count = 0;
        for (int i = 3; i < st.length && count < maxFrames; i++, count++) {
            sb.append("    at ").append(st[i]).append('\n');
        }
        return sb.toString();
    }
}
