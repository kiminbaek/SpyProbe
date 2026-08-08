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
        for (Constructor<?> c : cls.getDeclaredConstructors()) {
            if (paramTypes != null && !paramTypes.isEmpty() && !matchParams(c.getParameterTypes(), paramTypes)) {
                continue;
            }
            // v1.3: 防重复 hook（UI 重复点同一方法不翻倍）
            if (Config.get().hasHandle(cls.getName(), "<init>", paramTypes == null ? "" : paramTypes)) {
                LogStore.get().log(TAG, "[hook] skip (already hooked): " + cls.getName() + " <init>");
                continue;
            }
            XposedInterface.HookHandle h = module.hook(c).intercept(MethodProbe::onInvoke);
            Config.get().addHandle(cls.getName(), "<init>", paramTypes == null ? "" : paramTypes, h);
            hooked++;
        }
        JSONObject out = new JSONObject();
        out.put("ok", true);
        out.put("hooked", hooked);
        out.put("note", cls.getName() + " <init>");
        LogStore.get().log(TAG, "[hook] <init> x" + hooked + " " + cls.getName());
        return out.toString();
    }

    private String hookMethods(Class<?> cls, String methodName, String paramTypes) throws Throwable {
        int hooked = 0;
        String paramKey = paramTypes == null ? "" : paramTypes;
        for (Method m : cls.getDeclaredMethods()) {
            if (!m.getName().equals(methodName)) continue;
            if (paramTypes != null && !paramTypes.isEmpty() && !matchParams(m.getParameterTypes(), paramTypes)) {
                continue;
            }
            // v1.3: 防重复 hook（同 class#method(params) 已 hook 则跳过）
            if (Config.get().hasHandle(cls.getName(), methodName, paramKey)) {
                LogStore.get().log(TAG, "[hook] skip (already hooked): " + cls.getName() + "." + methodName + "(" + paramKey + ")");
                continue;
            }
            XposedInterface.HookHandle h = module.hook(m).intercept(MethodProbe::onInvoke);
            Config.get().addHandle(cls.getName(), methodName, paramKey, h);
            hooked++;
        }
        JSONObject out = new JSONObject();
        out.put("ok", true);
        out.put("hooked", hooked);
        out.put("note", cls.getName() + "." + methodName + "(" + paramKey + ")");
        LogStore.get().log(TAG, "[hook] " + cls.getName() + "." + methodName + " x" + hooked);
        return out.toString();
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

    private static boolean matchParams(Class<?>[] types, String paramTypes) {
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
        Object thiz = chain.getThisObject();
        List<Object> args = chain.getArgs();
        String caller = thiz != null ? thiz.getClass().getName() : "<static>";

        // v1.4: 返回值劫持 —— 命中规则直接返回强制值，不执行原方法（去检测/去付费的万能钥匙）
        try {
            java.lang.reflect.Executable exe = chain.getExecutable();
            if (exe instanceof java.lang.reflect.Method) {
                java.lang.reflect.Method m = (java.lang.reflect.Method) exe;
                Config.HijackRule hijack = Config.get().findHijack(
                        m.getDeclaringClass().getName(), m.getName(), joinParams(m.getParameterTypes()));
                if (hijack != null) {
                    Object forced = coerceReturn(m.getReturnType(), hijack.returnValue);
                    String ft = forced == null ? "null" : forced.getClass().getSimpleName();
                    LogStore.get().log(TAG, "[HIJACK] " + m.getDeclaringClass().getName() + "." + m.getName()
                            + "(" + joinParams(m.getParameterTypes()) + ") -> 强制返回 " + hijack.returnValue + " (" + ft + ")");
                    return forced;
                }
            }
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[hijack] check fail: " + t);
        }

        StringBuilder sb = new StringBuilder();
        sb.append("[invoke] ").append(caller).append("(");
        for (int i = 0; i < args.size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append(str(args.get(i), 300));
        }
        sb.append(")");
        LogStore.get().log(TAG, sb.toString());

        // v1.2: 实例字段值快照（最多 8 个字段，每个 100 字符）
        if (thiz != null) {
            try {
                StringBuilder fs = new StringBuilder("[fields] ");
                java.lang.reflect.Field[] fields = thiz.getClass().getDeclaredFields();
                int shown = 0;
                for (java.lang.reflect.Field f : fields) {
                    if (shown >= 8) break;
                    if (java.lang.reflect.Modifier.isStatic(f.getModifiers())) continue;
                    try {
                        f.setAccessible(true);
                        if (shown > 0) fs.append("; ");
                        fs.append(f.getName()).append("=").append(str(f.get(thiz), 100));
                        shown++;
                    } catch (Throwable t) { }
                }
                if (shown > 0) LogStore.get().log(TAG, fs.toString());
            } catch (Throwable t) { }
        }

        LogStore.get().log(TAG, "[stack]\n" + stack(14));

        Object result = chain.proceed();
        try {
            LogStore.get().log(TAG, "[return] " + str(result, 300));
        } catch (Throwable t) { }
        return result;
    }

    /** v1.4: 按返回类型把字符串强制值转成返回值 */
    private static Object coerceReturn(Class<?> rt, String val) {
        if (rt == void.class) return null;
        if (val == null || "null".equalsIgnoreCase(val.trim())) return null;
        String v = val.trim();
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
