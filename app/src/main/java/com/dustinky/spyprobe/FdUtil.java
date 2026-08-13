package com.dustinky.spyprobe;

import java.lang.reflect.Field;
import java.net.Socket;

/**
 * v7x: 从 java.net.Socket 反射拿底层 fd（int）
 *  - Android / OpenJDK 的 Socket.impl(SocketImpl).fd(FileDescriptor).descriptor(int)
 *  - 失败返回 -1（调用方自行兜底）
 *
 * v1.74.8 P0-11: 修复 fd 恒取不到的根因——原实现用 impl.getClass().getDeclaredField("fd")，
 *   getDeclaredField 只查当前类，而 fd 字段声明在父类 SocketImpl/AbstractPlainSocketImpl 里，
 *   子类 PlainSocketImpl 上必抛 NoSuchFieldException → 恒 -1 → SO_ORIGINAL_DST 恒 null
 *   → MITM 透明模式全部走 DNS 重连（被 DNS 屏蔽成 127.0.0.1 → connect localhost:443 全挂）。
 *   改为沿继承链向上 findField；并支持 getFileDescriptor() 方法兜底 + diag 记录失败原因。
 */
public final class FdUtil {

    private FdUtil() {}

    public static int getFd(Socket s) {
        return getFd(s, null);
    }

    /** diag 非空时把失败原因拼进去（MITM 透明模式调试用） */
    public static int getFd(Socket s, StringBuilder diag) {
        try {
            Field implField = findField(Socket.class, "impl");
            if (implField == null) { note(diag, "no field Socket.impl"); return -1; }
            implField.setAccessible(true);
            Object impl = implField.get(s);
            if (impl == null) { note(diag, "Socket.impl null"); return -1; }
            Field fdField = findField(impl.getClass(), "fd");
            if (fdField == null) {
                // 兜底：libcore AbstractPlainSocketImpl.getFileDescriptor() 方法
                try {
                    java.lang.reflect.Method m = impl.getClass().getMethod("getFileDescriptor");
                    m.setAccessible(true);
                    Object fd = m.invoke(impl);
                    return fdDescriptorInt(fd, diag);
                } catch (Throwable t) {
                    note(diag, "no fd field nor getFileDescriptor(): " + t);
                    return -1;
                }
            }
            fdField.setAccessible(true);
            Object fd = fdField.get(impl);
            return fdDescriptorInt(fd, diag);
        } catch (Throwable t) {
            note(diag, "FdUtil err: " + t);
            return -1;
        }
    }

    private static int fdDescriptorInt(Object fd, StringBuilder diag) {
        if (fd == null) { note(diag, "fd null"); return -1; }
        // Android: FileDescriptor.descriptor(int)；OpenJDK: FileDescriptor.fd(int) / handle(long)
        for (String name : new String[]{"descriptor", "fd", "handle"}) {
            try {
                Field intField = findField(fd.getClass(), name);
                if (intField == null) continue;
                intField.setAccessible(true);
                if (intField.getType() == long.class) {
                    long v = intField.getLong(fd);
                    return v == 0 ? -1 : (int) v;
                }
                return intField.getInt(fd);
            } catch (Throwable t) {
                note(diag, name + " err: " + t + "; ");
            }
        }
        note(diag, "no descriptor/fd/handle field in " + fd.getClass().getName());
        return -1;
    }

    /** 沿继承链向上找字段（getDeclaredField 只查本类，fd 声明在父类 SocketImpl 里） */
    private static Field findField(Class<?> c, String name) {
        for (Class<?> k = c; k != null; k = k.getSuperclass()) {
            try {
                return k.getDeclaredField(name);
            } catch (NoSuchFieldException e) {
                // 继续向上
            }
        }
        return null;
    }

    private static void note(StringBuilder diag, String msg) {
        if (diag != null) diag.append(msg).append("; ");
    }
}
