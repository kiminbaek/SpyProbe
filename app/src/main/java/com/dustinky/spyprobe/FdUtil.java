package com.dustinky.spyprobe;

import java.lang.reflect.Field;
import java.net.Socket;

/**
 * v7x: 从 java.net.Socket 反射拿底层 fd（int）
 *  - Android / OpenJDK 的 Socket.impl(AbstractPlainSocketImpl).fd(FileDescriptor).descriptor(int)
 *  - 失败返回 -1（调用方自行兜底）
 */
public final class FdUtil {

    private FdUtil() {}

    public static int getFd(Socket s) {
        try {
            Field implField = Socket.class.getDeclaredField("impl");
            implField.setAccessible(true);
            Object impl = implField.get(s);
            Field fdField = impl.getClass().getDeclaredField("fd");
            fdField.setAccessible(true);
            Object fd = fdField.get(impl);
            if (fd == null) return -1;
            Field intField = fd.getClass().getDeclaredField("descriptor");
            intField.setAccessible(true);
            return intField.getInt(fd);
        } catch (Throwable t) {
            return -1;
        }
    }
}
