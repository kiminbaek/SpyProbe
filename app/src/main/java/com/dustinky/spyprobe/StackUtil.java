package com.dustinky.spyprobe;

/**
 * v1.9: 调用栈格式化工具（借鉴 AdClose HookUtil.getFormattedStackTrace）
 * hook 回调里调用，记录"谁在调用"——定位检测/请求的发起方类。
 */
public class StackUtil {

    /** 返回当前调用栈文本（跳过本工具自身 3 帧） */
    public static String get() {
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        StringBuilder sb = new StringBuilder();
        for (int i = 3; i < stack.length; i++) {
            StackTraceElement e = stack[i];
            sb.append("  ").append(e.getClassName()).append(".")
              .append(e.getMethodName()).append("(line: ")
              .append(e.getLineNumber()).append(")\n");
        }
        return sb.toString();
    }

    /** 返回紧凑调用栈（每行类.方法），适配日志单行 */
    public static String getCompact() {
        return getCompact(12);
    }

    /** v1.54: 可指定帧数——[TCP] FAIL 12 帧在日志页刷屏（v1.53 截图 8 行栈），
     *  连接失败只需保留到"目标 App 发起方"（hook 样板 2 帧 + app 类 3-4 帧）即可定位。 */
    public static String getCompact(int maxFrames) {
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        StringBuilder sb = new StringBuilder();
        int count = 0;
        for (int i = 3; i < stack.length && count < maxFrames; i++, count++) {
            if (count > 0) sb.append(" <- ");
            StackTraceElement e = stack[i];
            String cn = e.getClassName();
            int dot = cn.lastIndexOf('.');
            sb.append(dot >= 0 ? cn.substring(dot + 1) : cn)
              .append(".").append(e.getMethodName());
        }
        return sb.toString();
    }
}
