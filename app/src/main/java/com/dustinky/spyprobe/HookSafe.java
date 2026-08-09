package com.dustinky.spyprobe;

/*
 * v1.37 P0-2: Hook 失败隔离工具（借鉴 Guise 的 runXposedCatching 工程思想，自研实现）
 *
 * 【问题】v1.31 曾因 shadowhook 与 Android16 PAC 不兼容导致 32 个 tombstone 全进程崩溃——
 *   hook 安装期/回调期的单个异常如果外泄，可能拖垮目标进程。
 * 【方案】所有 hook 安装统一走 install()：
 *   - 安装期异常：catch(Throwable) → 写 LogStore + DebugLog（失败留痕），不向上抛
 *   - 回调期异常：由各 probe 的 hook 回调自己 catch（见各 installXxx），这里管安装期
 * 【效果】单个 hook 崩不拖垮目标进程；失败必留日志桥（DebugLog 三保险可读）。
 */

public class HookSafe {

    /**
     * 统一包裹 hook 安装动作。
     * @param tag   日志标签（如 "Net"/"crypto"）
     * @param name  动作描述（如 "installSslBypass(early)"）
     * @param r     安装动作（内部再各自 try-catch）
     * @return true=安装完成（或内部已处理）；false=安装抛异常（已记日志）
     */
    public static boolean install(String tag, String name, Runnable r) {
        try {
            DebugLog.get().log(tag, "installing " + name);
            r.run();
            DebugLog.get().log(tag, "installed " + name);
            return true;
        } catch (Throwable t) {
            LogStore.get().log(tag, "[" + name + "] install FAIL: " + t);
            DebugLog.get().log(tag, "[" + name + "] install FAIL: " + t);
            return false;
        }
    }

    /** 简化版：无 name 时用 tag 作描述 */
    public static boolean install(String tag, Runnable r) {
        return install(tag, tag, r);
    }
}
