package com.dustinky.spyprobe.util

import android.content.Context
import android.util.Log
import java.io.BufferedWriter
import java.io.File
import java.io.FileOutputStream
import java.io.OutputStreamWriter
import java.nio.charset.StandardCharsets
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * v1.30.1: UI 进程自己的调试日志（此前只有目标进程 DebugLog，UI 导出失败原因无处查）。
 * 三保险：内存环形 200 条 + 落盘 UI app 私有目录 files/spyprobe_ui.log + logcat。
 * v1.31.1 P3-10: 落盘改为单线程持 writer 复用（此前每条日志 new Thread 写文件，高频时线程爆炸）。
 */
object UiLog {

    private const val TAG = "SpyProbeUi"
    private const val MAX_RING = 200

    private val ring = ArrayDeque<String>()
    private var file: File? = null
    private val fileLock = Any()
    private var writer: BufferedWriter? = null

    fun init(context: Context) {
        try {
            if (file == null) {
                file = File(context.filesDir, "spyprobe_ui.log")
            }
        } catch (t: Throwable) {
            Log.e(TAG, "UiLog.init failed", t)
        }
    }

    @JvmStatic
    fun log(msg: String) {
        val line = "${fmt()} [UI] $msg"
        synchronized(ring) {
            ring.addLast(line)
            while (ring.size > MAX_RING) ring.removeFirst()
        }
        Log.i(TAG, msg)
        // 落盘：单线程持 writer 同步写（不 new Thread；失败静默，下次重开）
        try {
            val f = file ?: return
            synchronized(fileLock) {
                var w = writer
                if (w == null) {
                    w = BufferedWriter(OutputStreamWriter(FileOutputStream(f, true), StandardCharsets.UTF_8))
                    writer = w
                }
                w.write(line)
                w.newLine()
                w.flush()
            }
        } catch (t: Throwable) {
            try {
                synchronized(fileLock) {
                    writer?.close()
                    writer = null
                }
            } catch (t2: Throwable) { }
        }
    }

    /**
     * v1.30.2: dump 返回 内存环形 + 落盘文件全文（合并去重）。
     * v1.31.1 P2-5: ring 非空时也读文件全文合并（此前只在 ring 为空时读文件——
     *   长时间运行 ring 只保留 200 条最新，文件里有全部历史，dump 却只返回 ring 的 200 条 → 丢历史）。
     *   合并策略与 DebugLog.dump() 一致：文件 size 超过 ring 理论大小则读文件全文（文件含全部历史）。
     */
    fun dump(): String {
        val mem = synchronized(ring) { ring.joinToString("\n") }
        val sb = StringBuilder(mem)
        val f = file
        if (f != null && f.exists()) {
            sb.append("\n---- file: ").append(f.absolutePath).append(" size=").append(f.length())
            // 文件更大时合并文件全文（文件是完整历史；ring 只是最近 200 条）
            if (mem.isEmpty() || f.length() > mem.length.toLong() + 512) {
                try {
                    sb.append('\n').append(f.readText())
                } catch (t: Throwable) {
                    sb.append("\n(read file fail: ").append(t).append(')')
                }
            }
        } else {
            sb.append("\n---- no ui log file yet")
        }
        return sb.toString()
    }

    fun logFile(): File? = file

    /**
     * v1.74.15: 清空 UI 调试日志（内存环形 + 落盘文件）。
     * 此前 files/spyprobe_ui.log 从不清理、无限累积（UI 高频日志如 ping 失败刷屏
     * 可占导出文件 80%+），「清空调试日志」按钮未覆盖此源 → 用户清空后导出仍巨大。
     * 清空后写一行留痕，证明清理执行过。
     */
    @JvmStatic
    fun clear() {
        synchronized(ring) {
            ring.clear()
        }
        try {
            synchronized(fileLock) {
                writer?.close()
                writer = null
                val f = file
                if (f != null && f.exists()) {
                    val del = f.delete()
                    log("UiLog cleared (file delete=$del)")
                } else {
                    log("UiLog cleared (memory only)")
                }
            }
        } catch (t: Throwable) {
            log("UiLog clear fail: $t")
        }
    }

    private fun fmt(): String =
        SimpleDateFormat("HH:mm:ss.SSS", Locale.US).format(Date())
}
