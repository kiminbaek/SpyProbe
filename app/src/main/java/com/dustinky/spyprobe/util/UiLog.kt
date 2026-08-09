package com.dustinky.spyprobe.util

import android.content.Context
import android.util.Log
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * v1.30.1: UI 进程自己的调试日志（此前只有目标进程 DebugLog，UI 导出失败原因无处查）。
 * 三保险：内存环形 200 条 + 落盘 UI app 私有目录 files/spyprobe_ui.log + logcat。
 */
object UiLog {

    private const val TAG = "SpyProbeUi"
    private const val MAX_RING = 200

    private val ring = ArrayDeque<String>()
    private var file: File? = null

    fun init(context: Context) {
        try {
            if (file == null) {
                file = File(context.filesDir, "spyprobe_ui.log")
            }
        } catch (t: Throwable) {
            Log.e(TAG, "UiLog.init failed", t)
        }
    }

    fun log(msg: String) {
        val line = "${fmt()} [UI] $msg"
        synchronized(ring) {
            ring.addLast(line)
            while (ring.size > MAX_RING) ring.removeFirst()
        }
        Log.i(TAG, msg)
        // 异步落盘（不阻塞 UI）
        try {
            val f = file ?: return
            Thread {
                try {
                    f.appendText(line + "\n")
                } catch (t: Throwable) { }
            }.start()
        } catch (t: Throwable) { }
    }

    /**
     * v1.30.2: dump 返回 内存环形 + 落盘文件全文（合并去重）。
     * 背景：重启后环形缓冲清空（只有文件还有历史），用户要"越详细越好"——文件不能丢。
     */
    fun dump(): String {
        val mem = synchronized(ring) { ring.joinToString("\n") }
        val sb = StringBuilder(mem)
        val f = file
        if (f != null && f.exists()) {
            sb.append("\n---- file: ").append(f.absolutePath).append(" size=").append(f.length())
            if (mem.isEmpty()) {
                // 环形已清空（重启过），直接读文件全文
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

    private fun fmt(): String =
        SimpleDateFormat("HH:mm:ss.SSS", Locale.US).format(Date())
}
