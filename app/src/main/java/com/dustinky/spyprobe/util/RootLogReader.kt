package com.dustinky.spyprobe.util

import java.io.BufferedReader
import java.io.InputStreamReader
import java.nio.charset.StandardCharsets
import java.text.SimpleDateFormat
import java.util.Collections
import java.util.Date
import java.util.Locale
import java.util.TreeSet
import java.util.concurrent.TimeUnit

/**
 * v1.31: Root 模式历史日志读取 —— 直读目标 App 沙箱内 LogPersister 落盘文件。
 *
 * 背景：日志落盘在目标进程 filesDir（/data/data/<pkg>/files/spyprobe_logs/），
 * 普通模式只能等目标 App 在线走 HTTP 拉；root 模式下用 `su -c cat` 直接读文件，
 * 目标 App 不在线也能看历史（这正是"历史日志必须随时可查"的核心诉求）。
 *
 * 授权模型（用户明确）：本 App 不主动触发 su 授权弹窗（Magisk 默认策略下
 * su 不弹窗、被拒直接报错）。用户需在设置里主动开启 Root 模式并自行完成授权；
 * 命令失败时给出"无 root 权限"提示并回退普通模式。
 *
 * 文件格式（LogPersister）：spyprobe_logs_<yyyy-MM-dd>_<n>.log，JSONL 每行：
 * {"seq":..,"t":"HH:mm:ss.SSS","tag":"..","m":".."}（UTF-8）
 */
object RootLogReader {

    private const val TAG = "SpyProbeRoot"
    private const val LOG_PREFIX = "spyprobe_logs_"

    /** 单条日志 */
    data class Entry(val seq: Long, val time: String, val tag: String, val msg: String)

    /** root 可用性检查（不弹窗，仅探测 su 是否可执行 + id -u == 0） */
    fun checkRoot(): Boolean {
        return try {
            val p = Runtime.getRuntime().exec(arrayOf("su", "-c", "id -u"))
            val done = p.waitFor(3, TimeUnit.SECONDS)
            if (!done) { p.destroyForcibly(); return false }
            val r = BufferedReader(InputStreamReader(p.inputStream, StandardCharsets.UTF_8))
            val line = r.readLine()?.trim()
            p.destroy()
            line == "0"
        } catch (t: Throwable) {
            false
        }
    }

    /** 列出目标 App 落盘日志文件（su ls 目录，解析日期分片） */
    fun listLogFiles(pkg: String): List<FileRef> {
        val out = suExec("ls -1 /data/data/$pkg/files/spyprobe_logs/") ?: return emptyList()
        val files = ArrayList<FileRef>()
        val dayFmt = SimpleDateFormat("yyyy-MM-dd", Locale.US)
        for (line in out.lineSequence()) {
            val n = line.trim()
            if (!n.startsWith(LOG_PREFIX) || !n.endsWith(".log")) continue
            // spyprobe_logs_2026-08-09_0.log
            val name = n.substring(LOG_PREFIX.length, n.length - 4) // 2026-08-09_0
            val u = name.lastIndexOf('_')
            if (u < 10) continue
            val day = name.substring(0, u)
            val part = name.substring(u + 1).toIntOrNull() ?: continue
            files.add(FileRef(day, part, "/data/data/$pkg/files/spyprobe_logs/$n"))
        }
        files.sortWith(compareBy<FileRef> { dayFmt.parse(it.day)?.time ?: 0L }.thenBy { it.part })
        return files
    }

    /** 可用的历史日期（按文件扫描，新日期在前） */
    fun days(pkg: String): List<String> {
        val set = TreeSet<String>(Collections.reverseOrder())
        for (f in listLogFiles(pkg)) set.add(f.day)
        return ArrayList(set)
    }

    /** 读某天全部日志（多分片按 seq 排序），max>0 保留最新 max 条 */
    fun readDay(pkg: String, day: String, max: Int = 0): List<Entry> {
        val files = listLogFiles(pkg).filter { it.day == day }
        if (files.isEmpty()) return emptyList()
        val out = ArrayList<Entry>()
        for (f in files) {
            val text = suExec("cat ${quote(f.path)}") ?: continue
            for (line in text.lineSequence()) {
                if (line.isBlank()) continue
                parseLine(line)?.let { out.add(it) }
            }
        }
        out.sortBy { it.seq }
        if (max > 0 && out.size > max) {
            return ArrayList(out.subList(out.size - max, out.size))
        }
        return out
    }

    /** 删除某天（day=null 全清） */
    fun clear(pkg: String, day: String?): Boolean {
        val base = "/data/data/$pkg/files/spyprobe_logs/"
        val cmd = if (day == null) "rm -f ${base}${LOG_PREFIX}*.log"
        else "rm -f ${base}${LOG_PREFIX}${day}_*.log"
        return suExec(cmd) != null
    }

    /** v1.31.2: root 抓系统 logcat 中 shadowhook_tag（shadowhook 内部日志）——
     *  native 库内部用 __android_log_print 打 logcat，LogStore 看不到，只有 root logcat 能拿到。
     *  返回原始文本（含时间戳/pid/tag），无输出返回 null。 */
    fun captureShadowHookLog(): String? {
        // logcat -d = dump 后退出；-s = 只显 tag shadowhook_tag；-t 300 限最近 300 行防超长
        return suExec("logcat -d -t 300 -s shadowhook_tag:*")
    }

    // ---------- 内部 ----------
    data class FileRef(val day: String, val part: Int, val path: String)

    /** su -c 命令；成功返回 stdout，失败返回 null（stderr 记录到 UiLog） */
    private fun suExec(cmd: String): String? {
        return try {
            val p = Runtime.getRuntime().exec(arrayOf("su", "-c", cmd))
            val done = p.waitFor(8, TimeUnit.SECONDS)
            if (!done) { p.destroyForcibly(); return null }
            val r = BufferedReader(InputStreamReader(p.inputStream, StandardCharsets.UTF_8))
            val sb = StringBuilder()
            var line: String?
            while (r.readLine().also { line = it } != null) sb.append(line).append('\n')
            val err = BufferedReader(InputStreamReader(p.errorStream, StandardCharsets.UTF_8))
            val eb = StringBuilder()
            while (err.readLine().also { line = it } != null) eb.append(line).append('\n')
            // v1.31.1 P3-2: 显式关闭流（此前只 destroy()，fd 泄漏；8s 超时 destroyForcibly 仅兜底）
            try { err.close() } catch (t: Throwable) { }
            try { r.close() } catch (t: Throwable) { }
            val code = p.exitValue()
            p.destroy()
            if (code != 0) {
                UiLog.log("$TAG su exit=$code cmd=${cmd.take(80)} err=${eb.toString().trim().take(200)}")
                null
            } else {
                sb.toString()
            }
        } catch (t: Throwable) {
            UiLog.log("$TAG su exception: ${t.javaClass.simpleName}: ${t.message}")
            null
        }
    }

    private fun quote(s: String): String = "'" + s.replace("'", "'\\''") + "'"

    /** 极简 JSONL 解析（与 LogPersister.parseLine 同款语义） */
    private fun parseLine(line: String): Entry? {
        return try {
            var seq = -1L; var t = ""; var tag = ""; var m = ""
            var idx = 0
            val n = line.length
            while (idx < n) {
                // 跳过非引号
                while (idx < n && line[idx] != '"') idx++
                if (idx + 1 >= n) break
                val keyStart = idx + 1
                val keyEnd = line.indexOf('"', keyStart)
                if (keyEnd < 0) break
                val key = line.substring(keyStart, keyEnd)
                idx = keyEnd + 1
                while (idx < n && (line[idx] == ' ' || line[idx] == ':' || line[idx] == '\t')) idx++
                if (idx >= n) break
                if (line[idx] == '"') {
                    // 字符串值：处理转义
                    val sb = StringBuilder()
                    var i = idx + 1
                    while (i < n) {
                        val c = line[i]
                        if (c == '\\' && i + 1 < n) {
                            when (val e = line[i + 1]) {
                                'n' -> { sb.append('\n'); i += 2 }
                                'r' -> { sb.append('\r'); i += 2 }
                                't' -> { sb.append('\t'); i += 2 }
                                '\\' -> { sb.append('\\'); i += 2 }
                                '"' -> { sb.append('"'); i += 2 }
                                'u' -> {
                                    if (i + 5 < n) {
                                        try {
                                            sb.append(line.substring(i + 2, i + 6).toInt(16).toChar())
                                            i += 6
                                        } catch (_: Throwable) { sb.append('u'); i += 2 }
                                    } else { sb.append('u'); i += 2 }
                                }
                                else -> { sb.append(e); i += 2 }
                            }
                        } else if (c == '"') { i++; break }
                        else { sb.append(c); i++ }
                    }
                    when (key) {
                        "t" -> t = sb.toString()
                        "tag" -> tag = sb.toString()
                        "m" -> m = sb.toString()
                    }
                    idx = i
                } else {
                    // 数字值（seq）
                    var i = idx
                    while (i < n && line[i] != ',' && line[i] != '}') i++
                    val v = line.substring(idx, i).trim()
                    if (key == "seq") seq = v.toLongOrNull() ?: -1L
                    idx = i
                }
            }
            Entry(seq, t, tag, m)
        } catch (_: Throwable) {
            null
        }
    }
}
