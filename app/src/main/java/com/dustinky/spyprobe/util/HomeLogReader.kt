package com.dustinky.spyprobe.util

import java.io.File
import java.text.SimpleDateFormat
import java.util.Collections
import java.util.Locale
import java.util.TreeSet

/**
 * v1.32: 本地历史日志读取 —— 读 SpyProbe 自己家 files/spyprobe_logs/（主进程落盘）。
 *
 * 背景：日志已从目标 App data 搬回 SpyProbe 自己家（目标进程推主进程 :9900，
 * 主进程 LogPersister 写自己 files）。因此历史日志**免 root、免目标 App 在线**，
 * 直接 File API 读自己家文件即可——RootLogReader（su 读目标沙箱）只保留兜底。
 *
 * 文件格式（LogPersister）：spyprobe_logs_<yyyy-MM-dd>_<n>.log，JSONL 每行：
 * {"seq":..,"t":"HH:mm:ss.SSS","tag":"..","m":".."}（UTF-8）
 */
object HomeLogReader {

    private const val TAG = "SpyProbeHomeLog"
    private const val LOG_PREFIX = "spyprobe_logs_"

    data class Entry(val seq: Long, val time: String, val tag: String, val msg: String)

    /** 自己家日志目录（filesDir/spyprobe_logs）；不存在返回 null */
    private fun logDir(filesDir: File): File? {
        val d = File(filesDir, "spyprobe_logs")
        return if (d.isDirectory) d else null
    }

    private fun dayFromName(name: String): String? {
        // spyprobe_logs_2026-08-09_0.log
        if (!name.startsWith(LOG_PREFIX) || !name.endsWith(".log")) return null
        val core = name.substring(LOG_PREFIX.length, name.length - 4)
        val u = core.lastIndexOf('_')
        if (u < 10) return null
        return core.substring(0, u)
    }

    /** 可用的历史日期（新日期在前）；目录不存在返回空 */
    fun days(filesDir: File): List<String> {
        val d = logDir(filesDir) ?: return emptyList()
        val set = TreeSet<String>(Collections.reverseOrder())
        d.listFiles { f -> f.isFile && dayFromName(f.name) != null }?.forEach { f ->
            dayFromName(f.name)?.let { set.add(it) }
        }
        return ArrayList(set)
    }

    /** 读某天全部日志（多分片按 seq 排序），max>0 保留最新 max 条 */
    fun readDay(filesDir: File, day: String, max: Int = 0): List<Entry> {
        val d = logDir(filesDir) ?: return emptyList()
        val prefix = "$LOG_PREFIX$day"
        val files = d.listFiles { f ->
            f.isFile && f.name.startsWith(prefix) && f.name.endsWith(".log")
        }?.sortedBy { it.name } ?: return emptyList()
        val out = ArrayList<Entry>()
        for (f in files) {
            try {
                f.forEachLine { line ->
                    if (line.isBlank()) return@forEachLine
                    parseLine(line)?.let { out.add(it) }
                }
            } catch (t: Throwable) {
                UiLog.log("$TAG read $day ${f.name} error: $t")
            }
        }
        out.sortBy { it.seq }
        if (max > 0 && out.size > max) {
            return ArrayList(out.subList(out.size - max, out.size))
        }
        return out
    }

    /** 删除某天（day=null 全清）；返回是否删了文件 */
    fun clear(filesDir: File, day: String?): Boolean {
        val d = logDir(filesDir) ?: return false
        var any = false
        d.listFiles { f ->
            f.isFile && (day == null || f.name.startsWith("$LOG_PREFIX$day"))
        }?.forEach { f ->
            if (f.delete()) any = true
        }
        return any
    }

    /** 极简 JSONL 解析（与 RootLogReader.parseLine 同款语义） */
    fun parseLine(line: String): Entry? {
        return try {
            var seq = -1L; var t = ""; var tag = ""; var m = ""
            var idx = 0
            val n = line.length
            while (idx < n) {
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
