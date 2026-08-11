package com.dustinky.spyprobe.util

import com.dustinky.spyprobe.LogPersister
import java.io.File
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
 *
 * v1.33: _<n> 从"5MB 滚动序号"升级为"会话序号"——目标进程每启动一次开新文件，
 *   8:10 一次抓包=_0，8:20 又一次=_1，天然分开。UI 卡片从"天"变为"会话"。
 */
object HomeLogReader {

    private const val TAG = "SpyProbeHomeLog"
    private const val LOG_PREFIX = "spyprobe_logs_"

    data class Entry(val seq: Long, val time: String, val tag: String, val msg: String)

    /** 会话卡片：date=开始日期；session=会话号（0,1,2...）；count=总条数；first/lastTime=首末时间 */
    data class SessionInfo(
        val date: String,
        val session: Int,
        val fileCount: Int,
        val count: Int,
        val firstTime: String,
        val lastTime: String
    )

    /** 自己家日志目录（filesDir/spyprobe_logs）；不存在返回 null */
    private fun logDir(filesDir: File): File? {
        val d = File(filesDir, "spyprobe_logs")
        return if (d.isDirectory) d else null
    }

    /** spyprobe_logs_2026-08-09_0.log -> (date=2026-08-09, session=0)；非法返回 null
     *  v1.50 P1-5: 兼容新格式 spyprobe_logs_<date>_<session>_<part>.log（5MB 滚动分段），
     *   同一会话的多 part 文件归到同一 (date, session) 分组（不再假分裂成多个会话卡片）。 */
    fun parseName(name: String): Pair<String, Int>? {
        if (!name.startsWith(LOG_PREFIX) || !name.endsWith(".log")) return null
        if (name.length < LOG_PREFIX.length + 11 + 2) return null
        val date = name.substring(LOG_PREFIX.length, LOG_PREFIX.length + 10)
        if (date.length != 10 || date[4] != '-' || date[7] != '-') return null
        val rest = name.substring(LOG_PREFIX.length + 10 + 1, name.length - 4) // "3_1" 或 "3"
        val session = rest.substringBefore('_').toIntOrNull() ?: return null
        return date to session
    }

    /**
     * 会话列表（新会话在前）：扫描全部文件，按 (date, session) 分组，
     * 统计条数 + 首末时间。v1.47 P1-8: 优先读 LogPersister 维护的 sessions.json 元数据
     * （count/first/last，写线程每 100 行落盘）——不再对每个文件全量逐行扫描；
     * 元数据缺失的文件（旧数据/手动拷贝）fallback 读首末行统计（保持兼容）。
     *
     * v1.36 P0-1: 修复字典序陷阱——旧实现 sortedBy{name} 按字典序排（_10 < _2），
     *   再用相邻 (date to session) 相等分组，同天会话 ≥10 次时 _2/_3.. 被 _10 拆散
     *   成独立会话卡片、文件归属错乱。改 groupBy 数值分组，不依赖字典序。
     */
    fun sessions(filesDir: File): List<SessionInfo> {
        val d = logDir(filesDir) ?: return emptyList()
        val byKey = d.listFiles { f -> f.isFile && parseName(f.name) != null }
            ?.groupBy { parseName(it.name)!! } ?: return emptyList()
        // v1.47 P1-8: 预读元数据（主进程 LogPersister 写线程维护的 sessions.json）
        val meta = LogPersister.get().loadMeta()
        val out = ArrayList<SessionInfo>()
        for ((key, filesOf) in byKey) {
            val (date, session) = key
            var count = 0
            var firstTime = ""
            var lastTime = ""
            for (f in filesOf) {
                val m = meta[f.name]
                if (m != null) {
                    count += m.count
                    if (m.first.isNotEmpty() && (firstTime.isEmpty() || m.first < firstTime)) firstTime = m.first
                    if (m.last.isNotEmpty() && (lastTime.isEmpty() || m.last > lastTime)) lastTime = m.last
                    continue
                }
                // 元数据缺失（旧文件/手拷）→ fallback 全读（兼容老数据，量小可接受）
                var f1: String? = null
                var l1: String? = null
                var n = 0
                try {
                    f.forEachLine { line ->
                        if (line.isBlank()) return@forEachLine
                        if (f1 == null) parseTime(line)?.let { f1 = it }
                        parseTime(line)?.let { l1 = it }
                        n++
                    }
                } catch (t: Throwable) {
                    UiLog.log("$TAG session $date/$session ${f.name} error: $t")
                }
                count += n
                if (f1 != null && (firstTime.isEmpty() || f1!! < firstTime)) firstTime = f1!!
                if (l1 != null && (lastTime.isEmpty() || l1!! > lastTime)) lastTime = l1!!
            }
            out.add(SessionInfo(date, session, filesOf.size, count, firstTime, lastTime))
        }
        out.sortWith(compareByDescending<SessionInfo> { it.date }.thenByDescending { it.session })
        return out
    }

    /** 读某会话全部日志（多分片按 seq 排序），max>0 保留最新 max 条 */
    fun readSession(filesDir: File, date: String, session: Int, max: Int = 0): List<Entry> {
        val d = logDir(filesDir) ?: return emptyList()
        val prefix = "$LOG_PREFIX$date"
        val files = d.listFiles { f ->
            f.isFile && f.name.startsWith(prefix) && f.name.endsWith(".log") &&
                    parseName(f.name)?.second == session
        }?.sortedBy { it.name } ?: return emptyList()
        val out = ArrayList<Entry>()
        for (f in files) {
            try {
                f.forEachLine { line ->
                    if (line.isBlank()) return@forEachLine
                    parseLine(line)?.let { out.add(it) }
                }
            } catch (t: Throwable) {
                UiLog.log("$TAG read $date/$session ${f.name} error: $t")
            }
        }
        out.sortBy { it.seq }
        if (max > 0 && out.size > max) {
            return ArrayList(out.subList(out.size - max, out.size))
        }
        return out
    }

    /** 读某天全部会话（兼容旧调用：按天聚合），max>0 保留最新 max 条 */
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

    /** 删除指定会话（date+session）；返回是否删了文件 */
    fun clearSession(filesDir: File, date: String, session: Int): Boolean {
        val d = logDir(filesDir) ?: return false
        var any = false
        d.listFiles { f ->
            f.isFile && parseName(f.name) == (date to session)
        }?.forEach { f ->
            if (f.delete()) any = true
        }
        return any
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

    /** 极简 JSON 行取 t 字段（首末时间用） */
    private fun parseTime(line: String): String? {
        val i = line.indexOf("\"t\":\"")
        if (i < 0) return null
        val j = line.indexOf('"', i + 5)
        if (j < 0) return null
        return line.substring(i + 5, j)
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
                                        } catch (t3: Throwable) {
                                            sb.append('u'); i += 2
                                        }
                                    } else {
                                        sb.append('u'); i += 2
                                    }
                                }
                                else -> { sb.append(e); i += 2 }
                            }
                        } else if (c == '"') { i++; break }
                        else { sb.append(c); i++ }
                    }
                    when (key) {
                        "seq" -> seq = sb.toString().toLongOrNull() ?: -1L
                        "t" -> t = sb.toString()
                        "tag" -> tag = sb.toString()
                        "m" -> m = sb.toString()
                    }
                    idx = i
                } else {
                    val end = idx
                    var j = end
                    while (j < n && line[j] != ',' && line[j] != '}') j++
                    when (key) {
                        "seq" -> seq = line.substring(end, j).trim().toLongOrNull() ?: -1L
                    }
                    idx = j
                }
            }
            Entry(seq, t, tag, m)
        } catch (t: Throwable) {
            null
        }
    }
}
