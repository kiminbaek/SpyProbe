package com.dustinky.spyprobe.ui

import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets

// v1.11: HTTP 封装（与 SpyServer API 契约对齐，原 MainActivity 逻辑 Kotlin 化）

data class LogEntry(val time: String, val tag: String, val msg: String) {
    fun display(): String = "$time [$tag] $msg"
}

data class StatusInfo(
    val pkg: String = "?",
    val versionName: String = "",
    val logCount: Int = 0,
    val classCount: Int = 0
)

data class MethodInfo(
    val signature: String,
    val params: String,
    val kind: String,
    val modifiers: String
)

data class ScanResult(
    val ok: Boolean,
    val className: String,
    val methods: List<MethodInfo>,
    val error: String = ""
)

data class HookEntry(val cls: String, val method: String, val params: String) {
    fun display(): String = "$cls.$method($params)"
}

// v1.13: 4 模式 hook 规则（fckvip 借鉴）；v1.14: +3 记录模式（SimpleHook 借鉴）
const val MODE_RETURN = 0
const val MODE_PARAM = 1
const val MODE_BLOCK = 2
const val MODE_STATIC = 3
const val MODE_RECORD_PARAMS = 4
const val MODE_RECORD_RETURN = 5
const val MODE_RECORD_BOTH = 6

fun modeName(mode: Int): String = when (mode) {
    MODE_RETURN -> "返回值"
    MODE_PARAM -> "参数值"
    MODE_BLOCK -> "拦截执行"
    MODE_STATIC -> "静态变量"
    MODE_RECORD_PARAMS -> "记录参数"
    MODE_RECORD_RETURN -> "记录返回"
    MODE_RECORD_BOTH -> "记录两者"
    else -> "模式$mode"
}

data class HijackEntry(val cls: String, val method: String, val params: String, val mode: Int,
                       val value: String, val paramValue: String,
                       val fieldName: String, val fieldType: String, val fieldValue: String) {
    fun display(): String {
        val detail = when (mode) {
            MODE_RETURN -> "-> $value"
            MODE_PARAM -> "改参[$paramValue]"
            MODE_BLOCK -> "== 拦截 =="
            MODE_STATIC -> "$fieldName($fieldType) = $fieldValue"
            MODE_RECORD_PARAMS -> "纯观测: 记参数"
            MODE_RECORD_RETURN -> "纯观测: 记返回"
            MODE_RECORD_BOTH -> "纯观测: 记参数+返回"
            else -> "-> $value"
        }
        return "[${modeName(mode)}] $cls.$method($params) $detail"
    }
}

class SpyApi(private var port: Int = 9901) {

    fun setPort(p: Int) { port = p }
    fun port(): Int = port

    fun baseUrl(): String = "http://127.0.0.1:$port"

    // ---------- HTTP ----------
    fun httpGet(path: String, readTimeoutMs: Int = 1500): String? {
        return try {
            val u = URL(baseUrl() + path)
            val c = u.openConnection() as HttpURLConnection
            c.connectTimeout = 1500
            c.readTimeout = readTimeoutMs
            val r = BufferedReader(InputStreamReader(c.inputStream, StandardCharsets.UTF_8))
            val sb = StringBuilder()
            var line: String?
            // v1.16 P1-5: 补换行（此前 /api/export、/api/logs/all 文本被压成一行不可读）
            while (r.readLine().also { line = it } != null) sb.append(line).append('\n')
            r.close()
            c.disconnect()
            sb.toString()
        } catch (t: Throwable) {
            null
        }
    }

    fun httpPost(path: String, json: String): String? {
        return try {
            val u = URL(baseUrl() + path)
            val c = u.openConnection() as HttpURLConnection
            c.requestMethod = "POST"
            c.setRequestProperty("Content-Type", "application/json")
            c.connectTimeout = 1500
            c.readTimeout = 1500
            c.doOutput = true
            val os: OutputStream = c.outputStream
            os.write(json.toByteArray(StandardCharsets.UTF_8))
            os.flush()
            os.close()
            val r = BufferedReader(InputStreamReader(c.inputStream, StandardCharsets.UTF_8))
            val sb = StringBuilder()
            var line: String?
            // v1.16 P1-5: 补换行（此前 /api/export、/api/logs/all 文本被压成一行不可读）
            while (r.readLine().also { line = it } != null) sb.append(line).append('\n')
            r.close()
            c.disconnect()
            sb.toString()
        } catch (t: Throwable) {
            null
        }
    }

    // ---------- API ----------
    fun ping(): StatusInfo? {
        val resp = httpGet("/api/ping") ?: return null
        return try {
            val o = JSONObject(resp)
            StatusInfo(
                pkg = o.optString("pkg", "?"),
                versionName = o.optString("versionName", ""),
                logCount = o.optInt("logCount", 0),
                classCount = o.optInt("classCount", 0)
            )
        } catch (t: Throwable) { null }
    }

    /** 扫描 9901-9910 找能 ping 通的 server 端口（多进程 app 可能偏移端口） */
    fun scanPorts(): Int {
        for (p in 9901..9910) {
            if (p == port) continue
            try {
                val u = URL("http://127.0.0.1:$p/api/ping")
                val c = u.openConnection() as HttpURLConnection
                c.connectTimeout = 600
                c.readTimeout = 600
                val code = c.responseCode
                c.disconnect()
                if (code == 200) return p
            } catch (t: Throwable) { }
        }
        return -1
    }

    /** 拉取增量日志；返回新行，null=未连接 */
    fun fetchLogs(since: Long): Pair<List<LogEntry>, Long>? {
        val resp = httpGet("/api/logs?since=$since") ?: return null
        return try {
            val o = JSONObject(resp)
            val next = o.optLong("next", since)
            val arr = o.optJSONArray("logs") ?: JSONArray()
            val list = ArrayList<LogEntry>()
            for (i in 0 until arr.length()) {
                val e = arr.getJSONObject(i)
                list.add(LogEntry(e.optString("time"), e.optString("tag"), e.optString("msg")))
            }
            Pair(list, next)
        } catch (t: Throwable) { null }
    }

    // v1.19 P2-1: 返回 Boolean —— 成功下发=true（响应含 ok），未连接/异常=false（供 UI 决定是否更新本地快照）
    fun sendConfig(map: Map<String, Any>): Boolean {
        return try {
            val o = JSONObject()
            for ((k, v) in map) {
                when (v) {
                    is Boolean -> o.put(k, v)
                    is Int -> o.put(k, v)
                    is Long -> o.put(k, v)
                    is String -> o.put(k, v)
                    else -> o.put(k, v.toString())
                }
            }
            val resp = httpPost("/api/config", o.toString()) ?: return false
            resp.contains("\"ok\":true") || resp.contains("\"ok\": true")
        } catch (t: Throwable) { false }
    }

    // v1.15 P0-3: GET /api/config 回读后端配置（开关状态从后端真实值初始化，不再硬编码默认值）
    fun fetchConfig(): Map<String, Any>? {
        val resp = httpGet("/api/config") ?: return null
        return try {
            val o = JSONObject(resp)
            val map = HashMap<String, Any>()
            val it = o.keys()
            while (it.hasNext()) {
                val k = it.next()
                val v = o.opt(k)
                if (v != null) map[k] = v
            }
            map
        } catch (t: Throwable) { null }
    }

    fun clear(): String? = httpPost("/api/clear", "{}")

    fun export(): String? {
        // v1.26 P0-1: 解析 /api/export JSON 的 text 字段（此前直接返回整个 JSON 字符串 → 分享出去是 JSON 乱码）
        // v1.26 P0-2: 导出单独 20s 长超时（日志量大时 1500ms 必超时 → Toast "导出失败"）
        val resp = httpGet("/api/export", 20000) ?: return null
        return try {
            val o = JSONObject(resp)
            if (!o.optBoolean("ok", false)) null else o.optString("text")
        } catch (t: Throwable) { null }
    }

    // ---------- v1.27: 历史日志（落盘文件） ----------
    /** 可用的历史日期列表（新日期在前） */
    fun historyDays(): List<String>? {
        val resp = httpGet("/api/history/days", 5000) ?: return null
        return try {
            val o = JSONObject(resp)
            if (!o.optBoolean("ok", false)) null
            else {
                val arr = o.optJSONArray("days") ?: JSONArray()
                val out = ArrayList<String>()
                for (i in 0 until arr.length()) out.add(arr.getString(i))
                out
            }
        } catch (t: Throwable) { null }
    }

    /** 读某天历史日志（JSON 数组转 LogEntry） */
    fun history(day: String, max: Int = 10000): List<LogEntry>? {
        val resp = httpGet("/api/history?day=$day&max=$max", 20000) ?: return null
        return try {
            val o = JSONObject(resp)
            if (!o.optBoolean("ok", false)) null
            else {
                val arr = o.optJSONArray("logs") ?: JSONArray()
                val out = ArrayList<LogEntry>()
                for (i in 0 until arr.length()) {
                    val j = arr.getJSONObject(i)
                    out.add(LogEntry(j.optString("t", ""), j.optString("tag", ""), j.optString("m", "")))
                }
                out
            }
        } catch (t: Throwable) { null }
    }

    /** 导出某天历史日志为纯文本 */
    fun exportDay(day: String): String? {
        val resp = httpGet("/api/export?day=$day", 30000) ?: return null
        return try {
            val o = JSONObject(resp)
            if (!o.optBoolean("ok", false)) null else o.optString("text")
        } catch (t: Throwable) { null }
    }

    /** 清空历史：day=null 清全部，否则清某天 */
    fun clearHistory(day: String?): Boolean {
        val path = if (day == null) "/api/history/clear" else "/api/history/clear?day=$day"
        val resp = httpPost(path, "{}") ?: return false
        return try { JSONObject(resp).optBoolean("ok", false) } catch (t: Throwable) { false }
    }

    // v1.29: 独立调试日志（排查"历史无记录/导出失败/重启丢日志"）
    data class DebugLogInfo(
        val init: Boolean,
        val dir: String,
        val text: String,
    )

    fun debugLog(): DebugLogInfo? {
        val resp = httpGet("/api/debuglog", 8000) ?: return null
        return try {
            val o = JSONObject(resp)
            if (!o.optBoolean("ok", false)) null
            else DebugLogInfo(
                o.optBoolean("init", false),
                o.optString("dir", ""),
                o.optString("text", ""),
            )
        } catch (t: Throwable) { null }
    }

    fun scanClass(cls: String): ScanResult {
        val resp = try {
            val o = JSONObject()
            o.put("class", cls)
            httpPost("/api/scan", o.toString())
        } catch (t: Throwable) { null }
        if (resp == null) return ScanResult(false, cls, emptyList(), "未连接")
        return try {
            val r = JSONObject(resp)
            if (!r.optBoolean("ok", false)) {
                ScanResult(false, cls, emptyList(), r.optString("error", "error"))
            } else {
                val arr = r.optJSONArray("methods") ?: JSONArray()
                val methods = ArrayList<MethodInfo>()
                for (i in 0 until arr.length()) {
                    val m = arr.getJSONObject(i)
                    methods.add(MethodInfo(
                        signature = m.optString("signature", "?"),
                        params = m.optString("params", ""),
                        kind = m.optString("kind", "method"),
                        modifiers = m.optString("modifiers", "")
                    ))
                }
                ScanResult(true, r.optString("className", cls), methods)
            }
        } catch (t: Throwable) {
            ScanResult(false, cls, emptyList(), "解析失败: $t")
        }
    }

    /** signature 如 "foo(java.lang.String,int)" -> 拆出 method + params */
    private fun splitSignature(signature: String): Pair<String, String> {
        var method = signature
        var params = ""
        if (method.contains("(")) {
            val pi = method.indexOf('(')
            val end = method.lastIndexOf(')')
            val inner = if (end > pi) method.substring(pi + 1, end).trim() else ""
            method = method.substring(0, pi).trim()
            if (inner.isNotEmpty()) {
                val parts = inner.split(",")
                params = parts.joinToString(",") { it.trim() }
            } else {
                params = ""
            }
        }
        return Pair(method, params)
    }

    // v1.15 P1-5: 增加 kind 参数 —— kind="constructor" 时 method 强制传 "<init>"（后端构造器 hook 分支）
    fun hook(cls: String, signature: String, fallbackParams: String, kind: String = "method"): String? {
        val (m, p) = splitSignature(signature)
        val method = if (kind == "constructor") "<init>" else m
        val params = if (p.isEmpty()) fallbackParams else p
        return try {
            val o = JSONObject()
            o.put("class", cls)
            o.put("method", method)
            // v1.28 P1: params 留空不写字段（后端 null=全部重载，保持 UI 旧行为）；显式传 "" 才表示无参精确
            if (params.isNotEmpty()) o.put("params", params)
            httpPost("/api/hook", o.toString())
        } catch (t: Throwable) { null }
    }

    /** v1.17: 直接按 class+method+params hook（UI 手动添加规则用，不解析 signature） */
    fun hookMethod(cls: String, method: String, params: String, kind: String = "method"): String? {
        val m = if (kind == "constructor") "<init>" else method
        return try {
            val o = JSONObject()
            o.put("class", cls)
            o.put("method", m)
            // v1.28 P1: 同上——留空=全部重载（null），""=无参精确（显式传）
            if (params.isNotEmpty()) o.put("params", params)
            httpPost("/api/hook", o.toString())
        } catch (t: Throwable) { null }
    }

    fun unhook(cls: String, method: String, params: String) {
        try {
            val o = JSONObject()
            o.put("class", cls)
            o.put("method", method)
            // v1.28 P1: 卸载时空串也缺省（后端 null/空=通配卸载全部重载，行为一致）
            if (params.isNotEmpty()) o.put("params", params)
            httpPost("/api/unhook", o.toString())
        } catch (t: Throwable) { }
    }

    fun listHooks(): List<HookEntry> {
        val resp = httpGet("/api/hooks") ?: return emptyList()
        return try {
            val o = JSONObject(resp)
            val arr = o.optJSONArray("hooks") ?: return emptyList()
            val list = ArrayList<HookEntry>()
            for (i in 0 until arr.length()) {
                val h = arr.getJSONObject(i)
                list.add(HookEntry(
                    cls = h.optString("class", "?"),
                    method = h.optString("method", "?"),
                    params = h.optString("params", "")
                ))
            }
            list
        } catch (t: Throwable) { emptyList() }
    }

    // v1.13: 4 模式规则设置（mode: 0=返回值 1=参数值 2=拦截执行 3=静态变量）；value=null 取消
    fun setHijack(cls: String, method: String, params: String, mode: Int = MODE_RETURN,
                  value: String? = null, paramValue: String = "",
                  fieldName: String = "", fieldType: String = "", fieldValue: String = "") {
        try {
            val o = JSONObject()
            o.put("class", cls)
            o.put("method", method)
            o.put("params", params)
            o.put("mode", mode)
            if (value == null) o.put("value", JSONObject.NULL) else o.put("value", value)
            o.put("paramValue", paramValue)
            o.put("fieldName", fieldName)
            o.put("fieldType", fieldType)
            o.put("fieldValue", fieldValue)
            httpPost("/api/hijack", o.toString())
        } catch (t: Throwable) { }
    }

    fun listHijacks(): List<HijackEntry> {
        val resp = httpGet("/api/hijacks") ?: return emptyList()
        return try {
            val o = JSONObject(resp)
            val arr = o.optJSONArray("hijacks") ?: return emptyList()
            val list = ArrayList<HijackEntry>()
            for (i in 0 until arr.length()) {
                val h = arr.getJSONObject(i)
                list.add(HijackEntry(
                    cls = h.optString("class", "?"),
                    method = h.optString("method", "?"),
                    params = h.optString("params", ""),
                    mode = h.optInt("mode", MODE_RETURN),
                    value = h.optString("value", ""),
                    paramValue = h.optString("paramValue", ""),
                    fieldName = h.optString("fieldName", ""),
                    fieldType = h.optString("fieldType", ""),
                    fieldValue = h.optString("fieldValue", "")
                ))
            }
            list
        } catch (t: Throwable) { emptyList() }
    }

    /** 类加载记录查询；返回 null=未连接 */
    fun queryClasses(filter: String, logAll: Boolean): Triple<Int, Int, List<String>>? {
        val resp = httpGet("/api/classes?filter=" + android.net.Uri.encode(filter) +
                (if (logAll) "&logall=true" else "")) ?: return null
        return try {
            val r = JSONObject(resp)
            val count = r.optInt("count", 0)
            val total = r.optInt("total", 0)
            val arr = r.optJSONArray("classes") ?: JSONArray()
            val list = ArrayList<String>()
            for (i in 0 until arr.length()) list.add(arr.getString(i))
            Triple(count, total, list)
        } catch (t: Throwable) { null }
    }

    fun dexdump(): String? = httpGet("/api/dexdump")
    fun dexclose() { try { httpGet("/api/dexclose") } catch (t: Throwable) { } }

    /** 字符串反查；返回 null=未连接/失败 */
    fun stringFind(str: String): String? {
        return try {
            val o = JSONObject()
            o.put("str", str)
            httpPost("/api/stringfind", o.toString())
        } catch (t: Throwable) { null }
    }
}
