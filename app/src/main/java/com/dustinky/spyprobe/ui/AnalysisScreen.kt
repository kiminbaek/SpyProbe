package com.dustinky.spyprobe.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.dustinky.spyprobe.HomeEventStore
import com.dustinky.spyprobe.HomeHttpStore
import com.dustinky.spyprobe.SpyEvent

/**
 * v1.56: 分析页——日志聚合统计（实时内存数据）
 * v1.63 P2-7: 聚合类型补全（原只有 HTTP/SQL/CRYPTO/NET）——新增
 *   URL/DETECT/PREFS/CLASS/METHOD/LOG/ACT/CERT/RULE 区块，概览补齐。
 *
 * 数据源（全部读主进程内存，纯 Kotlin 聚合，无新增 Java 层）：
 *   - HomeHttpStore.snapshot() —— HttpEntry（接口分析：host+path 次数/成功率/耗时）
 *   - HomeEventStore.all()      —— SpyEvent（SQL/CRYPTO/NET/URL/DETECT/... 聚合）
 *
 * 区块：
 *   1. 接口分析：host+path 聚合（次数/成功/失败/成功率/平均耗时/方法）
 *   2. SQL 分析：table+op 聚合（写库操作热度）
 *   3. 加密分析：algorithm 聚合（算法使用热度 + 模式分布）
 *   4. 连接分析：host 聚合（TCP/DNS 成败统计）
 *   5. URL 分析：url 来源聚合
 *   6. 检测分析：DETECT kind 聚合
 *   7. 偏好分析：PREFS getter 聚合
 *   8. 类加载：CLASS name 聚合
 *   9. 方法探测：METHOD 聚合
 *   10. 应用日志：LOG tag 聚合
 *   11. 页面流：ACT class 聚合
 *   12. 证书：CERT alias/op 聚合
 *   13. 规则引擎：RULE mode 聚合
 */

// ===== 聚合模型 =====

private data class ApiStat(
    val host: String,
    val path: String,
    val methods: MutableSet<String> = mutableSetOf(),
    var count: Int = 0,
    var ok: Int = 0,
    var fail: Int = 0,
    var totalMs: Long = 0
) {
    val avgMs: Long get() = if (count == 0) 0 else totalMs / count
    val successRate: Int get() = if (count == 0) 0 else ok * 100 / count
}

private data class SqlStat(
    val table: String,
    val op: String,
    var count: Int = 0
)

private data class CryptoStat(
    val algorithm: String,
    val modes: MutableSet<String> = mutableSetOf(),
    var count: Int = 0
)

private data class NetStat(
    val host: String,
    val kind: String, // TCP / DNS
    var count: Int = 0,
    var ok: Int = 0,
    var fail: Int = 0
)

// v1.63 P2-7: 新增聚合模型（探测类事件）
private data class UrlStat(val source: String, var count: Int = 0)
private data class DetectStat(val kind: String, var count: Int = 0)
private data class PrefsStat(val getter: String, val key: String, var count: Int = 0)
private data class ClassStat(val name: String, var count: Int = 0)
private data class MethodStat(val caller: String, var count: Int = 0)
private data class LogStat(val tag: String, val level: String, var count: Int = 0)
private data class ActStat(val className: String, val event: String, var count: Int = 0)
private data class CertStat(val alias: String, val op: String, var count: Int = 0)
private data class RuleStat(val mode: String, var count: Int = 0)

// ===== 聚合计算（纯 Kotlin，内存数据）=====

private fun aggregateApi(): List<ApiStat> {
    val map = LinkedHashMap<String, ApiStat>()
    val all = HomeHttpStore.get().snapshot()
    for (e in all) {
        val url = e.url ?: continue
        val host = try {
            val u = java.net.URI(url)
            u.host ?: url
        } catch (t: Throwable) { url }
        val path = try {
            val u = java.net.URI(url)
            val p = u.path
            if (p.isNullOrEmpty()) "/" else p
        } catch (t: Throwable) { "/" }
        val key = host + path
        val st = map.getOrPut(key) { ApiStat(host, path) }
        st.methods.add(e.method)
        st.count++
        if (e.done && e.status > 0 && e.status < 400) st.ok++
        else if (e.done && (e.status >= 400 || e.status <= 0)) st.fail++
        st.totalMs += e.durationMs
    }
    return map.values.sortedByDescending { it.count }
}

private fun aggregateSql(): List<SqlStat> {
    val map = LinkedHashMap<String, SqlStat>()
    for (e in HomeEventStore.get().all()) {
        if (!"SQL".equals(e.type)) continue
        val table = e.payload.optString("table", "")
        val op = e.payload.optString("op", "")
        val key = op + "|" + table
        val st = map.getOrPut(key) { SqlStat(table, op) }
        st.count++
    }
    return map.values.sortedByDescending { it.count }
}

private fun aggregateCrypto(): List<CryptoStat> {
    val map = LinkedHashMap<String, CryptoStat>()
    for (e in HomeEventStore.get().all()) {
        if (!"CRYPTO".equals(e.type)) continue
        val algo = e.payload.optString("algorithm", "")
        val mode = e.payload.optString("mode", "")
        val key = algo
        val st = map.getOrPut(key) { CryptoStat(algo) }
        if (mode.isNotEmpty()) st.modes.add(mode)
        st.count++
    }
    return map.values.sortedByDescending { it.count }
}

private fun aggregateNet(): List<NetStat> {
    val map = LinkedHashMap<String, NetStat>()
    for (e in HomeEventStore.get().all()) {
        if (!"NET".equals(e.type)) continue
        val host = e.payload.optString("host", "")
        val kind = e.payload.optString("kind", "")
        val ok = e.payload.optBoolean("ok", false)
        val key = kind + "|" + host
        val st = map.getOrPut(key) { NetStat(host, kind) }
        st.count++
        if (ok) st.ok++ else st.fail++
    }
    return map.values.sortedByDescending { it.count }
}

// ===== v1.63 P2-7: 探测类聚合 =====

private fun aggregateUrl(): List<UrlStat> {
    val map = LinkedHashMap<String, UrlStat>()
    for (e in HomeEventStore.get().all()) {
        if (!"URL".equals(e.type)) continue
        val source = e.payload.optString("source", "")
        val url = e.payload.optString("url", "")
        // 尽量提取 host，抓包分析更有意义
        val host = try {
            val u = java.net.URI(url)
            u.host ?: source
        } catch (t: Throwable) { source }
        val st = map.getOrPut(host) { UrlStat(host) }
        st.count++
    }
    return map.values.sortedByDescending { it.count }
}

private fun aggregateDetect(): List<DetectStat> {
    val map = LinkedHashMap<String, DetectStat>()
    for (e in HomeEventStore.get().all()) {
        if (!"DETECT".equals(e.type)) continue
        val kind = e.payload.optString("kind", "")
        val st = map.getOrPut(kind) { DetectStat(kind) }
        st.count++
    }
    return map.values.sortedByDescending { it.count }
}

private fun aggregatePrefs(): List<PrefsStat> {
    val map = LinkedHashMap<String, PrefsStat>()
    for (e in HomeEventStore.get().all()) {
        if (!"PREFS".equals(e.type)) continue
        val getter = e.payload.optString("getter", "")
        val key = e.payload.optString("key", "")
        val st = map.getOrPut(getter + "|" + key) { PrefsStat(getter, key) }
        st.count++
    }
    return map.values.sortedByDescending { it.count }
}

private fun aggregateClass(): List<ClassStat> {
    val map = LinkedHashMap<String, ClassStat>()
    for (e in HomeEventStore.get().all()) {
        if (!"CLASS".equals(e.type)) continue
        val name = e.payload.optString("name", "")
        val st = map.getOrPut(name) { ClassStat(name) }
        st.count++
    }
    return map.values.sortedByDescending { it.count }
}

private fun aggregateMethod(): List<MethodStat> {
    val map = LinkedHashMap<String, MethodStat>()
    for (e in HomeEventStore.get().all()) {
        if (!"METHOD".equals(e.type)) continue
        val caller = e.payload.optString("caller", "")
        val st = map.getOrPut(caller) { MethodStat(caller) }
        st.count++
    }
    return map.values.sortedByDescending { it.count }
}

private fun aggregateLog(): List<LogStat> {
    val map = LinkedHashMap<String, LogStat>()
    for (e in HomeEventStore.get().all()) {
        if (!"LOG".equals(e.type)) continue
        val tag = e.payload.optString("tag", "")
        val level = e.payload.optString("level", "")
        val st = map.getOrPut(tag + "|" + level) { LogStat(tag, level) }
        st.count++
    }
    return map.values.sortedByDescending { it.count }
}

private fun aggregateAct(): List<ActStat> {
    val map = LinkedHashMap<String, ActStat>()
    for (e in HomeEventStore.get().all()) {
        if (!"ACT".equals(e.type)) continue
        val className = e.payload.optString("class", "")
        val event = e.payload.optString("event", "")
        val st = map.getOrPut(className + "|" + event) { ActStat(className, event) }
        st.count++
    }
    return map.values.sortedByDescending { it.count }
}

private fun aggregateCert(): List<CertStat> {
    val map = LinkedHashMap<String, CertStat>()
    for (e in HomeEventStore.get().all()) {
        if (!"CERT".equals(e.type)) continue
        val alias = e.payload.optString("alias", "")
        val op = e.payload.optString("op", "")
        val st = map.getOrPut(alias + "|" + op) { CertStat(alias, op) }
        st.count++
    }
    return map.values.sortedByDescending { it.count }
}

private fun aggregateRule(): List<RuleStat> {
    val map = LinkedHashMap<String, RuleStat>()
    for (e in HomeEventStore.get().all()) {
        if (!"RULE".equals(e.type)) continue
        val mode = e.payload.optString("mode", "")
        val st = map.getOrPut(mode) { RuleStat(mode) }
        st.count++
    }
    return map.values.sortedByDescending { it.count }
}

// ===== UI =====

@Composable
fun AnalysisScreen(modifier: Modifier = Modifier) {
    var tick by remember { mutableIntStateOf(0) }

    // tick 变化时重新聚合（手动刷新按钮触发；数据源是 Store 内存快照）
    val api = remember(tick) { aggregateApi() }
    val sql = remember(tick) { aggregateSql() }
    val crypto = remember(tick) { aggregateCrypto() }
    val net = remember(tick) { aggregateNet() }
    // v1.63 P2-7: 探测类聚合
    val url = remember(tick) { aggregateUrl() }
    val detect = remember(tick) { aggregateDetect() }
    val prefs = remember(tick) { aggregatePrefs() }
    val clazz = remember(tick) { aggregateClass() }
    val method = remember(tick) { aggregateMethod() }
    val logAgg = remember(tick) { aggregateLog() }
    val act = remember(tick) { aggregateAct() }
    val cert = remember(tick) { aggregateCert() }
    val rule = remember(tick) { aggregateRule() }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 10.dp, vertical = 6.dp)
    ) {
        // 顶部概览 + 刷新
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                "内存聚合 · 实时抓包数据",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontSize = 10.sp,
                modifier = Modifier.weight(1f)
            )
            IconButton(onClick = { tick++ }, modifier = Modifier.size(30.dp)) {
                Icon(Icons.Filled.Refresh, contentDescription = "刷新分析",
                    modifier = Modifier.size(16.dp))
            }
        }

        // ===== 概览卡 =====
        Card(
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceContainer
            ),
            shape = RoundedCornerShape(8.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(Modifier.padding(horizontal = 12.dp, vertical = 10.dp)) {
                Text("概览", fontSize = 12.sp, fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.primary)
                Spacer(Modifier.size(6.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    OverviewChip("HTTP", api.sumOf { it.count }, Color(0xFF00E5FF))
                    OverviewChip("SQL", sql.sumOf { it.count }, Color(0xFF42A5F5))
                    OverviewChip("加密", crypto.sumOf { it.count }, Color(0xFFEF5350))
                    OverviewChip("连接", net.sumOf { it.count }, Color(0xFF66BB6A))
                    OverviewChip("URL", url.sumOf { it.count }, Color(0xFF66BB6A))
                    OverviewChip("检测", detect.sumOf { it.count }, Color(0xFFD32F2F))
                    OverviewChip("规则", rule.sumOf { it.count }, Color(0xFFF4511E))
                    OverviewChip("证书", cert.sumOf { it.count }, Color(0xFF9CCC65))
                }
            }
        }

        Spacer(Modifier.size(8.dp))

        // ===== 1. 接口分析 =====
        SectionCard(title = "接口分析", subtitle = "host+path · 成功率 / 平均耗时") {
            if (api.isEmpty()) {
                EmptyHint("暂无 HTTP 请求（抓包后自动聚合）")
            } else {
                api.take(30).forEach { st ->
                    AnalysisRow(
                        keyText = if (st.host == st.path) st.host else st.path,
                        subText = st.host,
                        rightText = "${st.count}次",
                        metaText = "${st.successRate}% · ${st.avgMs}ms",
                        metaColor = when {
                            st.count == 0 -> Color(0xFF90A4AE)
                            st.successRate >= 90 -> Color(0xFF66BB6A)
                            st.successRate >= 60 -> Color(0xFFFFA726)
                            else -> MaterialTheme.colorScheme.error
                        }
                    )
                }
                if (api.size > 30) {
                    Text("… 还有 ${api.size - 30} 个接口", fontSize = 10.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(vertical = 4.dp))
                }
            }
        }

        Spacer(Modifier.size(8.dp))

        // ===== 2. SQL 分析 =====
        SectionCard(title = "SQL 分析", subtitle = "表 × 操作 · 写库热度") {
            if (sql.isEmpty()) {
                EmptyHint("暂无 SQL 事件（SQLite 探测开启后自动聚合）")
            } else {
                sql.take(30).forEach { st ->
                    AnalysisRow(
                        keyText = if (st.table.isBlank()) st.op else st.table,
                        subText = st.op,
                        rightText = "${st.count}次",
                        metaText = "",
                        metaColor = Color(0xFF42A5F5)
                    )
                }
                if (sql.size > 30) {
                    Text("… 还有 ${sql.size - 30} 个表", fontSize = 10.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(vertical = 4.dp))
                }
            }
        }

        Spacer(Modifier.size(8.dp))

        // ===== 3. 加密分析 =====
        SectionCard(title = "加密分析", subtitle = "算法 · 模式分布") {
            if (crypto.isEmpty()) {
                EmptyHint("暂无加密事件（加密探测开启后自动聚合）")
            } else {
                crypto.take(20).forEach { st ->
                    AnalysisRow(
                        keyText = st.algorithm,
                        subText = if (st.modes.isEmpty()) "" else "模式: " + st.modes.joinToString("/"),
                        rightText = "${st.count}次",
                        metaText = "",
                        metaColor = Color(0xFFEF5350)
                    )
                }
            }
        }

        Spacer(Modifier.size(8.dp))

        // ===== 4. 连接分析 =====
        SectionCard(title = "连接分析", subtitle = "TCP/DNS · 成败统计") {
            if (net.isEmpty()) {
                EmptyHint("暂无连接事件（网络探测开启后自动聚合）")
            } else {
                net.take(30).forEach { st ->
                    AnalysisRow(
                        keyText = st.host,
                        subText = st.kind,
                        rightText = "${st.count}次",
                        metaText = "✓${st.ok} ✗${st.fail}",
                        metaColor = if (st.fail == 0) Color(0xFF66BB6A) else MaterialTheme.colorScheme.error
                    )
                }
            }
        }

        Spacer(Modifier.size(8.dp))

        // ===== v1.63 P2-7: 探测类区块 =====

        // 5. URL 分析
        SectionCard(title = "URL 分析", subtitle = "来源 host · 构造点热度") {
            if (url.isEmpty()) {
                EmptyHint("暂无 URL 构造事件（URL 探测开启后自动聚合）")
            } else {
                url.take(20).forEach { st ->
                    AnalysisRow(
                        keyText = st.source,
                        subText = "",
                        rightText = "${st.count}次",
                        metaText = "",
                        metaColor = Color(0xFF66BB6A)
                    )
                }
            }
        }

        Spacer(Modifier.size(8.dp))

        // 6. 检测分析
        SectionCard(title = "检测分析", subtitle = "环境/反调试/越狱检测命中") {
            if (detect.isEmpty()) {
                EmptyHint("暂无检测命中（环境探测开启后自动聚合）")
            } else {
                detect.take(20).forEach { st ->
                    AnalysisRow(
                        keyText = if (st.kind.isBlank()) "?" else st.kind,
                        subText = "",
                        rightText = "${st.count}次",
                        metaText = "",
                        metaColor = Color(0xFFD32F2F)
                    )
                }
            }
        }

        Spacer(Modifier.size(8.dp))

        // 7. 偏好读取分析
        SectionCard(title = "偏好读取", subtitle = "SharedPreferences getter × key") {
            if (prefs.isEmpty()) {
                EmptyHint("暂无偏好读取（偏好探测开启后自动聚合）")
            } else {
                prefs.take(20).forEach { st ->
                    AnalysisRow(
                        keyText = if (st.key.isBlank()) st.getter else st.key,
                        subText = st.getter,
                        rightText = "${st.count}次",
                        metaText = "",
                        metaColor = Color(0xFF5C6BC0)
                    )
                }
            }
        }

        Spacer(Modifier.size(8.dp))

        // 8. 类加载分析
        SectionCard(title = "类加载", subtitle = "动态加载类热度") {
            if (clazz.isEmpty()) {
                EmptyHint("暂无类加载事件（类加载探测开启后自动聚合）")
            } else {
                clazz.take(20).forEach { st ->
                    AnalysisRow(
                        keyText = st.name,
                        subText = "",
                        rightText = "${st.count}次",
                        metaText = "",
                        metaColor = Color(0xFF7E57C2)
                    )
                }
            }
        }

        Spacer(Modifier.size(8.dp))

        // 9. 方法探测分析
        SectionCard(title = "方法探测", subtitle = "caller · 自定义探测热度") {
            if (method.isEmpty()) {
                EmptyHint("暂无方法探测（方法探测开启后自动聚合）")
            } else {
                method.take(20).forEach { st ->
                    AnalysisRow(
                        keyText = st.caller,
                        subText = "",
                        rightText = "${st.count}次",
                        metaText = "",
                        metaColor = Color(0xFFEC407A)
                    )
                }
            }
        }

        Spacer(Modifier.size(8.dp))

        // 10. 应用日志分析
        SectionCard(title = "应用日志", subtitle = "目标 App Log tag × level") {
            if (logAgg.isEmpty()) {
                EmptyHint("暂无目标 App 日志（LogCat 探测开启后自动聚合）")
            } else {
                logAgg.take(20).forEach { st ->
                    AnalysisRow(
                        keyText = st.tag,
                        subText = "level=" + st.level,
                        rightText = "${st.count}次",
                        metaText = "",
                        metaColor = Color(0xFF90A4AE)
                    )
                }
            }
        }

        Spacer(Modifier.size(8.dp))

        // 11. 页面流分析
        SectionCard(title = "页面流", subtitle = "Activity/Intent 跳转热度") {
            if (act.isEmpty()) {
                EmptyHint("暂无页面事件（页面流探测开启后自动聚合）")
            } else {
                act.take(20).forEach { st ->
                    AnalysisRow(
                        keyText = st.className,
                        subText = st.event,
                        rightText = "${st.count}次",
                        metaText = "",
                        metaColor = Color(0xFFFF8A65)
                    )
                }
            }
        }

        Spacer(Modifier.size(8.dp))

        // 12. 证书分析
        SectionCard(title = "证书访问", subtitle = "mTLS 证书 alias × op") {
            if (cert.isEmpty()) {
                EmptyHint("暂无证书访问（Keystore 探测开启后自动聚合）")
            } else {
                cert.take(20).forEach { st ->
                    AnalysisRow(
                        keyText = if (st.alias.isBlank()) st.op else st.alias,
                        subText = st.op,
                        rightText = "${st.count}次",
                        metaText = "",
                        metaColor = Color(0xFF9CCC65)
                    )
                }
            }
        }

        Spacer(Modifier.size(8.dp))

        // 13. 规则引擎分析
        SectionCard(title = "规则引擎", subtitle = "hook 规则命中分布") {
            if (rule.isEmpty()) {
                EmptyHint("暂无规则命中（配置 hook 规则后自动聚合）")
            } else {
                rule.forEach { st ->
                    AnalysisRow(
                        keyText = st.mode,
                        subText = "",
                        rightText = "${st.count}次",
                        metaText = "",
                        metaColor = Color(0xFFF4511E)
                    )
                }
            }
        }

        Spacer(Modifier.size(16.dp))
    }
}

/** 区块卡片：标题 + 副标题 + 内容 */
@Composable
private fun SectionCard(title: String, subtitle: String, content: @Composable () -> Unit) {
    Card(
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer
        ),
        shape = RoundedCornerShape(8.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(Modifier.padding(horizontal = 12.dp, vertical = 10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(title, fontSize = 13.sp, fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface)
                Spacer(Modifier.width(8.dp))
                Text(subtitle, fontSize = 10.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Spacer(Modifier.size(4.dp))
            content()
        }
    }
}

/** 概览小计数（彩色数字 + 标签） */
@Composable
private fun OverviewChip(label: String, count: Int, color: Color) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(count.toString(), fontSize = 16.sp, fontWeight = FontWeight.Bold, color = color)
        Text(label, fontSize = 9.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

/** 聚合行：名称 + 次数字 + 元信息 */
@Composable
private fun AnalysisRow(
    keyText: String,
    subText: String,
    rightText: String,
    metaText: String,
    metaColor: Color
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 3.dp)
    ) {
        Column(Modifier.weight(1f)) {
            Text(
                keyText,
                fontSize = 11.sp,
                fontFamily = FontFamily.Monospace,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                color = MaterialTheme.colorScheme.onSurface
            )
            if (subText.isNotEmpty()) {
                Text(
                    subText,
                    fontSize = 9.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        if (metaText.isNotEmpty()) {
            Text(metaText, fontSize = 10.sp, color = metaColor,
                modifier = Modifier.padding(end = 8.dp))
        }
        Text(rightText, fontSize = 11.sp, fontWeight = FontWeight.SemiBold,
            color = MaterialTheme.colorScheme.primary)
    }
}
