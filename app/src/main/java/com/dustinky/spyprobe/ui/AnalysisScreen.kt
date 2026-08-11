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
 *
 * 数据源（全部读主进程内存，纯 Kotlin 聚合，无新增 Java 层）：
 *   - HomeHttpStore.snapshot() —— HttpEntry（接口分析：host+path 次数/成功率/耗时）
 *   - HomeEventStore.all()      —— SpyEvent（SQL/CRYPTO/NET 聚合）
 *
 * 四大区块：
 *   1. 接口分析：host+path 聚合（次数/成功/失败/成功率/平均耗时/方法）
 *   2. SQL 分析：table+op 聚合（写库操作热度）
 *   3. 加密分析：algorithm 聚合（算法使用热度 + 模式分布）
 *   4. 连接分析：host 聚合（TCP/DNS 成败统计）
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

// ===== UI =====

@Composable
fun AnalysisScreen(modifier: Modifier = Modifier) {
    var tick by remember { mutableIntStateOf(0) }

    // tick 变化时重新聚合（手动刷新按钮触发；数据源是 Store 内存快照）
    val api = remember(tick) { aggregateApi() }
    val sql = remember(tick) { aggregateSql() }
    val crypto = remember(tick) { aggregateCrypto() }
    val net = remember(tick) { aggregateNet() }

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
                    OverviewChip("接口数", api.size, MaterialTheme.colorScheme.primary)
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

@Composable
private fun EmptyHint(text: String) {
    Text(
        text,
        fontSize = 10.sp,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(vertical = 6.dp)
    )
}
