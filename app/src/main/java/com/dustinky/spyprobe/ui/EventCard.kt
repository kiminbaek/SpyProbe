package com.dustinky.spyprobe.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.dustinky.spyprobe.ui.theme.codeStyle
import org.json.JSONObject

/**
 * v1.55: 通用结构化事件卡片 + 详情页（SQL/JSON/CRYPTO/NET/URL/CLIP）
 *
 * 日志行含 [EVT#id] → LogsScreen 解析 → HomeEventStore.find(id) → EventCard 渲染卡片，
 * 点开 → EventDetailScreen 全屏详情（结构化字段表 + 原始视图）。
 *
 * 卡片按 type 着色，一眼区分：
 *   SQL     —— 蓝（数据库操作）
 *   JSON    —— 紫（序列化结构）
 *   CRYPTO  —— 红（加密）
 *   NET     —— 青（TCP/DNS 连接）
 *   URL     —— 绿（URL 构造点）
 *   CLIP    —— 琥珀（剪贴板）
 */

/** v1.55: 事件类型颜色 */
internal fun eventColor(type: String): Color = when (type) {
    "SQL" -> Color(0xFF42A5F5)
    "JSON" -> Color(0xFFAB47BC)
    "CRYPTO" -> Color(0xFFEF5350)
    "NET" -> Color(0xFF00E5FF)
    "URL" -> Color(0xFF66BB6A)
    "CLIP" -> Color(0xFFFFA726)
    else -> Color(0xFF90A4AE)
}

/** v1.55: 事件类型标签（卡片左上角小标签） */
internal fun eventTypeLabel(type: String): String = when (type) {
    "SQL" -> "SQL"
    "JSON" -> "JSON"
    "CRYPTO" -> "加密"
    "NET" -> "网络"
    "URL" -> "URL"
    "CLIP" -> "剪贴板"
    else -> type
}

/** v1.55: 从日志行解析 [EVT#N] 关联 id */
internal fun parseEvtId(line: String): Long? {
    val m = Regex("""\[EVT#(\d+)]""").find(line) ?: return null
    return m.groupValues[1].toLongOrNull()
}

/**
 * v1.55: 通用事件微卡片——命中 HomeEventStore 的 [EVT#N] 行渲染：
 *   [SQL]  UPDATE cacheObject
 *   EVT#7  2026-08-12 12:00:00            table=cacheObject
 */
@Composable
internal fun EventCard(entry: com.dustinky.spyprobe.SpyEvent, onClick: () -> Unit) {
    val col = eventColor(entry.type)
    val title = if (entry.title.isBlank()) entry.type else entry.title
    // payload 摘要：取第一个非空值字段（详情页有完整字段表）
    val summary = payloadSummary(entry.payload)
    Card(
        onClick = onClick,
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer,
        ),
        shape = RoundedCornerShape(8.dp),
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp)
    ) {
        Column(Modifier.padding(horizontal = 10.dp, vertical = 6.dp)) {
            // 第一行：类型色块 + 标题 + 状态点（done 事件显示耗时）
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    eventTypeLabel(entry.type),
                    color = Color.White,
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier
                        .background(col, RoundedCornerShape(4.dp))
                        .padding(horizontal = 5.dp, vertical = 1.dp)
                )
                Spacer(Modifier.width(6.dp))
                Text(
                    title,
                    style = MaterialTheme.typography.bodySmall,
                    fontSize = 11.sp,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f)
                )
                if (entry.done) {
                    Spacer(Modifier.width(6.dp))
                    Text(
                        "${entry.durationMs}ms",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.secondary,
                        fontSize = 9.sp
                    )
                }
            }
            // 第二行：EVT# + 时间 + 摘要
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    "EVT#${entry.id}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 9.sp
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    summary,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 9.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
    }
}

/** v1.55: payload 摘要——取 sql/args/content/host/data 等关键字段（截断 60 字符） */
private fun payloadSummary(p: JSONObject): String {
    if (p == null) return ""
    val keys = listOf("sql", "args", "content", "host", "data", "key", "err")
    for (k in keys) {
        val v = p.optString(k, "")
        if (v.isNotEmpty() && v != "null") {
            return if (v.length > 60) v.take(60) + "…" else v
        }
    }
    return ""
}

/**
 * v1.55: 通用事件详情页（全屏）——结构化字段表 + 原始视图 + 复制。
 * 字段按 payload 键名友好排序渲染：op/table/sql/args/algorithm/mode/key/iv/data/
 * host/ip/port/timeout/ok/err/source/content/truncated…
 */
@Composable
internal fun EventDetailScreen(
    entry: com.dustinky.spyprobe.SpyEvent,
    onBack: () -> Unit
) {
    Column(Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background)) {
        // 顶栏
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier
                .fillMaxWidth()
                .background(MaterialTheme.colorScheme.surfaceContainer)
                .padding(horizontal = 4.dp, vertical = 6.dp)
        ) {
            IconButton(onClick = onBack) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回", modifier = Modifier.size(18.dp))
            }
            Text(
                eventTypeLabel(entry.type),
                color = Color.White,
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                modifier = Modifier
                    .background(eventColor(entry.type), RoundedCornerShape(4.dp))
                    .padding(horizontal = 6.dp, vertical = 2.dp)
            )
            Spacer(Modifier.width(8.dp))
            Text(
                entry.title.ifBlank { entry.type },
                style = MaterialTheme.typography.titleSmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f)
            )
            Text(
                "EVT#${entry.id}",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontSize = 10.sp
            )
        }

        Column(
            Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(12.dp)
        ) {
            // ===== 结构化字段表 =====
            fieldRow("类型", entry.type)
            fieldRow("时间", java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", java.util.Locale.US)
                .format(java.util.Date(entry.time)))
            if (entry.done) fieldRow("耗时", "${entry.durationMs}ms")
            fieldRow("ID", "EVT#${entry.id}")

            HorizontalDivider(Modifier.padding(vertical = 8.dp))

            // payload 字段（友好顺序）
            val p = entry.payload
            if (p != null && p.length() > 0) {
                val order = listOf(
                    "op", "algorithm", "mode", "key", "iv", "data",
                    "table", "sql", "args",
                    "kind", "host", "ip", "port", "timeout", "ok", "err",
                    "source", "content", "truncated"
                )
                val sorted = order.filter { p.has(it) } + otherKeys(p, order)
                for (k in sorted) {
                    fieldRow(k, p.optString(k, ""))
                }
                HorizontalDivider(Modifier.padding(vertical = 8.dp))
            }

            // ===== 原始视图 =====
            Text("原始日志", style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.primary, fontSize = 11.sp)
            Spacer(Modifier.size(4.dp))
            Text(
                entry.logLine,
                style = codeStyle,
                fontSize = 11.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            // ===== 调用栈 =====
            if (entry.stack.isNotBlank()) {
                HorizontalDivider(Modifier.padding(vertical = 8.dp))
                Text("调用栈", style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.primary, fontSize = 11.sp)
                Spacer(Modifier.size(4.dp))
                Text(
                    entry.stack,
                    style = codeStyle,
                    fontSize = 10.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

/** v1.55: 详情页字段行（键 + 值，值可换行） */
@Composable
private fun fieldRow(key: String, value: String) {
    if (value.isEmpty()) return
    Column(Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
        Text(
            key,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.primary,
            fontSize = 10.sp,
            fontWeight = FontWeight.Bold
        )
        Text(
            value,
            style = codeStyle,
            fontSize = 12.sp,
            color = MaterialTheme.colorScheme.onSurface
        )
    }
}

/** v1.55: payload 中不在友好顺序里的其余键（按字母序） */
private fun otherKeys(p: JSONObject, order: List<String>): List<String> {
    val out = ArrayList<String>()
    val it = p.keys()
    while (it.hasNext()) {
        val k = it.next()
        if (!order.contains(k)) out.add(k)
    }
    out.sort()
    return out
}
