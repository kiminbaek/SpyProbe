package com.dustinky.spyprobe.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
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
 * v1.57: 通用事件详情页（全屏，小黄鸟式）——顶栏 + 顶部 Tab（总览/原始/调用栈）
 * + 总览 SectionCard 折叠分区 + JSON 高亮 + KeyValueTable。
 *
 * 布局（对齐 HttpDetailPage 小黄鸟风格）：
 *   ┌─────────────────────────────────────────┐
 *   │ ← [SQL] UPDATE cacheObject  EVT#7  ⧉分享 │   ← 顶栏：返回+类型徽标+标题+ID+复制/分享
 *   ├─────────────────────────────────────────┤
 *   │ 总览│原始│调用栈                           │   ← 顶部 Tab（浏览器式下划线选中）
 *   ├─────────────────────────────────────────┤
 *   │  内容区：                                  │
 *   │  总览 = SectionCard 折叠分区               │
 *   │    ├ 基本信息（类型/时间/耗时/ID）          │
 *   │    ├ payload 字段（友好分组 Key-Value）     │
 *   │    └ JSON 内容（SyntaxHighlighter 高亮）   │
 *   │  原始 = SyntaxHighlighter(logLine)        │
 *   │  调用栈 = codeStyle 折叠文本                │
 *   └─────────────────────────────────────────┘
 */
@Composable
internal fun EventDetailScreen(
    entry: com.dustinky.spyprobe.SpyEvent,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    var view by remember { mutableStateOf(0) }        // 0=总览 1=原始 2=调用栈
    val col = eventColor(entry.type)

    Column(Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background)) {
        // ===== 顶栏 =====
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier
                .fillMaxWidth()
                .background(MaterialTheme.colorScheme.surfaceContainer)
                .padding(horizontal = 4.dp, vertical = 6.dp)
        ) {
            IconButton(onClick = onBack, modifier = Modifier.size(36.dp)) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回",
                    modifier = Modifier.size(20.dp))
            }
            Text(
                eventTypeLabel(entry.type),
                color = Color.White,
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                modifier = Modifier
                    .background(col, RoundedCornerShape(4.dp))
                    .padding(horizontal = 6.dp, vertical = 2.dp)
            )
            Spacer(Modifier.width(8.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    entry.title.ifBlank { entry.type },
                    style = MaterialTheme.typography.titleSmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    "EVT#${entry.id}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 10.sp
                )
            }
            if (entry.done) {
                Spacer(Modifier.width(6.dp))
                Text(
                    "${entry.durationMs}ms",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.secondary,
                    fontSize = 10.sp
                )
            }
            IconButton(onClick = {
                copyText(context, entry.logLine + if (entry.stack.isNotBlank()) "\n\n调用栈:\n" + entry.stack else "")
            }) {
                Icon(CopyIcon, contentDescription = "复制",
                    tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(18.dp))
            }
            IconButton(onClick = { shareEventText(context, entry) }) {
                Icon(Icons.Filled.Share, contentDescription = "分享",
                    tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(18.dp))
            }
        }

        // ===== 顶部 Tab（浏览器式下划线）=====
        val tabs = buildList {
            add("总览"); add("原始")
            if (entry.stack.isNotBlank()) add("调用栈")
        }
        Row(
            verticalAlignment = Alignment.Bottom,
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState())
                .padding(top = 6.dp)
        ) {
            tabs.forEachIndexed { i, label ->
                DetailTab(label = label, selected = view == i, onClick = { view = i })
            }
        }
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)

        // ===== 内容区 =====
        Box(
            Modifier
                .weight(1f)
                .fillMaxWidth()
                .background(MaterialTheme.colorScheme.surfaceContainerLowest)
        ) {
            when (view) {
                0 -> EventOverview(entry)
                1 -> EventRawView(entry)
                else -> EventStackView(entry)
            }
        }
    }
}

/** v1.57: 总览 = SectionCard 折叠分区：基本信息 + payload 字段 + JSON 内容 */
@Composable
private fun EventOverview(entry: com.dustinky.spyprobe.SpyEvent) {
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        // 基本信息
        SectionCard(title = "基本信息") {
            KvRow("类型", entry.type)
            KvRow("ID", "EVT#${entry.id}")
            KvRow("时间", java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", java.util.Locale.getDefault())
                .format(java.util.Date(entry.time)))
            if (entry.done) KvRow("耗时", "${entry.durationMs}ms")
        }

        // payload 字段（友好分组）
        val p = entry.payload
        if (p != null && p.length() > 0) {
            val groups = payloadGroups(entry.type)
            for (group in groups) {
                val rows = group.keys.mapNotNull { k ->
                    val v = p.optString(k, "")
                    if (v.isEmpty() || v == "null" || v == "{}" || v == "[]") null
                    else k to v
                }
                if (rows.isNotEmpty()) {
                    SectionCard(title = group.title) {
                        rows.forEach { (k, v) ->
                            // 大字段（JSON/长文本）用折叠 + 高亮，短字段用 KeyValueTable 行
                            if (v.length > 300 || looksLikeJson(v)) {
                                val jsonLike = looksLikeJson(v)
                                var expanded by remember { mutableStateOf(false) }
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clickable { expanded = !expanded }
                                        .padding(vertical = 3.dp)
                                ) {
                                    Text(
                                        k,
                                        style = MaterialTheme.typography.labelMedium,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        fontSize = 10.sp,
                                        modifier = Modifier.width(110.dp)
                                    )
                                    Text(
                                        if (expanded) "▾ 收起" else "▸ 展开（${v.length} 字符）",
                                        fontSize = 10.sp,
                                        color = MaterialTheme.colorScheme.secondary
                                    )
                                }
                                if (expanded) {
                                    if (jsonLike) {
                                        SyntaxHighlighter(v)
                                    } else {
                                        Text(v, style = codeStyle, fontSize = 11.sp, softWrap = true,
                                            color = MaterialTheme.colorScheme.onSurface)
                                    }
                                }
                            } else {
                                KvRow(k, v)
                            }
                        }
                    }
                }
            }

            // payload 里没被分组覆盖的其余键（兜底）
            val covered = groups.flatMap { it.keys }.toSet()
            val rest = otherKeys(p, covered.toList())
            if (rest.isNotEmpty()) {
                SectionCard(title = "其他字段") {
                    rest.forEach { k ->
                        val v = p.optString(k, "")
                        if (v.isNotEmpty() && v != "null") KvRow(k, v)
                    }
                }
            }
        }

        // 原始日志（始终可见，小字）
        if (entry.logLine.isNotBlank()) {
            SectionCard(title = "原始日志") {
                Text(entry.logLine, style = codeStyle, fontSize = 10.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant, softWrap = true)
            }
        }
    }
}

/** v1.57: 原始视图——SyntaxHighlighter 自动识别 JSON/HTTP/纯文本 */
@Composable
private fun EventRawView(entry: com.dustinky.spyprobe.SpyEvent) {
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(12.dp)
    ) {
        SyntaxHighlighter(entry.logLine)
    }
}

/** v1.57: 调用栈视图 */
@Composable
private fun EventStackView(entry: com.dustinky.spyprobe.SpyEvent) {
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(12.dp)
    ) {
        Text(entry.stack, style = codeStyle, fontSize = 10.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant, softWrap = true)
    }
}

/** v1.57: 判断字符串像不像 JSON（用于自动高亮） */
private fun looksLikeJson(s: String): Boolean {
    val t = s.trimStart()
    return (t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]"))
}

/** v1.57: payload 字段友好分组（按事件类型） */
private data class PayloadGroup(val title: String, val keys: List<String>)

private fun payloadGroups(type: String): List<PayloadGroup> = when (type) {
    "SQL" -> listOf(
        PayloadGroup("SQL 操作", listOf("op", "table")),
        PayloadGroup("语句", listOf("sql")),
        PayloadGroup("参数", listOf("args"))
    )
    "JSON" -> listOf(
        PayloadGroup("来源", listOf("source")),
        PayloadGroup("内容", listOf("content"))
    )
    "CRYPTO" -> listOf(
        PayloadGroup("算法", listOf("algorithm", "mode", "key", "iv")),
        PayloadGroup("数据", listOf("data")),
        PayloadGroup("结果", listOf("ok", "err"))
    )
    "NET" -> listOf(
        PayloadGroup("连接", listOf("host", "ip", "port", "timeout", "kind")),
        PayloadGroup("结果", listOf("ok", "err"))
    )
    "URL" -> listOf(
        PayloadGroup("URL", listOf("url")),
        PayloadGroup("来源", listOf("source", "kind"))
    )
    "CLIP" -> listOf(
        PayloadGroup("剪贴板内容", listOf("content"))
    )
    else -> listOf(PayloadGroup("字段", listOf()))
}

/** v1.57: payload 中不在分组里的其余键（按字母序） */
private fun otherKeys(p: JSONObject, covered: List<String>): List<String> {
    val out = ArrayList<String>()
    val it = p.keys()
    while (it.hasNext()) {
        val k = it.next()
        if (!covered.contains(k)) out.add(k)
    }
    out.sort()
    return out
}

/** v1.57: 分享事件文本 */
private fun shareEventText(context: android.content.Context, entry: com.dustinky.spyprobe.SpyEvent) {
    try {
        val text = "=== EVT#${entry.id} [${entry.type}] ${entry.title} ===\n\n" +
                entry.logLine + if (entry.stack.isNotBlank()) "\n\n调用栈:\n" + entry.stack else ""
        val intent = android.content.Intent(android.content.Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(android.content.Intent.EXTRA_TEXT, text)
        }
        context.startActivity(android.content.Intent.createChooser(intent, "分享事件"))
    } catch (t: Throwable) {
        android.widget.Toast.makeText(context, "分享失败: $t", android.widget.Toast.LENGTH_SHORT).show()
    }
}
