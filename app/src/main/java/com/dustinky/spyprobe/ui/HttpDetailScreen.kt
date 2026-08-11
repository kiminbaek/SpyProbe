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
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.dustinky.spyprobe.HttpEntry
import com.dustinky.spyprobe.ui.theme.codeStyle
import org.json.JSONArray
import org.json.JSONObject

/**
 * v1.48: 小黄鸟式 HTTP 请求详情页（全屏 Dialog）
 *
 * 布局：
 *   ┌─────────────────────────────────────────┐
 *   │ ✕  REQ#7  GET api.xxx.com/v1/user   ⧉分享 │   ← 顶栏：id+方法+域名+操作
 *   ├─────────────────────────────────────────┤
 *   │  [请求]  [响应]                          │   ← 底部大 Tab（请求/响应切换）
 *   ├─────────────────────────────────────────┤
 *   │  总览 │ 原始 │ 参数 │ 请求头 │ 请求体      │   ← 顶部视图 Tab（随请求/响应切换）
 *   ├─────────────────────────────────────────┤
 *   │  内容区（按视图切换）                     │
 *   └─────────────────────────────────────────┘
 *
 * 请求侧视图：总览 / 原始 / 参数 / 请求头 / 请求体
 * 响应侧视图：总览 / 原始 / 响应头 / 响应体
 */
@Composable
fun HttpDetailDialog(entry: HttpEntry, onDismiss: () -> Unit) {
    val context = LocalContext.current
    var side by remember { mutableStateOf(0) }        // 0=请求 1=响应
    var view by remember { mutableStateOf(0) }        // 0=总览 1=原始 2=参数/头 3=体
    var expandStack by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = MaterialTheme.colorScheme.surfaceContainerLowest,
        title = {
            // ===== 顶栏：id + 方法色块 + 域名 =====
            Column {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    MethodBadge(entry.method)
                    Spacer(Modifier.width(8.dp))
                    Text(
                        "REQ#${entry.id}",
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        fontSize = 12.sp
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(
                        hostOf(entry.url),
                        style = MaterialTheme.typography.titleMedium,
                        maxLines = 1,
                        overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f)
                    )
                    // 状态点
                    if (entry.done && entry.status > 0) {
                        Spacer(Modifier.width(8.dp))
                        StatusDot(entry.status)
                    }
                    IconButton(onClick = { copyText(context, entry.rawRequest() + "\n\n" + entry.rawResponse()) }) {
                        Icon(CopyIcon, contentDescription = "复制", tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(18.dp))
                    }
                    IconButton(onClick = { shareText(context, entry) }) {
                        Icon(Icons.Filled.Share, contentDescription = "分享", tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(18.dp))
                    }
                    IconButton(onClick = onDismiss) {
                        Icon(Icons.Filled.Close, contentDescription = "关闭", tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(18.dp))
                    }
                }
                // 完整 URL 小字
                Text(
                    entry.url,
                    style = codeStyle,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 10.sp,
                    maxLines = 1,
                    overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                    modifier = Modifier.padding(top = 2.dp)
                )
            }
        },
        text = {
            Column {
                // ===== 底部大 Tab：请求 / 响应 =====
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    listOf("请求", "响应").forEachIndexed { i, label ->
                        FilterChip(
                            selected = side == i,
                            onClick = { side = i; view = 0 },
                            label = { Text(label, fontSize = 13.sp, fontWeight = FontWeight.SemiBold) }
                        )
                    }
                    Spacer(Modifier.weight(1f))
                    if (entry.done && entry.status > 0) {
                        Text(
                            "${entry.durationMs}ms",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.secondary,
                            fontSize = 11.sp
                        )
                    }
                }
                Spacer(Modifier.height(8.dp))

                // ===== 顶部视图 Tab（随 side 切换）=====
                val tabs = if (side == 0) listOf("总览", "原始", "参数", "请求头", "请求体")
                           else listOf("总览", "原始", "响应头", "响应体")
                Row(
                    horizontalArrangement = Arrangement.spacedBy(4.dp),
                    modifier = Modifier.horizontalScroll(rememberScrollState())
                ) {
                    tabs.forEachIndexed { i, label ->
                        FilterChip(
                            selected = view == i,
                            onClick = { view = i },
                            label = { Text(label, fontSize = 11.sp) }
                        )
                    }
                }
                Spacer(Modifier.height(10.dp))

                // ===== 内容区 =====
                Box(
                    Modifier
                        .fillMaxWidth()
                        .heightIn(max = 460.dp)
                        .background(MaterialTheme.colorScheme.surfaceContainer, RoundedCornerShape(10.dp))
                        .padding(12.dp)
                ) {
                    when (side) {
                        0 -> when (view) {
                            0 -> OverviewView(entry, expandStack) { expandStack = !expandStack }
                            1 -> RawView(entry.rawRequest())
                            2 -> ParamsView(entry)
                            3 -> HeadersView(entry.reqHeaders)
                            else -> BodyView(entry.reqBodyType, entry.reqBody)
                        }
                        else -> when (view) {
                            0 -> OverviewView(entry, expandStack) { expandStack = !expandStack }
                            1 -> RawView(entry.rawResponse())
                            2 -> HeadersView(entry.respHeaders)
                            else -> BodyView(entry.respBodyType, entry.respBody)
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text("关闭") }
        },
        dismissButton = {}
    )
}

// ================= 视图组件 =================

/** 总览：字段网格 + 调用栈 */
@Composable
private fun OverviewView(entry: HttpEntry, expandStack: Boolean, onToggleStack: () -> Unit) {
    Column(Modifier.verticalScroll(rememberScrollState())) {
        // v1.49: 四列改 2×2 网格（小屏不再拥挤，信息更清晰）
        Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            InfoCell("方法", entry.method, methodColor(entry.method))
            InfoCell("状态码", if (entry.done && entry.status > 0) entry.status.toString() else "…", statusColor(entry.status))
        }
        Spacer(Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            InfoCell("耗时", if (entry.done) "${entry.durationMs}ms" else "进行中", null)
            InfoCell("大小", "${entry.reqBodyBytes}→${entry.respBodyBytes}B", null)
        }
        Spacer(Modifier.height(10.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            InfoCell("来源", entry.source, null)
            InfoCell("线程", entry.thread, null)
        }
        Spacer(Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            InfoCell("请求体", entry.reqBodyType, null)
            InfoCell("响应体", entry.respBodyType, null)
        }
        Spacer(Modifier.height(10.dp))
        Text("URL", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 10.sp)
        Text(entry.url, style = codeStyle, fontSize = 11.sp, softWrap = true)

        if (entry.stack.isNotBlank()) {
            Spacer(Modifier.height(10.dp))
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable(onClick = onToggleStack)
            ) {
                Text("调用栈", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.secondary, fontSize = 11.sp)
                Spacer(Modifier.width(6.dp))
                Text(if (expandStack) "▾ 收起" else "▸ 展开", fontSize = 10.sp, color = MaterialTheme.colorScheme.secondary)
            }
            if (expandStack) {
                Spacer(Modifier.height(4.dp))
                Text(
                    entry.stack,
                    style = codeStyle,
                    fontSize = 10.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    softWrap = true
                )
            }
        }
    }
}

/** 原始 HTTP 报文 */
@Composable
private fun RawView(raw: String) {
    Column(Modifier.verticalScroll(rememberScrollState())) {
        Text(raw, style = codeStyle, fontSize = 11.sp, softWrap = true)
    }
}

/** 参数（query k-v 表格） */
@Composable
private fun ParamsView(entry: HttpEntry) {
    if (entry.query.isEmpty()) {
        EmptyHint("无查询参数")
        return
    }
    Column(Modifier.verticalScroll(rememberScrollState())) {
        entry.query.forEach { e ->
            KvRow(e.key, e.value)
        }
    }
}

/** 请求头/响应头 k-v 表格 */
@Composable
private fun HeadersView(headers: Map<String, String>) {
    if (headers.isEmpty()) {
        EmptyHint("无头部信息")
        return
    }
    Column(Modifier.verticalScroll(rememberScrollState())) {
        headers.forEach { e ->
            KvRow(e.key, e.value)
        }
    }
}

/** 请求体/响应体：文本 / JSON 格式化 / Hex 三视图（v1.49: 大 body 截断 + 展开全部） */
@Composable
private fun BodyView(bodyType: String, body: String) {
    var mode by remember { mutableStateOf(0) }
    var fullBody by remember { mutableStateOf(false) }
    if (body.isEmpty()) {
        EmptyHint("无请求体")
        return
    }
    // 大 body 阈值：显示时截断到 4000 字符，点击"展开全部"看完整（防渲染卡顿）
    val bodyLimit = 4000
    val isLarge = body.length > bodyLimit
    val shownBody = if (fullBody || !isLarge) body else body.take(bodyLimit) + "\n…（已截断，共 ${body.length} 字符）"
    Column {
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            val labels = if (bodyType == "binary") listOf("Hex", "文本")
                         else listOf("文本", "JSON", "Hex")
            labels.forEachIndexed { i, label ->
                FilterChip(
                    selected = mode == i,
                    onClick = { mode = i },
                    label = { Text(label, fontSize = 10.sp) }
                )
            }
        }
        Spacer(Modifier.height(8.dp))
        Box(
            Modifier
                .fillMaxWidth()
                .heightIn(max = 380.dp)
                .verticalScroll(rememberScrollState())
                .background(MaterialTheme.colorScheme.surfaceContainerHigh, RoundedCornerShape(8.dp))
                .padding(10.dp)
        ) {
            when {
                bodyType == "binary" && mode == 0 -> Text(hexDump(shownBody, full = fullBody), style = codeStyle, fontSize = 10.sp, softWrap = true)
                mode == 1 && bodyType != "binary" -> {
                    val json = formatJsonPretty(shownBody)
                    if (json != null) Text(json, style = codeStyle, fontSize = 10.sp, softWrap = true)
                    else Text(shownBody, style = codeStyle, fontSize = 10.sp, softWrap = true)
                }
                mode == 2 && bodyType != "binary" -> Text(hexDump(shownBody, full = fullBody), style = codeStyle, fontSize = 10.sp, softWrap = true)
                else -> Text(shownBody, style = codeStyle, fontSize = 10.sp, softWrap = true)
            }
        }
        // v1.49: 大 body 展开/收起
        if (isLarge) {
            Spacer(Modifier.height(4.dp))
            Text(
                if (fullBody) "▾ 收起" else "▸ 展开全部（${body.length} 字符）",
                fontSize = 10.sp,
                color = MaterialTheme.colorScheme.secondary,
                modifier = Modifier
                    .clickable { fullBody = !fullBody }
                    .padding(vertical = 2.dp)
            )
        }
    }
}

// ================= 小组件 =================

@Composable
private fun InfoCell(label: String, value: String, color: Color?) {
    Column {
        Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 9.sp)
        Text(
            value,
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.SemiBold,
            color = color ?: MaterialTheme.colorScheme.onSurface,
            fontSize = 12.sp
        )
    }
}

@Composable
private fun KvRow(k: String, v: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 3.dp)
    ) {
        Text(
            k,
            style = codeStyle,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.secondary,
            fontSize = 11.sp,
            modifier = Modifier.width(150.dp)
        )
        Text(
            v,
            style = codeStyle,
            fontSize = 11.sp,
            color = MaterialTheme.colorScheme.onSurface,
            softWrap = true,
            modifier = Modifier.weight(1f)
        )
    }
}

@Composable
private fun EmptyHint(text: String) {
    Box(Modifier.fillMaxWidth().padding(vertical = 20.dp), contentAlignment = Alignment.Center) {
        Text(text, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun MethodBadge(method: String) {
    val m = method.uppercase()
    Text(
        m,
        color = Color.White,
        fontSize = 11.sp,
        fontWeight = FontWeight.Bold,
        modifier = Modifier
            .background(methodColor(m), RoundedCornerShape(4.dp))
            .padding(horizontal = 6.dp, vertical = 2.dp)
    )
}

@Composable
private fun StatusDot(status: Int) {
    val c = statusColor(status)
    Box(
        Modifier
            .width(8.dp)
            .height(8.dp)
            .background(c, RoundedCornerShape(50))
    )
}

// ================= 颜色 =================

/** HTTP 方法色块 */
internal fun methodColor(method: String): Color = when (method.uppercase()) {
    "GET" -> Color(0xFF2E7D32)      // 绿
    "POST" -> Color(0xFFF9A825)     // 黄
    "PUT" -> Color(0xFF1565C0)      // 蓝
    "DELETE" -> Color(0xFFC62828)   // 红
    "PATCH" -> Color(0xFF6A1B9A)    // 紫
    "HEAD" -> Color(0xFF00838F)     // 青
    "OPTIONS" -> Color(0xFF4E342E)  // 棕
    else -> Color(0xFF37474F)
}

/** 状态码颜色：2xx 绿 / 3xx 青 / 4xx 琥珀 / 5xx 红 */
internal fun statusColor(status: Int): Color = when {
    status in 200..299 -> Color(0xFF43A047)
    status in 300..399 -> Color(0xFF00ACC1)
    status in 400..499 -> Color(0xFFFFB300)
    status in 500..599 -> Color(0xFFE53935)
    else -> Color(0xFF78909C)
}

// ================= 工具 =================

internal fun hostOf(url: String): String {
    return try {
        val u = java.net.URI(url)
        val h = u.host ?: return url
        val p = u.port
        if (p > 0 && p != 80 && p != 443) "$h:$p" else h
    } catch (t: Throwable) { url }
}

private fun copyText(context: android.content.Context, text: String) {
    try {
        val cm = context.getSystemService(android.content.Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
        cm.setPrimaryClip(android.content.ClipData.newPlainText("spyprobe", text))
        android.widget.Toast.makeText(context, "已复制", android.widget.Toast.LENGTH_SHORT).show()
    } catch (t: Throwable) {
        android.widget.Toast.makeText(context, "复制失败: $t", android.widget.Toast.LENGTH_SHORT).show()
    }
}

private fun shareText(context: android.content.Context, entry: HttpEntry) {
    try {
        val text = "=== REQ#${entry.id} ${entry.method} ${entry.url} ===\n\n" +
                entry.rawRequest() + "\n\n" + entry.rawResponse()
        val intent = android.content.Intent(android.content.Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(android.content.Intent.EXTRA_TEXT, text)
        }
        context.startActivity(android.content.Intent.createChooser(intent, "分享请求"))
    } catch (t: Throwable) {
        android.widget.Toast.makeText(context, "分享失败: $t", android.widget.Toast.LENGTH_SHORT).show()
    }
}

/** JSON 格式化（带缩进；非 JSON 返回 null） */
private fun formatJsonPretty(line: String): String? {
    val start = line.indexOf('{').takeIf { it >= 0 } ?: line.indexOf('[')
    if (start < 0) return null
    val candidate = line.substring(start)
    return try {
        when {
            candidate.startsWith("[") -> JSONArray(candidate).toString(2)
            else -> JSONObject(candidate).toString(2)
        }
    } catch (t: Throwable) { null }
}

/** hex dump（v1.49: full=false 截断 256B；full=true 完整显示最多 4096B 防渲染卡顿） */
private fun hexDump(line: String, full: Boolean = false): String {
    val cap = if (full) 4096 else 256
    val bytes = line.toByteArray(Charsets.UTF_8).take(cap).toByteArray()
    val sb = StringBuilder()
    var off = 0
    while (off < bytes.size) {
        val chunk = minOf(16, bytes.size - off)
        sb.append(String.format("%04x  ", off))
        for (i in 0 until chunk) sb.append(String.format("%02x ", bytes[off + i]))
        for (i in chunk until 16) sb.append("   ")
        sb.append(" |")
        for (i in 0 until chunk) {
            val b = bytes[off + i]
            sb.append(if (b.toInt() in 0x20..0x7e) b.toInt().toChar() else '.')
        }
        sb.append("|")
        if (off + chunk < bytes.size) sb.append("\n")
        off += chunk
    }
    return sb.toString()
}
