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
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Share
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
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.dustinky.spyprobe.HttpEntry
import com.dustinky.spyprobe.ui.theme.codeStyle

/**
 * v1.51: 小黄鸟式全屏请求详情页（v1.48 Dialog 弹窗 → 全屏页）
 *
 * 布局：
 *   ┌─────────────────────────────────────────┐
 *   │ ← [GET] REQ#7 api.xxx.com      ●200 ⧉分享 │   ← 顶栏：返回+方法+REQ#+域名+状态+复制/分享
 *   ├─────────────────────────────────────────┤
 *   │  url 完整小字                             │
 *   ├─────────────────────────────────────────┤
 *   │ 总览│原始│参数(2)│请求头(5)│请求体          │   ← 顶部 Tab（浏览器式下划线选中）
 *   ├─────────────────────────────────────────┤
 *   │  内容区（折叠分区/双列表格/语法高亮）        │
 *   ├─────────────────────────────────────────┤
 *   │  ↑ 请求（荧光绿选中）   ↓ 响应（灰）        │   ← 底部切换（小黄鸟式）
 *   └─────────────────────────────────────────┘
 *
 * 请求侧：总览 / 原始 / 参数 / 请求头 / 请求体
 * 响应侧：总览 / 原始 / 响应头 / 响应体
 */
@Composable
fun HttpDetailPage(entry: HttpEntry, onBack: () -> Unit) {
    val context = LocalContext.current
    var side by remember { mutableStateOf(0) }        // 0=请求 1=响应
    var view by remember { mutableStateOf(0) }        // 0=总览 1=原始 2=参数/头 3=体
    var expandStack by remember { mutableStateOf(false) }

    Dialog(
        onDismissRequest = onBack,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Column(
            Modifier
                .fillMaxSize()
                .background(MaterialTheme.colorScheme.surfaceContainerLowest)
                .statusBarsPadding()
                .navigationBarsPadding()
        ) {
            // ===== 顶栏 =====
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 4.dp, vertical = 6.dp)
            ) {
                IconButton(onClick = onBack, modifier = Modifier.size(36.dp)) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回",
                        modifier = Modifier.size(20.dp))
                }
                MethodBadge(entry.method)
                Spacer(Modifier.width(6.dp))
                Column(Modifier.weight(1f)) {
                    Text(
                        "REQ#${entry.id}",
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        fontSize = 11.sp
                    )
                    Text(
                        hostOf(entry.url),
                        style = MaterialTheme.typography.titleMedium,
                        fontSize = 13.sp,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
                if (entry.done && entry.status > 0) {
                    Spacer(Modifier.width(6.dp))
                    StatusBadge(entry.status, entry.statusMsg)
                }
                IconButton(onClick = { copyText(context, entry.rawRequest() + "\n\n" + entry.rawResponse()) }) {
                    Icon(CopyIcon, contentDescription = "复制", tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(18.dp))
                }
                IconButton(onClick = { shareText(context, entry) }) {
                    Icon(Icons.Filled.Share, contentDescription = "分享", tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(18.dp))
                }
            }
            // 完整 URL 小字
            Text(
                entry.url,
                style = codeStyle,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontSize = 10.sp,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.padding(horizontal = 12.dp)
            )

            // ===== 顶部视图 Tab（浏览器式下划线，随 side 切换）=====
            val tabs = if (side == 0) listOf("总览", "原始", "参数", "请求头", "请求体")
                       else listOf("总览", "原始", "响应头", "响应体")
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

            // ===== 底部切换条（小黄鸟式 ↑请求 / ↓响应）=====
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .fillMaxWidth()
                    .background(MaterialTheme.colorScheme.surface)
                    .padding(vertical = 4.dp)
            ) {
                BottomSwitch("↑ 请求", selected = side == 0) { side = 0; view = 0 }
                BottomSwitch("↓ 响应", selected = side == 1) { side = 1; view = 0 }
                Spacer(Modifier.weight(1f))
                if (entry.done && entry.status > 0) {
                    Text(
                        "${entry.durationMs}ms",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.secondary,
                        fontSize = 11.sp,
                        modifier = Modifier.padding(end = 14.dp)
                    )
                }
            }
        }
    }
}

// ================= Tab / 切换条 =================

/** v1.51: 浏览器式 Tab——文字 + 底部 2dp 色条（选中荧光绿） */
@Composable
internal fun DetailTab(label: String, selected: Boolean, onClick: () -> Unit) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = Modifier
            .clickable(onClick = onClick)
            .padding(horizontal = 14.dp, vertical = 8.dp)
    ) {
        Text(
            label,
            fontSize = 12.sp,
            fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal,
            color = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(Modifier.height(4.dp))
        Box(
            Modifier
                .width(22.dp)
                .height(2.dp)
                .background(
                    if (selected) MaterialTheme.colorScheme.primary else Color.Transparent,
                    RoundedCornerShape(1.dp)
                )
        )
    }
}

/** v1.51: 底部 ↑请求 / ↓响应 切换（选中荧光绿 + 加粗） */
@Composable
private fun BottomSwitch(label: String, selected: Boolean, onClick: () -> Unit) {
    Text(
        label,
        fontSize = 13.sp,
        fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal,
        color = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 8.dp)
    )
}

// ================= 总览（折叠分区）=================

/** v1.51: 总览 = SectionCard 折叠分区：状态/详情/调用栈 */
@Composable
private fun OverviewView(entry: HttpEntry, expandStack: Boolean, onToggleStack: () -> Unit) {
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        SectionCard(title = "状态") {
            KvRow("方法", entry.method)
            KvRow("状态码", if (entry.done && entry.status > 0) "${entry.status} ${entry.statusMsg}" else "…")
            KvRow("耗时", if (entry.done) "${entry.durationMs}ms" else "进行中")
            KvRow("大小", "${fmtBytes(entry.reqBodyBytes.toLong())} → ${fmtBytes(entry.respBodyBytes.toLong())}")
        }
        SectionCard(title = "请求详情") {
            KvRow("来源", entry.source)
            KvRow("线程", entry.thread)
            KvRow("请求体类型", entry.reqBodyType)
            KvRow("响应体类型", entry.respBodyType)
            KvRow("时间", java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", java.util.Locale.getDefault())
                .format(java.util.Date(entry.time)))
        }
        SectionCard(title = "URL", initiallyExpanded = true) {
            Text(entry.url, style = codeStyle, fontSize = 11.sp, softWrap = true,
                color = MaterialTheme.colorScheme.onSurface)
        }
        if (entry.stack.isNotBlank()) {
            SectionCard(
                title = "调用栈",
                subtitle = if (expandStack) "▾ 收起" else "▸ 展开",
                initiallyExpanded = expandStack,
                onClickTitle = onToggleStack
            ) {
                Text(entry.stack, style = codeStyle, fontSize = 10.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant, softWrap = true)
            }
        }
    }
}

/** v1.51: 可折叠分区卡片——标题条 + 箭头 + 内容 */
@Composable
internal fun SectionCard(
    title: String,
    subtitle: String? = null,
    initiallyExpanded: Boolean = true,
    onClickTitle: (() -> Unit)? = null,
    content: @Composable () -> Unit
) {
    var expanded by remember { mutableStateOf(initiallyExpanded) }
    Column(
        Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surfaceContainer, RoundedCornerShape(10.dp))
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier
                .fillMaxWidth()
                .clickable { onClickTitle?.invoke() ?: run { expanded = !expanded } }
                .padding(horizontal = 12.dp, vertical = 10.dp)
        ) {
            Text(if (expanded) "▾" else "▸", fontSize = 11.sp,
                color = MaterialTheme.colorScheme.secondary)
            Spacer(Modifier.width(6.dp))
            Text(title, style = MaterialTheme.typography.titleSmall, fontSize = 12.sp)
            if (subtitle != null) {
                Spacer(Modifier.weight(1f))
                Text(subtitle, fontSize = 10.sp, color = MaterialTheme.colorScheme.secondary)
            }
        }
        if (expanded) {
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            Column(Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
                content()
            }
        }
    }
}

// ================= 原始视图（语法高亮）=================

/** v1.51: 原始 HTTP 报文——语法高亮（请求/响应通用，自动识别） */
@Composable
internal fun RawView(raw: String) {
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(12.dp)
    ) {
        SyntaxHighlighter(raw)
    }
}

// ================= 参数 / 头部（双列表格）=================

@Composable
private fun ParamsView(entry: HttpEntry) {
    if (entry.query.isEmpty()) {
        EmptyHint("无查询参数")
        return
    }
    KeyValueTable(entry.query.toList())
}

@Composable
private fun HeadersView(headers: Map<String, String>) {
    if (headers.isEmpty()) {
        EmptyHint("无头部信息")
        return
    }
    KeyValueTable(headers.toList())
}

/** v1.51: 双列表格（Key 左白 / Value 右略暗，细线分隔） */
@Composable
internal fun KeyValueTable(entries: List<Pair<String, String>>) {
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 12.dp)
    ) {
        entries.forEachIndexed { i, (k, v) ->
            Row(
                Modifier
                    .fillMaxWidth()
                    .padding(vertical = 6.dp)
            ) {
                Text(
                    k,
                    style = codeStyle,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface,
                    fontSize = 11.sp,
                    modifier = Modifier.width(140.dp)
                )
                Text(
                    v,
                    style = codeStyle,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 11.sp,
                    softWrap = true,
                    modifier = Modifier.weight(1f)
                )
            }
            if (i < entries.lastIndex) {
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            }
        }
    }
}

// ================= 请求体/响应体（语法高亮三视图）=================

/** 请求体/响应体：文本 / JSON 高亮 / Hex 三视图（v1.49: 大 body 截断 + 展开全部） */
@Composable
internal fun BodyView(bodyType: String, body: String) {
    var mode by remember { mutableStateOf(0) }
    var fullBody by remember { mutableStateOf(false) }
    if (body.isEmpty()) {
        EmptyHint("无内容")
        return
    }
    // 大 body 阈值：显示时截断到 4000 字符，点击"展开全部"看完整（防渲染卡顿）
    val bodyLimit = 4000
    val isLarge = body.length > bodyLimit
    val shownBody = if (fullBody || !isLarge) body else body.take(bodyLimit) + "\n…（已截断，共 ${body.length} 字符）"
    Column(Modifier.fillMaxSize()) {
        Row(
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
        ) {
            val labels = if (bodyType == "binary") listOf("Hex", "文本")
                         else listOf("文本", "JSON", "Hex")
            labels.forEachIndexed { i, label ->
                DetailTab(label = label, selected = mode == i, onClick = { mode = i })
            }
        }
        Box(
            Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .background(MaterialTheme.colorScheme.surfaceContainer, RoundedCornerShape(10.dp))
                .padding(10.dp)
        ) {
            when {
                bodyType == "binary" && mode == 0 -> Text(hexDump(shownBody, full = fullBody), style = codeStyle, fontSize = 10.sp, softWrap = true)
                mode == 1 && bodyType != "binary" -> SyntaxHighlighter(shownBody)
                mode == 2 && bodyType != "binary" -> Text(hexDump(shownBody, full = fullBody), style = codeStyle, fontSize = 10.sp, softWrap = true)
                else -> Text(shownBody, style = codeStyle, fontSize = 10.sp, softWrap = true)
            }
        }
        // v1.49: 大 body 展开/收起
        if (isLarge) {
            Text(
                if (fullBody) "▾ 收起" else "▸ 展开全部（${body.length} 字符）",
                fontSize = 10.sp,
                color = MaterialTheme.colorScheme.secondary,
                modifier = Modifier
                    .clickable { fullBody = !fullBody }
                    .padding(horizontal = 12.dp, vertical = 4.dp)
            )
        }
    }
}

// ================= 语法高亮（v1.51 新增）=================

/** 高亮类型：JSON 或 HTTP 报文（自动探测） */
private enum class HlKind { JSON, HTTP, PLAIN }

/**
 * v1.51: 通用语法高亮 Text——JSON（键琥珀/字符串荧光绿/数字白/null粉）
 * 和 HTTP 报文（协议蓝/方法红/URL浅绿/头键绿/状态琥珀）自动识别。
 */
@Composable
internal fun SyntaxHighlighter(text: String) {
    val annotated = remember(text) { highlightAnnotated(text) }
    Text(annotated, style = codeStyle, fontSize = 10.sp, softWrap = true)
}

/** 探测并构建高亮 AnnotatedString */
private fun highlightAnnotated(text: String): androidx.compose.ui.text.AnnotatedString {
    val kind = detectKind(text)
    return when (kind) {
        HlKind.JSON -> highlightJson(text)
        HlKind.HTTP -> highlightHttp(text)
        HlKind.PLAIN -> androidx.compose.ui.text.AnnotatedString(text)
    }
}

private fun detectKind(text: String): HlKind {
    val t = text.trimStart()
    if (t.startsWith("{") || t.startsWith("[")) return HlKind.JSON
    // HTTP 报文：请求行 POST xxx HTTP/1.1 或 响应行 HTTP/1.1 200
    if (Regex("""^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+\s+HTTP/\S+""").containsMatchIn(t)) return HlKind.HTTP
    if (Regex("""^HTTP/\S+\s+\d{3}""").containsMatchIn(t)) return HlKind.HTTP
    return HlKind.PLAIN
}

/** JSON 高亮：键琥珀 #FFB300 / 字符串荧光绿 #00E676 / 数字白 / null粉 #FF80AB */
private fun highlightJson(text: String): androidx.compose.ui.text.AnnotatedString {
    val builder = androidx.compose.ui.text.AnnotatedString.Builder()
    val keyCol = Color(0xFFFFB300)
    val strCol = Color(0xFF00E676)
    val numCol = Color(0xFFFFFFFF)
    val nullCol = Color(0xFFFF80AB)

    // 匹配 JSON token：键("xxx":)、字符串值("xxx")、数字、关键字
    // 用 token 切分避免嵌套匹配
    // 标点字符类中的 [ ] 必须转义，否则外层 [ 缺闭合 → PatternSyntaxException（v1.53.1 P0 修复：点「原始」闪退）
    val tokenRegex = Regex("""("[^"\\]*(?:\\.[^"\\]*)*")(\s*:)?|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|\b(null|true|false)\b|([{}\[\],])""")
    var last = 0
    for (m in tokenRegex.findAll(text)) {
        if (m.range.first > last) builder.append(text.substring(last, m.range.first))
        val g1 = m.groupValues[1]
        val g2 = m.groupValues[2]
        val g3 = m.groupValues[3]
        val g4 = m.groupValues[4]
        val g5 = m.groupValues[5]
        when {
            g2.isNotEmpty() -> {   // 键 + 冒号
                builder.withStyle(SpanStyle(color = keyCol)) { append(g1) }
                builder.append(":")
            }
            g1.isNotEmpty() ->     // 字符串值
                builder.withStyle(SpanStyle(color = strCol)) { append(g1) }
            g3.isNotEmpty() ->     // 数字
                builder.withStyle(SpanStyle(color = numCol)) { append(g3) }
            g4.isNotEmpty() ->     // null/true/false
                builder.withStyle(SpanStyle(color = nullCol)) { append(g4) }
            g5.isNotEmpty() ->     // 标点
                builder.append(g5)
        }
        last = m.range.last + 1
    }
    if (last < text.length) builder.append(text.substring(last))
    return builder.toAnnotatedString()
}

/** HTTP 报文高亮：协议蓝 #00E5FF / 方法红 #FF5252 / URL浅绿 #69F0AE / 头键绿 / 状态琥珀 */
private fun highlightHttp(text: String): androidx.compose.ui.text.AnnotatedString {
    val builder = androidx.compose.ui.text.AnnotatedString.Builder()
    val protoCol = Color(0xFF00E5FF)
    val methodCol = Color(0xFFFF5252)
    val urlCol = Color(0xFF69F0AE)
    val keyCol = Color(0xFF69F0AE)
    val statusCol = Color(0xFFFFB300)

    val lines = text.split("\n")
    var bodyStarted = false
    for ((idx, line) in lines.withIndex()) {
        if (idx > 0) builder.append("\n")
        if (bodyStarted) {
            // body：整体按 JSON 高亮（失败则原文）
            builder.append(highlightJson(line).text.ifEmpty { line })
            continue
        }
        // 请求行: METHOD URL HTTP/x.x
        val reqM = Regex("""^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)(\s+)(\S+)(\s+)(HTTP/\S+)""").find(line)
        if (reqM != null) {
            builder.withStyle(SpanStyle(color = methodCol, fontWeight = FontWeight.Bold)) { append(reqM.groupValues[1]) }
            builder.append(reqM.groupValues[2])
            builder.withStyle(SpanStyle(color = urlCol)) { append(reqM.groupValues[3]) }
            builder.append(reqM.groupValues[4])
            builder.withStyle(SpanStyle(color = protoCol)) { append(reqM.groupValues[5]) }
            bodyStarted = line.isBlank().not()
            continue
        }
        // 响应行: HTTP/x.x 200 OK
        val respM = Regex("""^(HTTP/\S+)(\s+)(\d{3})(.*)$""").find(line)
        if (respM != null) {
            builder.withStyle(SpanStyle(color = protoCol)) { append(respM.groupValues[1]) }
            builder.append(respM.groupValues[2])
            builder.withStyle(SpanStyle(color = statusCol, fontWeight = FontWeight.Bold)) { append(respM.groupValues[3]) }
            builder.append(respM.groupValues[4])
            bodyStarted = line.isBlank().not()
            continue
        }
        // 头行: Key: Value
        val hdrM = Regex("""^([^:]+):(\s*)(.*)$""").find(line)
        if (hdrM != null) {
            builder.withStyle(SpanStyle(color = keyCol)) { append(hdrM.groupValues[1]) }
            builder.append(":")
            builder.append(hdrM.groupValues[2])
            builder.append(hdrM.groupValues[3])
            continue
        }
        // 空行 → 之后是 body
        if (line.isBlank()) { builder.append(line); bodyStarted = true; continue }
        builder.append(line)
    }
    return builder.toAnnotatedString()
}

// ================= 小组件 =================

@Composable
internal fun EmptyHint(text: String) {
    Box(Modifier.fillMaxWidth().padding(vertical = 24.dp), contentAlignment = Alignment.Center) {
        Text(text, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
internal fun KvRow(k: String, v: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
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
            v,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurface,
            fontSize = 12.sp,
            softWrap = true,
            modifier = Modifier.weight(1f)
        )
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

/** v1.51: 状态码胶囊（绿色底 + 白字），顶栏更醒目 */
@Composable
private fun StatusBadge(status: Int, statusMsg: String) {
    val c = statusColor(status)
    val txt = if (statusMsg.isNotBlank()) "$status $statusMsg" else status.toString()
    Text(
        txt,
        color = Color.White,
        fontSize = 10.sp,
        fontWeight = FontWeight.Bold,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis,
        modifier = Modifier
            .background(c.copy(alpha = 0.85f), RoundedCornerShape(4.dp))
            .padding(horizontal = 6.dp, vertical = 2.dp)
    )
}

// ================= 颜色（v1.51 统一到 SpyProbe 主题色系）=================

/** HTTP 方法色块：荧光绿 GET / 琥珀 POST / 青蓝 PUT/PATCH / 亮红 DELETE */
internal fun methodColor(method: String): Color = when (method.uppercase()) {
    "GET" -> Color(0xFF00E676)      // 荧光绿（主题 primary）
    "POST" -> Color(0xFFFFB300)     // 琥珀（主题 tertiary）
    "PUT", "PATCH" -> Color(0xFF00E5FF)   // 青蓝（主题 secondary）
    "DELETE" -> Color(0xFFFF5252)   // 亮红（主题 error）
    "HEAD", "OPTIONS" -> Color(0xFF00E5FF) // 青蓝
    else -> Color(0xFF546E7A)
}

/** 状态码颜色：2xx 荧光绿 / 3xx 青蓝 / 4xx 琥珀 / 5xx 亮红 */
internal fun statusColor(status: Int): Color = when {
    status in 200..299 -> Color(0xFF00E676)
    status in 300..399 -> Color(0xFF00E5FF)
    status in 400..499 -> Color(0xFFFFB300)
    status in 500..599 -> Color(0xFFFF5252)
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

internal fun copyText(context: android.content.Context, text: String) {
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

/** hex dump（v1.49: full=false 截断 256B；full=true 完整显示最多 4096B 防渲染卡顿） */
internal fun hexDump(line: String, full: Boolean = false): String {
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
