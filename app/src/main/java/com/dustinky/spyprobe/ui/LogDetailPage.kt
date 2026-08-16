package com.dustinky.spyprobe.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.dustinky.spyprobe.ui.theme.codeStyle

/**
 * v2.1.1: 日志行全屏详情分析页——替代旧 LogDetailDialog 小弹窗。
 *
 * 旧实现：AlertDialog 三 Tab（文本/JSON/Hex），没法分析，用户反馈"抓包结果要能点开有详情分析页"。
 * 本页面复用 HttpDetailPage 同款全屏布局：顶栏徽标 + 下划线 Tab（总览/原始/JSON/Hex）。
 * "总览"按行内容自动解析结构化字段：
 *   - [TCP] >>> ip:port->ip:port [N B hex] → 连接方向/源/目标/大小
 *   - KL dart:io xxx #N invoked → 函数名/调用次数/语义（加密前/解密后明文）
 *   - REQ#/EVT# → 提示回列表点卡片看深度详情
 *   - JSON 行 → 格式化预览
 *   - 其他 → 时间戳/标签/正文拆行
 */
@Composable
internal fun LogDetailPage(line: String, onBack: () -> Unit) {
    val context = androidx.compose.ui.platform.LocalContext.current
    var view by remember { mutableStateOf(0) }        // 0=总览 1=原始 2=JSON 3=Hex

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
                    .background(MaterialTheme.colorScheme.surfaceContainer)
                    .padding(horizontal = 4.dp, vertical = 6.dp)
            ) {
                IconButton(onClick = onBack, modifier = Modifier.size(36.dp)) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回",
                        modifier = Modifier.size(20.dp))
                }
                val badge = analyzeBadge(line)
                Text(
                    badge.label,
                    color = Color.White,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier
                        .background(badge.color, RoundedCornerShape(4.dp))
                        .padding(horizontal = 6.dp, vertical = 2.dp)
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    badge.title.ifBlank { "日志分析" },
                    style = MaterialTheme.typography.titleSmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f)
                )
                IconButton(onClick = { copyText(context, line) }) {
                    Icon(CopyIcon, contentDescription = "复制",
                        tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(18.dp))
                }
                IconButton(onClick = { shareLine(context, line) }) {
                    Icon(Icons.Filled.Share, contentDescription = "分享",
                        tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(18.dp))
                }
            }

            // ===== 顶部 Tab =====
            Row(
                verticalAlignment = Alignment.Bottom,
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState())
                    .padding(top = 6.dp)
            ) {
                listOf("总览", "原始", "JSON", "Hex").forEachIndexed { i, label ->
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
                    0 -> LogOverview(line)
                    1 -> RawScroll(line)
                    2 -> JsonView(line)
                    else -> RawScroll(hexDump(line), mono = true)
                }
            }
        }
    }
}

/** 分析徽标：识别行类型（TCP/KL/REQ/JSON/普通） */
private data class Badge(val label: String, val color: Color, val title: String)

private fun analyzeBadge(line: String): Badge {
    return when {
        line.contains("[TCP]") || line.contains("[Net") || line.contains("[SSL") ||
                line.contains("[OkHttp") || line.contains("[Cronet") || line.contains("[HUC") ->
            Badge("TCP", Color(0xFF00E676), extractTcpTitle(line) ?: "网络流量")
        line.contains("KL dart:io") || line.contains("[KEYLOG]") || line.contains("[KV]") ->
            Badge("KL", Color(0xFFFFC107), extractKlTitle(line))
        line.contains("[REQ#") ->
            Badge("HTTP", Color(0xFF42A5F5), "HTTP 请求（点列表卡片看深度详情）")
        line.contains("[EVT#") ->
            Badge("EVT", Color(0xFFCE93D8), "事件（点列表卡片看深度详情）")
        formatJson(line) != null -> Badge("JSON", Color(0xFFFFB300), "JSON 数据")
        else -> Badge("LOG", Color(0xFF78909C), "日志行")
    }
}

/** TCP 行 → 摘要标题：方向 + 源->目标 + 大小 */
private fun extractTcpTitle(line: String): String? {
    val arrow = Regex("""([<>]{2,3})\s*(\S+?)\s*->\s*(\S+?)(?:\s+\[|$)""").find(line)
    val size = Regex("""\[(\d+)B hex\]""").find(line)
    val dir = arrow?.groupValues?.get(1) ?: ""
    val arrowTxt = when {
        dir.startsWith(">>>") -> "上行"
        dir.startsWith("<<<") -> "下行"
        else -> "流量"
    }
    val sizeTxt = size?.groupValues?.get(1)?.let { "${it}B" } ?: ""
    return listOfNotNull(
        arrowTxt,
        arrow?.groupValues?.get(2),
        "→",
        arrow?.groupValues?.get(3),
        sizeTxt
    ).joinToString(" ")
}

/** KL 行 → 函数名 + 计数 */
private fun extractKlTitle(line: String): String {
    val m = Regex("""KL dart:io (\w+)(?: #(\d+))?\s+invoked""").find(line)
    val fn = m?.groupValues?.get(1) ?: "dart:io"
    val n = m?.groupValues?.get(2)
    return "KL dart:io $fn" + if (n != null) " × $n" else ""
}

// ================= 总览 =================
private fun parseTime(line: String): String? {
    val m = Regex("""^(\d{2}:\d{2}:\d{2}(?:\.\d{3})?)""").find(line)
    return m?.groupValues?.get(1)
}

private fun parseTagPart(line: String): Triple<String, String, String> {
    // [时间] [Tag] 正文
    val time = parseTime(line) ?: ""
    var rest = line.removePrefix(time).trimStart()
    val tagEnd = rest.indexOf(']')
    val tag = if (tagEnd > 0 && rest.startsWith("[")) rest.substring(1, tagEnd) else ""
    val msg = if (tagEnd > 0) rest.substring(tagEnd + 1).trim() else rest
    return Triple(time, tag, msg)
}

@Composable
private fun LogOverview(line: String) {
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        // 基本信息
        SectionCard(title = "基本信息") {
            val (time, tag, msg) = parseTagPart(line)
            if (time.isNotEmpty()) KvRow("时间", time)
            if (tag.isNotEmpty()) KvRow("模块", tag)
            KvRow("长度", "${msg.length} 字符")

            // TCP 结构化
            if (line.contains("[TCP]") || line.contains("[Net") || line.contains("[SSL") ||
                line.contains("[OkHttp") || line.contains("[Cronet") || line.contains("[HUC")) {
                val arrow = Regex("""([<>]{2,3})\s*(\S+?)\s*->\s*(\S+?)(?:\s+\[|$)""").find(msg)
                if (arrow != null) {
                    val dir = arrow.groupValues[1]
                    KvRow("方向", when {
                        dir.startsWith(">>>") -> "上行（发送）"
                        dir.startsWith("<<<") -> "下行（接收）"
                        else -> dir
                    })
                    KvRow("源地址", arrow.groupValues[2])
                    KvRow("目标地址", arrow.groupValues[3])
                }
                val size = Regex("""\[(\d+)B hex\]""").find(msg)
                if (size != null) KvRow("数据量", "${size.groupValues[1]}B")
            }

            // KL 结构化
            if (line.contains("KL dart:io")) {
                val m = Regex("""KL dart:io (\w+)(?: #(\d+))?\s+invoked""").find(line)
                if (m != null) {
                    KvRow("函数", "dart:io ${m.groupValues[1]}")
                    m.groupValues[2].takeIf { it.isNotEmpty() }?.let { KvRow("累计调用", "第 $it 次") }
                    KvRow("语义", klSemantic(m.groupValues[1]))
                }
            }

            if (line.contains("[REQ#")) KvRow("建议", "该行关联 HTTP 请求，点日志列表卡片可看完整请求/响应分析")
            if (line.contains("[EVT#")) KvRow("建议", "该行关联结构化事件，点日志列表卡片可看完整事件详情")
        }

        // JSON 检测
        val json = formatJson(line)
        if (json != null) {
            SectionCard(title = "JSON 内容") {
                Text(json, style = codeStyle, softWrap = true, fontSize = 11.sp)
            }
        }

        // 原始正文
        SectionCard(title = "原始内容") {
            Text(line, style = codeStyle, softWrap = true, fontSize = 11.sp,
                color = MaterialTheme.colorScheme.onSurface)
        }
    }
}

/** KL 函数语义（与 flutter_keylog.cpp hook 点对应） */
private fun klSemantic(fn: String): String {
    return when (fn) {
        "Filter_Process" -> "TLS 加密前明文处理（SecureFilter.process，抓明文的关键点）"
        "Filter_Processed" -> "TLS 解密后明文处理（SecureFilter.processed，响应明文）"
        "SecureSocket_Init" -> "SSL_CTX 创建（新建安全连接上下文）"
        "SecureSocket_Connect" -> "TLS 握手（发起安全连接）"
        else -> "dart:io 加密通道调用"
    }
}

// ================= 原始 / JSON / Hex =================
@Composable
private fun RawScroll(text: String, mono: Boolean = false) {
    Box(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(12.dp)
    ) {
        Text(text, style = codeStyle, softWrap = true)
    }
}

@Composable
private fun JsonView(line: String) {
    val json = formatJson(line)
    Box(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(12.dp)
    ) {
        if (json != null) {
            Text(json, style = codeStyle, softWrap = true)
        } else {
            Text("（该行不是 JSON 内容）", style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

/** 分享日志行到系统分享 */
private fun shareLine(context: android.content.Context, line: String) {
    try {
        val it = android.content.Intent(android.content.Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(android.content.Intent.EXTRA_TEXT, line)
        }
        context.startActivity(android.content.Intent.createChooser(it, "分享日志"))
    } catch (t: Throwable) {
        copyText(context, line)
    }
}