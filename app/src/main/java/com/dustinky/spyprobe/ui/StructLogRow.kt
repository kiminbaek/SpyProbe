package com.dustinky.spyprobe.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material3.Icon
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
import com.dustinky.spyprobe.ui.theme.codeStyle

/**
 * v2.1.0 P0: 纯文本日志行结构化解渲染（实时列表兜底 Text → 拆行显示）。
 *
 * 旧实现：未命中 REQ#/EVT# 卡片的行直接 Text(line) 一整行塞进去——
 * 「05:55:50.373 [SpyProbe.Native] [TCP] >>> ::ffff:...->... [64B hex] 1403 0300 ...」
 * 一长串 hex 糊脸，看不出结构。本组件对齐历史层 HistoryLineRow 风格：
 *   [时间戳] [徽标Tag] [正文…]
 * 并额外处理 TCP hex 行（[N B hex] 段）：默认折叠为摘要行（方向+大小），
 * 点三角展开显示 hex dump（复用 LogsScreen.hexDump）。
 */
@Composable
internal fun StructLogRow(line: String, onClick: () -> Unit) {
    val time = line.takeWhile { it != ' ' && it != '[' }
    val rest = line.removePrefix(time).trimStart()
    val tagEnd = rest.indexOf(']')
    val tag = if (tagEnd > 0 && rest.startsWith("[")) rest.substring(1, tagEnd) else ""
    val msg0 = if (tagEnd > 0) rest.substring(tagEnd + 1).trim() else rest
    val tagColor = logColor("[$tag]")

    // TCP hex 段：[(N)B hex] 后跟 hex 字节 → 可折叠
    val hexMatch = Regex("""\[(\d+)B hex\]\s+([0-9a-fA-F ]+)""").find(msg0)
    if (hexMatch != null) {
        var expanded by remember(line) { mutableStateOf(false) }
        val hexHead = msg0.substring(0, msg0.indexOf('[')).trim() // 「>>> ip:port->ip:port」段
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .clickable(onClick = onClick)
                .padding(horizontal = 4.dp, vertical = 3.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(time, style = codeStyle, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.width(88.dp))
                Text(if (tag.isEmpty()) "?" else tag, style = codeStyle, color = tagColor,
                    fontWeight = FontWeight.Bold, maxLines = 1,
                    overflow = TextOverflow.Ellipsis, modifier = Modifier.width(72.dp))
                Text(hexHead, style = codeStyle,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
                Spacer(Modifier.width(6.dp))
                Text("[${hexMatch.groupValues[1]}B hex]",
                    style = codeStyle, color = Color(0xFF42A5F5), fontSize = 9.sp,
                    maxLines = 1, overflow = TextOverflow.Ellipsis)
                Icon(
                    if (expanded) Icons.Filled.KeyboardArrowUp else Icons.Filled.KeyboardArrowDown,
                    contentDescription = if (expanded) "收起" else "展开",
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.width(18.dp)
                )
            }
            if (expanded) {
                Text(
                    hexDump(line),
                    style = codeStyle,
                    color = Color(0xFF00E5FF),
                    fontSize = 10.sp,
                    softWrap = false,
                    modifier = Modifier.padding(start = 88.dp + 72.dp + 8.dp, top = 2.dp)
                )
            }
        }
        return
    }

    // 普通行：时间戳 + 徽标 + 正文（失败行红色）
    val fail = msg0.contains("FAIL") || msg0.contains("ERROR") || msg0.contains("[ERR]")
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 4.dp, vertical = 3.dp)
    ) {
        Text(time, style = codeStyle, color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.width(88.dp))
        Text(if (tag.isEmpty()) "?" else tag, style = codeStyle, color = tagColor,
            fontWeight = FontWeight.Bold, maxLines = 1,
            overflow = TextOverflow.Ellipsis, modifier = Modifier.width(72.dp))
        Text(msg0, style = codeStyle,
            color = if (fail) Color(0xFFFF5252) else MaterialTheme.colorScheme.onSurface,
            softWrap = true, maxLines = 3,
            overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
    }
}