package com.dustinky.spyprobe.ui

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.dustinky.spyprobe.ui.theme.codeStyle
import kotlinx.coroutines.launch

// v1.24: 日志页视觉优化 —— 统计行卡化 + 浮动按钮 + 终端风格
// v1.18: 独立日志页 —— 统计行 + 过滤 + 暂停/清空/导出 + 着色 + 自动滚动

@Composable
fun LogsScreen(vm: SpyViewModel, modifier: Modifier = Modifier) {
    val logLines by vm.logLines.collectAsState()
    val logCount by vm.logCount.collectAsState()
    val context = LocalContext.current
    val listState = rememberLazyListState()
    val scope = rememberCoroutineScope()

    var filter by remember { mutableStateOf("") }
    var onlyNet by remember { mutableStateOf(false) }
    var onlyMth by remember { mutableStateOf(false) }
    var autoScroll by remember { mutableStateOf(true) }
    // v1.25 P1-3: 暂停状态从局部 remember 改为 vm（此前暂停只停自动滚动不停轮询——日志还在积累；
    //   vm.paused 同时控制轮询停止 + 自动滚动暂停，语义一致）
    val paused by vm.paused.collectAsState()

    // 过滤
    val filtered by remember {
        derivedStateOf {
            var list = logLines
            if (onlyNet) list = list.filter { (_, l) -> Regex(NET_FILTER).find(l) != null }
            if (onlyMth) list = list.filter { (_, l) -> l.contains("[Mth") }
            if (filter.isNotEmpty()) list = list.filter { (_, l) -> matchesFilter(l, filter) }
            list
        }
    }

    // 自动滚到底
    LaunchedEffect(filtered.size, autoScroll, paused) {
        if (autoScroll && !paused && filtered.isNotEmpty()) {
            try { listState.animateScrollToItem(filtered.size - 1) } catch (_: Throwable) { }
        }
    }

    // 统计
    val netCount = logLines.count { (_, l) -> Regex(NET_FILTER).find(l) != null }
    val mthCount = logLines.count { (_, l) -> l.contains("[Mth") }
    val errCount = logLines.count { (_, l) -> l.contains("FAIL") || l.contains("ERROR") || l.contains("[ERR]") }

    Column(modifier = modifier.fillMaxSize()) {

        // ===== 统计卡（顶部工具栏角色，0dp 圆角与顶栏衔接）=====
        Card(
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceContainer
            ),
            shape = RoundedCornerShape(0.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(Modifier.padding(horizontal = 16.dp, vertical = 10.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    StatChip("总计", logCount, MaterialTheme.colorScheme.primary)
                    Spacer(Modifier.width(8.dp))
                    StatChip("网络", netCount, Color(0xFF00E5FF))
                    Spacer(Modifier.width(8.dp))
                    StatChip("方法", mthCount, Color(0xFF42A5F5))
                    Spacer(Modifier.width(8.dp))
                    StatChip("错误", errCount, MaterialTheme.colorScheme.error)
                }

                Spacer(Modifier.height(8.dp))

                // 过滤快捷 chip
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    FilterChip(
                        selected = onlyNet,
                        onClick = { onlyNet = !onlyNet },
                        label = { Text("仅网络", fontSize = 11.sp) }
                    )
                    FilterChip(
                        selected = onlyMth,
                        onClick = { onlyMth = !onlyMth },
                        label = { Text("仅方法", fontSize = 11.sp) }
                    )
                    FilterChip(
                        selected = paused,
                        onClick = { vm.togglePaused() },
                        label = { Text(if (paused) "▶ 继续" else "⏸ 暂停", fontSize = 11.sp) }
                    )
                    FilterChip(
                        selected = autoScroll,
                        onClick = { autoScroll = !autoScroll },
                        label = { Text("自动滚动", fontSize = 11.sp) }
                    )
                }

                Spacer(Modifier.height(6.dp))
                OutlinedTextField(
                    value = filter,
                    onValueChange = { filter = it },
                    placeholder = { Text("过滤关键字 / 正则", fontSize = 12.sp) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        }

        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)

        // ===== 日志列表（终端风格）=====
        Box(Modifier.fillMaxSize()) {
            LazyColumn(
                state = listState,
                modifier = Modifier
                    .fillMaxSize()
                    .background(MaterialTheme.colorScheme.surfaceContainerLowest)
                    .padding(horizontal = 8.dp, vertical = 4.dp)
            ) {
                items(filtered, key = { it.first }) { (idx, line) ->
                    Text(
                        line,
                        style = codeStyle,
                        color = logColor(line),
                        softWrap = true,
                        modifier = Modifier.padding(vertical = 1.dp)
                    )
                }
            }

            // ===== 浮动操作按钮（v1.24：跳到顶/底 + 导出）=====
            Column(
                modifier = Modifier
                    .align(Alignment.BottomEnd)
                    .padding(end = 12.dp, bottom = 12.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
                horizontalAlignment = Alignment.End
            ) {
                // 导出
                FloatingActionButton(
                    onClick = {
                        scope.launch {
                            val text = vm.api.export()
                            if (text == null || text.isEmpty()) {
                                android.widget.Toast.makeText(context, "导出失败", android.widget.Toast.LENGTH_SHORT).show()
                                return@launch
                            }
                            val share = Intent(Intent.ACTION_SEND).apply {
                                type = "text/plain"
                                putExtra(Intent.EXTRA_TEXT, text.substring(0, minOf(text.length, 100000)))
                            }
                            context.startActivity(Intent.createChooser(share, "导出日志").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                        }
                    },
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                    contentColor = MaterialTheme.colorScheme.primary,
                    shape = RoundedCornerShape(14.dp),
                    modifier = Modifier.size(44.dp)
                ) {
                    Icon(Icons.Filled.Share, contentDescription = "导出",
                        modifier = Modifier.size(20.dp))
                }
                // 跳到顶部
                FloatingActionButton(
                    onClick = {
                        scope.launch {
                            try { listState.animateScrollToItem(0) } catch (_: Throwable) { }
                        }
                    },
                    containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
                    contentColor = MaterialTheme.colorScheme.onSurface,
                    shape = RoundedCornerShape(14.dp),
                    modifier = Modifier.size(44.dp)
                ) {
                    Icon(Icons.Filled.KeyboardArrowUp, contentDescription = "顶部",
                        modifier = Modifier.size(22.dp))
                }
                // 跳到底部
                FloatingActionButton(
                    onClick = {
                        scope.launch {
                            try { listState.animateScrollToItem(filtered.size - 1) } catch (_: Throwable) { }
                        }
                    },
                    containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
                    contentColor = MaterialTheme.colorScheme.onSurface,
                    shape = RoundedCornerShape(14.dp),
                    modifier = Modifier.size(44.dp)
                ) {
                    Icon(Icons.Filled.KeyboardArrowDown, contentDescription = "底部",
                        modifier = Modifier.size(22.dp))
                }
            }
        }
    }
}

// ===== 统计徽章 =====
@Composable
private fun StatChip(label: String, count: Int, color: Color) {
    Box(
        modifier = Modifier
            .background(color.copy(alpha = 0.12f), RoundedCornerShape(8.dp))
            .padding(horizontal = 10.dp, vertical = 5.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                "$count",
                style = MaterialTheme.typography.labelMedium,
                color = color,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace
            )
            Spacer(Modifier.width(4.dp))
            Text(
                label,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontSize = 10.sp
            )
        }
    }
}
