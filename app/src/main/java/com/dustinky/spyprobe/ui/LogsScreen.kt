package com.dustinky.spyprobe.ui

import androidx.compose.foundation.background
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
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
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

// v1.27: 日志页重构 —— 实时/历史双模式 + 分类筛选 + 历史落盘查看/清空（日志持久化核心）
// v1.24: 日志页视觉优化 —— 统计行卡化 + 浮动按钮 + 终端风格
// v1.18: 独立日志页 —— 统计行 + 过滤 + 暂停/清空/导出 + 着色 + 自动滚动

/** v1.27: 日志分类（按行文本 tag 归类，实时/历史共用） */
enum class LogCategory(val label: String) {
    ALL("全部"), NET("网络"), MTH("方法"), RULE("Hook"), CRYPTO("加密"), CLS("类加载"), SYS("系统")
}

// v1.28 P2: 正则编译放到顶层常量（此前 categoryOfLine/统计每行都 new Regex，高频路径浪费）
private val NET_REGEX = Regex(NET_FILTER)

internal fun categoryOfLine(line: String): LogCategory = when {
    NET_REGEX.containsMatchIn(line) -> LogCategory.NET
    line.contains("[Mth") -> LogCategory.MTH
    line.contains("[RULE") -> LogCategory.RULE
    line.contains("[Crypto") || line.contains("[CRYPTO") ||
            line.contains("[ENC") || line.contains("[DEC") -> LogCategory.CRYPTO
    line.contains("[Cls") || line.contains("[Class") -> LogCategory.CLS
    else -> LogCategory.SYS
}

@Composable
fun LogsScreen(vm: SpyViewModel, modifier: Modifier = Modifier) {
    val logLines by vm.logLines.collectAsState()
    val logCount by vm.logCount.collectAsState()
    val historyDays by vm.historyDays.collectAsState()
    val historyLogs by vm.historyLogs.collectAsState()
    val historyLoading by vm.historyLoading.collectAsState()
    val context = LocalContext.current
    val listState = rememberLazyListState()
    val scope = rememberCoroutineScope()

    var modeHistory by remember { mutableStateOf(false) }
    var filter by remember { mutableStateOf("") }
    var category by remember { mutableStateOf(LogCategory.ALL) }
    var autoScroll by remember { mutableStateOf(true) }
    var selectedDay by remember { mutableStateOf<String?>(null) }
    var showClearDialog by remember { mutableStateOf(false) }
    // v1.25 P1-3: 暂停状态从局部 remember 改为 vm（此前暂停只停自动滚动不停轮询——日志还在积累；
    //   vm.paused 同时控制轮询停止 + 自动滚动暂停，语义一致）
    val paused by vm.paused.collectAsState()

    val displayLines = if (modeHistory) historyLogs else logLines

    // v1.27: 进入历史模式拉日期列表
    LaunchedEffect(modeHistory) {
        if (modeHistory) vm.loadHistoryDays()
    }
    // v1.27: 选中日期变化拉历史（默认选最新一天）
    LaunchedEffect(modeHistory, historyDays) {
        if (modeHistory && selectedDay == null && historyDays.isNotEmpty()) {
            selectedDay = historyDays.first()
        }
    }
    LaunchedEffect(selectedDay) {
        if (modeHistory && selectedDay != null) vm.loadHistory(selectedDay!!)
    }

    // 过滤（v1.27: 分类筛选 + 关键词）
    val filtered by remember(displayLines, category, filter) {
        derivedStateOf {
            var list = displayLines
            if (category != LogCategory.ALL) list = list.filter { (_, l) -> categoryOfLine(l) == category }
            if (filter.isNotEmpty()) list = list.filter { (_, l) -> matchesFilter(l, filter) }
            list
        }
    }

    // 自动滚到底（仅实时模式；历史是静态数据由用户滚动）
    LaunchedEffect(filtered.size, autoScroll, paused, modeHistory) {
        if (autoScroll && !paused && !modeHistory && filtered.isNotEmpty()) {
            try { listState.animateScrollToItem(filtered.size - 1) } catch (_: Throwable) { }
        }
    }

    // 统计（v1.28 P2: 仅实时模式计算——历史模式展示"历史条数"且可能上万行，全量扫描浪费）
    val netCount = if (modeHistory) 0 else displayLines.count { (_, l) -> NET_REGEX.find(l) != null }
    val mthCount = if (modeHistory) 0 else displayLines.count { (_, l) -> l.contains("[Mth") }
    val errCount = if (modeHistory) 0 else displayLines.count { (_, l) -> l.contains("FAIL") || l.contains("ERROR") || l.contains("[ERR]") }

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
                    // v1.27: 实时 / 历史 模式切换
                    FilterChip(
                        selected = !modeHistory,
                        onClick = { modeHistory = false; selectedDay = null },
                        label = { Text("实时", fontSize = 11.sp) }
                    )
                    Spacer(Modifier.width(6.dp))
                    FilterChip(
                        selected = modeHistory,
                        onClick = { modeHistory = true },
                        label = { Text("历史", fontSize = 11.sp) }
                    )
                    Spacer(Modifier.width(8.dp))
                    if (!modeHistory) {
                        StatChip("总计", logCount, MaterialTheme.colorScheme.primary)
                        Spacer(Modifier.width(8.dp))
                        StatChip("网络", netCount, Color(0xFF00E5FF))
                        Spacer(Modifier.width(8.dp))
                        StatChip("方法", mthCount, Color(0xFF42A5F5))
                        Spacer(Modifier.width(8.dp))
                        StatChip("错误", errCount, MaterialTheme.colorScheme.error)
                    } else {
                        StatChip("历史条数", historyLogs.size, MaterialTheme.colorScheme.primary)
                        Spacer(Modifier.width(8.dp))
                        Text(
                            "落盘日志·进程重启不丢",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            fontSize = 10.sp
                        )
                    }
                }

                // v1.27: 历史模式 —— 日期选择行
                if (modeHistory) {
                    Spacer(Modifier.height(8.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        LazyRow(
                            modifier = Modifier.weight(1f),
                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            items(historyDays) { day ->
                                FilterChip(
                                    selected = day == selectedDay,
                                    onClick = { selectedDay = day },
                                    label = { Text(day, fontSize = 11.sp) }
                                )
                            }
                        }
                        IconButton(onClick = { vm.loadHistoryDays() }, modifier = Modifier.size(30.dp)) {
                            Icon(Icons.Filled.Refresh, contentDescription = "刷新日期",
                                modifier = Modifier.size(16.dp))
                        }
                        IconButton(onClick = { showClearDialog = true }, modifier = Modifier.size(30.dp)) {
                            Icon(Icons.Filled.Delete, contentDescription = "清空历史",
                                tint = MaterialTheme.colorScheme.error,
                                modifier = Modifier.size(16.dp))
                        }
                    }
                    if (historyLoading) {
                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                    }
                }

                Spacer(Modifier.height(8.dp))

                // v1.27: 分类筛选（全部/网络/方法/Hook/加密/类加载/系统）
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    LogCategory.values().forEach { cat ->
                        FilterChip(
                            selected = category == cat,
                            onClick = { category = cat },
                            label = { Text(cat.label, fontSize = 11.sp) }
                        )
                    }
                }

                // v1.25 P1-3: 暂停/自动滚动（仅实时模式；历史静态数据无此语义）
                if (!modeHistory) {
                    Spacer(Modifier.height(6.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
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
            if (filtered.isEmpty()) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text(
                        if (modeHistory) {
                            if (historyDays.isEmpty()) "暂无历史日志（抓包时日志会自动落盘保存）"
                            else "该日期/分类下暂无日志"
                        } else "暂无日志（开始抓包后这里实时滚动）",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            } else {
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
            }

            // ===== 浮动操作按钮（v1.24：跳到顶/底 + 导出）=====
            Column(
                modifier = Modifier
                    .align(Alignment.BottomEnd)
                    .padding(end = 12.dp, bottom = 12.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
                horizontalAlignment = Alignment.End
            ) {
                // 导出（实时=内存日志；历史=选中日期落盘日志）
                FloatingActionButton(
                    onClick = {
                        scope.launch {
                            val text = if (modeHistory) {
                                if (selectedDay == null) { android.widget.Toast.makeText(context, "请先选择日期", android.widget.Toast.LENGTH_SHORT).show(); return@launch }
                                vm.api.exportDay(selectedDay!!)
                            } else {
                                vm.api.export()
                            }
                            if (text == null || text.isEmpty()) {
                                // v1.30.1: 失败原因显示出来（HTTP 错误 / JSON 解析失败 / 空内容）
                                val why = if (text == null) vm.api.lastHttpError.ifEmpty { "HTTP 无响应" } else "日志内容为空"
                                com.dustinky.spyprobe.util.UiLog.log("LogsScreen 导出失败: $why")
                                android.widget.Toast.makeText(context, "导出失败：$why", android.widget.Toast.LENGTH_LONG).show()
                                return@launch
                            }
                            // v1.30: 写 txt 文件分享（不再截断 10 万字符，长日志完整导出）
                            val err = com.dustinky.spyprobe.util.ShareLogUtil.shareTxtFile(
                                context,
                                "SpyProbe 日志导出",
                                if (modeHistory) "spyprobe_logs_${selectedDay}" else "spyprobe_logs",
                                text
                            )
                            if (err != null) {
                                com.dustinky.spyprobe.util.UiLog.log("LogsScreen 写文件/分享失败: $err")
                                android.widget.Toast.makeText(context, "导出失败：$err", android.widget.Toast.LENGTH_LONG).show()
                            }
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

    // ===== v1.27: 清空历史确认弹窗（清当天 / 清全部 / 取消）=====
    if (showClearDialog) {
        AlertDialog(
            onDismissRequest = { showClearDialog = false },
            title = { Text("清空历史日志") },
            text = { Text("已落盘的历史日志删除后不可恢复。\n\n选中的日期：${selectedDay ?: "无"}") },
            confirmButton = {
                // v1.28 P1: 未选中日期时禁用"清空当天"——否则误点会把全部历史删光
                TextButton(
                    onClick = {
                        showClearDialog = false
                        vm.clearHistory(selectedDay) { ok ->
                            android.widget.Toast.makeText(context,
                                if (ok) "已清空 ${selectedDay}" else "清空失败", android.widget.Toast.LENGTH_SHORT).show()
                        }
                    },
                    enabled = selectedDay != null
                ) { Text("清空当天") }
            },
            dismissButton = {
                Row {
                    TextButton(onClick = {
                        showClearDialog = false
                        vm.clearHistory(null) { ok ->
                            android.widget.Toast.makeText(context,
                                if (ok) "已清空全部历史" else "清空失败", android.widget.Toast.LENGTH_SHORT).show()
                        }
                    }) { Text("清空全部", color = MaterialTheme.colorScheme.error) }
                    TextButton(onClick = { showClearDialog = false }) { Text("取消") }
                }
            }
        )
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
