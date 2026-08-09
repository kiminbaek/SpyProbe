package com.dustinky.spyprobe.ui

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
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Star
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
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.path
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.dustinky.spyprobe.ui.theme.codeStyle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

// v1.31: 历史日志三层导航重做（小黄鸟式）——
//   ① 历史卡片列表（日期+条数+时间范围+收藏/清空）→ ② 当天日志列表（时间+tag+摘要）→ ③ 单条详情（完整内容+复制+分享+高亮）
//   Root 模式直读目标沙箱文件（目标 App 可不在线）；普通模式 HTTP。
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

/** v1.31: 历史导航层级 */
private enum class HistoryLevel { DAYS, LINES, DETAIL }

/** v1.31.1 P3-12: 自定义 StarBorder 图标（material-icons-core 无此图标，extended 已移除） */
private val StarBorderIcon: ImageVector by lazy {
    ImageVector.Builder(
        name = "StarBorder",
        defaultWidth = 24.dp,
        defaultHeight = 24.dp,
        viewportWidth = 24f,
        viewportHeight = 24f
    ).apply {
        path(fill = SolidColor(Color.Black)) {
            moveTo(22f, 9.24f)
            lineToRelative(-7.19f, -0.62f)
            lineTo(12f, 2f)
            lineTo(9.19f, 8.63f)
            lineTo(2f, 9.24f)
            lineToRelative(5.46f, 4.73f)
            lineTo(5.82f, 21f)
            lineTo(12f, 17.27f)
            lineTo(18.18f, 21f)
            lineToRelative(-1.63f, -7.03f)
            lineTo(22f, 9.24f)
            close()
            moveTo(12f, 15.4f)
            lineToRelative(-3.76f, 2.27f)
            lineToRelative(1f, -4.28f)
            lineToRelative(-3.32f, -2.88f)
            lineToRelative(4.38f, -0.38f)
            lineTo(12f, 6.1f)
            lineToRelative(1.71f, 4.04f)
            lineToRelative(4.38f, 0.38f)
            lineToRelative(-3.32f, 2.88f)
            lineToRelative(1f, 4.28f)
            lineTo(12f, 15.4f)
            close()
        }
    }.build()
}

/**
 * v1.31.1 P3-12: 自定义 ContentCopy 图标（去掉 material-icons-extended 依赖，APK -5MB）。
 * 标准 Material Icons content_copy 路径（24dp viewport），与原 extended 图标完全一致。
 */
private val CopyIcon: ImageVector by lazy {
    ImageVector.Builder(
        name = "ContentCopy",
        defaultWidth = 24.dp,
        defaultHeight = 24.dp,
        viewportWidth = 24f,
        viewportHeight = 24f
    ).apply {
        path(fill = SolidColor(Color.Black)) {
            moveTo(19f, 3f)
            horizontalLineTo(5f)
            curveTo(3.9f, 3f, 3f, 3.9f, 3f, 5f)
            verticalLineToRelative(14f)
            curveTo(3f, 20.1f, 3.9f, 21f, 5f, 21f)
            horizontalLineToRelative(14f)
            curveTo(20.1f, 21f, 21f, 20.1f, 21f, 19f)
            verticalLineTo(5f)
            curveTo(21f, 3.9f, 20.1f, 3f, 19f, 3f)
            close()
            moveTo(19f, 19f)
            horizontalLineTo(5f)
            verticalLineTo(5f)
            horizontalLineToRelative(14f)
            verticalLineTo(19f)
            close()
            moveTo(17f, 7f)
            horizontalLineTo(9f)
            verticalLineToRelative(2f)
            horizontalLineToRelative(8f)
            verticalLineTo(7f)
            close()
            moveTo(17f, 11f)
            horizontalLineTo(9f)
            verticalLineToRelative(2f)
            horizontalLineToRelative(8f)
            verticalLineTo(11f)
            close()
            moveTo(9f, 15f)
            horizontalLineToRelative(5f)
            verticalLineToRelative(-2f)
            horizontalLineTo(9f)
            verticalLineTo(15f)
            close()
        }
    }.build()
}

@Composable
fun LogsScreen(vm: SpyViewModel, modifier: Modifier = Modifier) {
    val logLines by vm.logLines.collectAsState()
    val logCount by vm.logCount.collectAsState()
    val historyDays by vm.historyDays.collectAsState()
    val historyLogs by vm.historyLogs.collectAsState()
    val historyLoading by vm.historyLoading.collectAsState()
    val historySource by vm.historySource.collectAsState()
    val context = LocalContext.current
    val listState = rememberLazyListState()
    val scope = rememberCoroutineScope()

    var modeHistory by remember { mutableStateOf(false) }
    var filter by remember { mutableStateOf("") }
    var category by remember { mutableStateOf(LogCategory.ALL) }
    var autoScroll by remember { mutableStateOf(true) }
    var selectedDay by remember { mutableStateOf<String?>(null) }
    var showClearDialog by remember { mutableStateOf(false) }
    // v1.31: 历史三层导航
    var historyLevel by remember { mutableStateOf(HistoryLevel.DAYS) }
    var detailEntry by remember { mutableStateOf<Pair<Long, String>?>(null) }
    // v1.25 P1-3: 暂停状态从局部 remember 改为 vm（此前暂停只停自动滚动不停轮询——日志还在积累；
    //   vm.paused 同时控制轮询停止 + 自动滚动暂停，语义一致）
    val paused by vm.paused.collectAsState()

    val displayLines = if (modeHistory && historyLevel != HistoryLevel.DAYS) historyLogs else logLines

    // v1.27: 进入历史模式拉日期列表
    LaunchedEffect(modeHistory) {
        if (modeHistory) {
            historyLevel = HistoryLevel.DAYS
            selectedDay = null
            vm.loadHistoryDays()
        }
    }
    // v1.31: 进入某天 → 拉该天日志
    LaunchedEffect(selectedDay, historyLevel) {
        if (modeHistory && historyLevel == HistoryLevel.LINES && selectedDay != null) {
            vm.loadHistory(selectedDay!!)
        }
    }

    // 过滤（v1.27: 分类筛选 + 关键词；v1.31: 仅列表层过滤，详情层不适用）
    val filtered by remember(displayLines, category, filter, modeHistory, historyLevel) {
        derivedStateOf {
            var list = displayLines
            if (category != LogCategory.ALL) list = list.filter { (_, l) -> categoryOfLine(l) == category }
            if (filter.isNotEmpty()) list = list.filter { (_, l) -> matchesFilter(l, filter) }
            list
        }
    }

    // 自动滚到底（仅实时模式；历史是静态数据由用户滚动）
    LaunchedEffect(filtered.size, autoScroll, paused, modeHistory, historyLevel) {
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
                    // v1.31: 历史详情层级有返回键（v1.31.1 P2-1: 按层级降级——DETAIL→LINES→DAYS，而非直接跳回卡片）
                    if (modeHistory && historyLevel != HistoryLevel.DAYS) {
                        IconButton(onClick = {
                            if (historyLevel == HistoryLevel.DETAIL) {
                                historyLevel = HistoryLevel.LINES
                            } else {
                                historyLevel = HistoryLevel.DAYS
                                selectedDay = null
                            }
                        }, modifier = Modifier.size(30.dp)) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回",
                                modifier = Modifier.size(18.dp))
                        }
                        Spacer(Modifier.width(4.dp))
                    }
                    // v1.27: 实时 / 历史 模式切换
                    FilterChip(
                        selected = !modeHistory,
                        onClick = { modeHistory = false; selectedDay = null; historyLevel = HistoryLevel.DAYS },
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
                        // v1.31: 层级指示：卡片列表 → 某天 → 详情
                        when (historyLevel) {
                            HistoryLevel.DAYS -> {
                                StatChip("历史天数", historyDays.size, MaterialTheme.colorScheme.primary)
                                Spacer(Modifier.width(8.dp))
                                Text(
                                    historySource,
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    fontSize = 9.sp,
                                    maxLines = 2
                                )
                            }
                            HistoryLevel.LINES -> {
                                StatChip("记录", historyLogs.size, MaterialTheme.colorScheme.primary)
                                Spacer(Modifier.width(8.dp))
                                Text(
                                    "落盘日志·进程重启不丢",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    fontSize = 10.sp
                                )
                            }
                            HistoryLevel.DETAIL -> {
                                Text(
                                    "日志详情",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    fontSize = 11.sp
                                )
                            }
                        }
                    }
                }

                // v1.31: 卡片列表层 —— 刷新/清空全部按钮；列表层 —— 刷新/清空当天按钮（v1.31.1 P2-3 新增单天清空入口）
                if (modeHistory && historyLevel == HistoryLevel.DAYS) {
                    Spacer(Modifier.height(8.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        IconButton(onClick = { vm.loadHistoryDays() }, modifier = Modifier.size(30.dp)) {
                            Icon(Icons.Filled.Refresh, contentDescription = "刷新日期",
                                modifier = Modifier.size(16.dp))
                        }
                        IconButton(onClick = { showClearDialog = true }, modifier = Modifier.size(30.dp)) {
                            Icon(Icons.Filled.Delete, contentDescription = "清空历史",
                                tint = MaterialTheme.colorScheme.error,
                                modifier = Modifier.size(16.dp))
                        }
                        Spacer(Modifier.width(6.dp))
                        Text(
                            if (historyDays.isEmpty()) "暂无历史日志（抓包时日志会自动落盘保存）" else "点击日期卡片查看当天日志",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            fontSize = 10.sp
                        )
                    }
                    if (historyLoading) {
                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                    }
                }
                if (modeHistory && historyLevel == HistoryLevel.LINES) {
                    Spacer(Modifier.height(8.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        IconButton(onClick = { selectedDay?.let { vm.loadHistory(it) } }, modifier = Modifier.size(30.dp)) {
                            Icon(Icons.Filled.Refresh, contentDescription = "刷新当天",
                                modifier = Modifier.size(16.dp))
                        }
                        IconButton(onClick = { showClearDialog = true }, modifier = Modifier.size(30.dp)) {
                            Icon(Icons.Filled.Delete, contentDescription = "清空当天",
                                tint = MaterialTheme.colorScheme.error,
                                modifier = Modifier.size(16.dp))
                        }
                        Spacer(Modifier.width(6.dp))
                        Text(
                            "点击日志行查看详情",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            fontSize = 10.sp
                        )
                    }
                    if (historyLoading) {
                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                    }
                }

                Spacer(Modifier.height(8.dp))

                // v1.31: 列表层/实时层显示分类筛选；详情层不显示
                if (!(modeHistory && historyLevel == HistoryLevel.DETAIL)) {
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        LogCategory.values().forEach { cat ->
                            FilterChip(
                                selected = category == cat,
                                onClick = { category = cat },
                                label = { Text(cat.label, fontSize = 11.sp) }
                            )
                        }
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

                // v1.31: 搜索框 —— 实时/历史列表层显示
                if (!(modeHistory && historyLevel == HistoryLevel.DETAIL)) {
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
        }

        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)

        // ===== 内容区（v1.31 三层）=====
        Box(Modifier.fillMaxSize()) {
            when {
                // ---- 历史层 ①：日期卡片列表（小黄鸟式）----
                modeHistory && historyLevel == HistoryLevel.DAYS -> {
                    if (historyDays.isEmpty()) {
                        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                            Text(
                                if (historyLoading) "加载中…"
                                else "暂无历史日志（抓包时日志会自动落盘保存）",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    } else {
                        LazyColumn(
                            modifier = Modifier
                                .fillMaxSize()
                                .background(MaterialTheme.colorScheme.surfaceContainerLowest)
                                .padding(horizontal = 10.dp, vertical = 8.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            items(historyDays, key = { it }) { day ->
                                HistoryDayCard(
                                    day = day,
                                    favorite = vm.isFavoriteDay(day),
                                    onToggleFavorite = { vm.toggleFavoriteDay(day) },
                                    onClick = {
                                        selectedDay = day
                                        historyLevel = HistoryLevel.LINES
                                    }
                                )
                            }
                        }
                    }
                }

                // ---- 历史层 ②：某天日志列表 ----
                modeHistory && historyLevel == HistoryLevel.LINES -> {
                    if (filtered.isEmpty()) {
                        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                            Text(
                                if (historyLoading) "加载中…"
                                else if (selectedDay == null) "未选择日期"
                                else "该日期/分类下暂无日志",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    } else {
                        LazyColumn(
                            modifier = Modifier
                                .fillMaxSize()
                                .background(MaterialTheme.colorScheme.surfaceContainerLowest)
                                .padding(horizontal = 8.dp, vertical = 4.dp)
                        ) {
                            items(filtered, key = { it.first }) { (idx, line) ->
                                HistoryLineRow(
                                    idx = idx,
                                    line = line,
                                    onClick = {
                                        detailEntry = idx to line
                                        historyLevel = HistoryLevel.DETAIL
                                    }
                                )
                            }
                        }
                    }
                }

                // ---- 历史层 ③：单条详情 ----
                modeHistory && historyLevel == HistoryLevel.DETAIL -> {
                    val entry = detailEntry
                    if (entry == null) {
                        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                            Text("无详情", style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    } else {
                        HistoryDetailView(entry = entry)
                    }
                }

                // ---- 实时模式：原日志列表 ----
                else -> {
                    if (filtered.isEmpty()) {
                        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                            Text(
                                "暂无日志（开始抓包后这里实时滚动）",
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
                }
            }

            // ===== 浮动操作按钮 =====
            Column(
                modifier = Modifier
                    .align(Alignment.BottomEnd)
                    .padding(end = 12.dp, bottom = 12.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
                horizontalAlignment = Alignment.End
            ) {
                // 导出（实时=内存日志；历史卡片层=导出某天/全部；历史详情层=分享单条）
                if (modeHistory && historyLevel == HistoryLevel.DETAIL) {
                    // 详情层：复制 + 分享单条
                    FloatingActionButton(
                        onClick = {
                            detailEntry?.let { (_, line) ->
                                val ctx = context
                                scope.launch {
                                    val clip = withContext(Dispatchers.IO) {
                                        val cm = ctx.getSystemService(android.content.Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
                                        cm.setPrimaryClip(android.content.ClipData.newPlainText("SpyProbe 日志", line))
                                        "已复制"
                                    }
                                    android.widget.Toast.makeText(ctx, clip, android.widget.Toast.LENGTH_SHORT).show()
                                }
                            }
                        },
                        containerColor = MaterialTheme.colorScheme.primaryContainer,
                        contentColor = MaterialTheme.colorScheme.primary,
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier.size(44.dp)
                    ) {
                        Icon(CopyIcon, contentDescription = "复制",
                            modifier = Modifier.size(20.dp))
                    }
                    FloatingActionButton(
                        onClick = {
                            detailEntry?.let { (_, line) ->
                                scope.launch {
                                    val uri = withContext(Dispatchers.IO) {
                                        com.dustinky.spyprobe.util.ShareLogUtil.writeLogTxtFile(context, "spyprobe_log", line)
                                    }
                                    if (uri == null) {
                                        android.widget.Toast.makeText(context, "导出失败：无法写入 txt 文件（详见 UiLog）", android.widget.Toast.LENGTH_LONG).show()
                                    } else {
                                        val err = com.dustinky.spyprobe.util.ShareLogUtil.shareUri(context, "SpyProbe 日志", uri)
                                        if (err != null) {
                                            android.widget.Toast.makeText(context, "导出失败：$err", android.widget.Toast.LENGTH_LONG).show()
                                        }
                                    }
                                }
                            }
                        },
                        containerColor = MaterialTheme.colorScheme.primaryContainer,
                        contentColor = MaterialTheme.colorScheme.primary,
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier.size(44.dp)
                    ) {
                        Icon(Icons.Filled.Share, contentDescription = "分享",
                            modifier = Modifier.size(20.dp))
                    }
                } else if (modeHistory && historyLevel == HistoryLevel.LINES) {
                    // 列表层：导出当天
                    FloatingActionButton(
                        onClick = {
                            val day = selectedDay
                            scope.launch {
                                if (day == null) {
                                    android.widget.Toast.makeText(context, "请先选择日期", android.widget.Toast.LENGTH_SHORT).show()
                                    return@launch
                                }
                                val text = withContext(Dispatchers.IO) {
                                    if (vm.rootMode.value) {
                                        // Root 模式：本地已有数据，直接拼文本
                                        vm.historyLogs.value.joinToString("\n") { it.second }
                                    } else {
                                        vm.api.exportDay(day)
                                    }
                                }
                                if (text == null || text.isEmpty()) {
                                    val why = if (text == null) vm.api.lastHttpError.ifEmpty { "HTTP 无响应" } else "日志内容为空"
                                    com.dustinky.spyprobe.util.UiLog.log("LogsScreen 导出失败: $why")
                                    android.widget.Toast.makeText(context, "导出失败：$why", android.widget.Toast.LENGTH_LONG).show()
                                    return@launch
                                }
                                val uri = withContext(Dispatchers.IO) {
                                    com.dustinky.spyprobe.util.ShareLogUtil.writeLogTxtFile(context, "spyprobe_logs_$day", text)
                                }
                                if (uri == null) {
                                    com.dustinky.spyprobe.util.UiLog.log("LogsScreen 写文件失败: $day len=${text.length}")
                                    android.widget.Toast.makeText(context, "导出失败：无法写入 txt 文件（详见 UiLog）", android.widget.Toast.LENGTH_LONG).show()
                                    return@launch
                                }
                                val err = com.dustinky.spyprobe.util.ShareLogUtil.shareUri(context, "SpyProbe 日志导出", uri)
                                if (err != null) {
                                    com.dustinky.spyprobe.util.UiLog.log("LogsScreen 分享失败: $err")
                                    android.widget.Toast.makeText(context, "导出失败：$err", android.widget.Toast.LENGTH_LONG).show()
                                }
                            }
                        },
                        containerColor = MaterialTheme.colorScheme.primaryContainer,
                        contentColor = MaterialTheme.colorScheme.primary,
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier.size(44.dp)
                    ) {
                        Icon(Icons.Filled.Share, contentDescription = "导出当天",
                            modifier = Modifier.size(20.dp))
                    }
                } else if (!modeHistory || historyLevel == HistoryLevel.DAYS) {
                    // 实时层 / 历史卡片层：导出（实时=内存；历史卡片层=当前选中天或全部）
                    FloatingActionButton(
                        onClick = {
                            scope.launch {
                                if (modeHistory && historyLevel == HistoryLevel.DAYS) {
                                    // 卡片层导出整段历史（全部天）——HTTP 模式导出全部
                                    // v1.31.1 P2-2: Root 模式卡片层不能整段导出（历史为按天文件），直接提示并取消，
                                    //   不再把提示文案写成 txt 分享（原逻辑误分享"提示文本.txt"）
                                    if (vm.rootMode.value) {
                                        android.widget.Toast.makeText(
                                            context,
                                            "Root 模式：请进入具体日期后导出（历史为按天文件）",
                                            android.widget.Toast.LENGTH_SHORT
                                        ).show()
                                        return@launch
                                    }
                                    val text = withContext(Dispatchers.IO) { vm.api.export() }
                                    if (text.isNullOrEmpty()) {
                                        val why = if (text == null) vm.api.lastHttpError.ifEmpty { "HTTP 无响应" } else "日志内容为空"
                                        android.widget.Toast.makeText(context, "导出失败：$why", android.widget.Toast.LENGTH_LONG).show()
                                    } else {
                                        val uri = withContext(Dispatchers.IO) {
                                            com.dustinky.spyprobe.util.ShareLogUtil.writeLogTxtFile(context, "spyprobe_logs", text)
                                        }
                                        if (uri != null) {
                                            val err = com.dustinky.spyprobe.util.ShareLogUtil.shareUri(context, "SpyProbe 日志导出", uri)
                                            if (err != null) android.widget.Toast.makeText(context, "导出失败：$err", android.widget.Toast.LENGTH_LONG).show()
                                        }
                                    }
                                    return@launch
                                }
                                val text = withContext(Dispatchers.IO) { vm.api.export() }
                                if (text == null || text.isEmpty()) {
                                    val why = if (text == null) vm.api.lastHttpError.ifEmpty { "HTTP 无响应" } else "日志内容为空"
                                    com.dustinky.spyprobe.util.UiLog.log("LogsScreen 导出失败: $why")
                                    android.widget.Toast.makeText(context, "导出失败：$why", android.widget.Toast.LENGTH_LONG).show()
                                    return@launch
                                }
                                val uri = withContext(Dispatchers.IO) {
                                    com.dustinky.spyprobe.util.ShareLogUtil.writeLogTxtFile(context, "spyprobe_logs", text)
                                }
                                if (uri == null) {
                                    com.dustinky.spyprobe.util.UiLog.log("LogsScreen 写文件失败: len=${text.length}")
                                    android.widget.Toast.makeText(context, "导出失败：无法写入 txt 文件（详见 UiLog）", android.widget.Toast.LENGTH_LONG).show()
                                    return@launch
                                }
                                val err = com.dustinky.spyprobe.util.ShareLogUtil.shareUri(context, "SpyProbe 日志导出", uri)
                                if (err != null) {
                                    com.dustinky.spyprobe.util.UiLog.log("LogsScreen 分享失败: $err")
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
                }
                // 跳到顶部/底部（仅实时模式 & 历史列表层）
                if (!(modeHistory && historyLevel == HistoryLevel.DETAIL)) {
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

    // ===== v1.27: 清空历史确认弹窗（v1.31.1 P2-3: 按层级提供 清当天/清全部）=====
    if (showClearDialog) {
        val clearingDay = selectedDay // LINES 层 selectedDay 非空 → 清当天；DAYS 层 → 清全部
        AlertDialog(
            onDismissRequest = { showClearDialog = false },
            title = { Text("清空历史日志") },
            text = {
                Text(
                    if (clearingDay != null) "删除 $clearingDay 当天已落盘日志，不可恢复。"
                    else "已落盘的历史日志删除后不可恢复。\n\n当前层级：卡片列表（${historyDays.size} 天）"
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        showClearDialog = false
                        vm.clearHistory(clearingDay) { ok ->
                            android.widget.Toast.makeText(context,
                                if (ok) if (clearingDay != null) "已清空当天历史" else "已清空全部历史"
                                else "清空失败（无权限/未连接）", android.widget.Toast.LENGTH_SHORT).show()
                            if (ok) {
                                // 清当天后回到卡片层刷新列表
                                if (clearingDay != null) {
                                    historyLevel = HistoryLevel.DAYS
                                    selectedDay = null
                                    vm.loadHistoryDays()
                                }
                            }
                        }
                    }
                ) { Text(if (clearingDay != null) "清空当天" else "清空全部", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = {
                TextButton(onClick = { showClearDialog = false }) { Text("取消") }
            }
        )
    }
}

/** v1.31: 历史日期卡片（小黄鸟式：日期 + 记录数 + 时间范围 + 收藏星） */
@Composable
private fun HistoryDayCard(
    day: String,
    favorite: Boolean,
    onToggleFavorite: () -> Unit,
    onClick: () -> Unit
) {
    Card(
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer
        ),
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(12.dp))
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 12.dp)
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    day,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.primary
                )
                Spacer(Modifier.height(3.dp))
                Text(
                    "点击查看当天日志",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 10.sp
                )
            }
            IconButton(onClick = onToggleFavorite, modifier = Modifier.size(32.dp)) {
                Icon(
                    if (favorite) Icons.Filled.Star else StarBorderIcon,
                    contentDescription = if (favorite) "取消收藏" else "收藏",
                    tint = if (favorite) Color(0xFFFFB300) else MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(20.dp)
                )
            }
            Text("›", style = MaterialTheme.typography.titleLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

/** v1.31: 历史日志行（时间 + tag + 摘要，点击进详情） */
@Composable
private fun HistoryLineRow(idx: Long, line: String, onClick: () -> Unit) {
    // 解析：HH:mm:ss.SSS [tag] msg
    val time = line.takeWhile { it != ' ' && it != '[' }
    val rest = line.removePrefix(time).trimStart()
    val tagEnd = rest.indexOf(']')
    val tag = if (tagEnd > 0 && rest.startsWith("[")) rest.substring(1, tagEnd) else ""
    val msg = if (tagEnd > 0) rest.substring(tagEnd + 1).trim() else rest
    val tagColor = logColor("[$tag]")

    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 4.dp, vertical = 5.dp)
    ) {
        Text(
            time,
            style = codeStyle,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.width(88.dp)
        )
        Text(
            tag.ifEmpty { "?" },
            style = codeStyle,
            color = tagColor,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.width(72.dp)
        )
        Text(
            msg,
            style = codeStyle,
            color = MaterialTheme.colorScheme.onSurface,
            softWrap = true,
            maxLines = 2,
            overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
            modifier = Modifier.weight(1f)
        )
    }
}

/** v1.31: 单条详情（完整内容 + 高亮 + 复制/分享按钮在 FAB） */
@Composable
private fun HistoryDetailView(entry: Pair<Long, String>) {
    val line = entry.second
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.surfaceContainerLowest)
            .padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        item {
            // 头部分区：完整原文着色 + 关键信息提取
            Text(
                "完整日志",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontSize = 10.sp
            )
        }
        item {
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceContainer
                ),
                shape = RoundedCornerShape(10.dp)
            ) {
                Text(
                    line,
                    style = codeStyle,
                    color = logColor(line),
                    softWrap = true,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(12.dp)
                )
            }
        }
        item {
            Text(
                "关键字高亮",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontSize = 10.sp
            )
        }
        item {
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceContainer
                ),
                shape = RoundedCornerShape(10.dp)
            ) {
                HighlightedText(
                    text = line,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(12.dp)
                )
            }
        }
    }
}

/** v1.31: 关键信息高亮（URL / IP / 方法 / 状态码 / tag 色） */
@Composable
private fun HighlightedText(text: String, modifier: Modifier = Modifier) {
    val tokens = remember(text) { highlightTokens(text) }
    Row(modifier = modifier) {
        tokens.forEach { (tok, kind) ->
            val color = when (kind) {
                "url" -> Color(0xFF4FC3F7)     // URL 蓝
                "ip" -> Color(0xFFFF7043)      // IP 橙
                "method" -> Color(0xFF66BB6A)  // 方法绿
                "num" -> Color(0xFFFFB300)     // 数字琥珀
                "tag" -> logColor("[${tok.removePrefix("[").removeSuffix("]")}]")
                else -> MaterialTheme.colorScheme.onSurface
            }
            Text(
                tok,
                style = codeStyle,
                color = color,
                softWrap = true
            )
        }
    }
}

/** v1.31: 把日志行切成 (文本, 类型) 列表，用于高亮渲染 */
private fun highlightTokens(line: String): List<Pair<String, String>> {
    val out = ArrayList<Pair<String, String>>()
    // 匹配：URL、IP、HTTP 方法、数字、[tag]
    val re = Regex("(https?://[^\\s\"]+)|(\\d{1,3}(\\.\\d{1,3}){3})|\\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\\b|(\\d{2,4})|(\\[[^\\]]+\\])")
    var pos = 0
    for (m in re.findAll(line)) {
        if (m.range.first > pos) out.add(line.substring(pos, m.range.first) to "plain")
        val g = m.value
        val kind = when {
            m.groups[1] != null -> "url"
            m.groups[2] != null -> "ip"
            m.groups[4] != null -> "method"
            m.groups[5] != null && g.length in 2..4 -> "num"
            m.groups[6] != null -> "tag"
            else -> "plain"
        }
        out.add(g to kind)
        pos = m.range.last + 1
    }
    if (pos < line.length) out.add(line.substring(pos) to "plain")
    return out
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
