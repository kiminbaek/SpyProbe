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
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
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
import androidx.compose.material3.Checkbox
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
import androidx.compose.runtime.mutableStateMapOf
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
// v1.49: 提升为 internal——HttpDetailScreen 顶栏「复制」按钮复用（原来 private，仅 LogsScreen 内可用）
internal val CopyIcon: ImageVector by lazy {
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
    val historySessions by vm.historySessions.collectAsState()
    val historyLogs by vm.historyLogs.collectAsState()
    val historyLoading by vm.historyLoading.collectAsState()
    val historySource by vm.historySource.collectAsState()
    val context = LocalContext.current
    val listState = rememberLazyListState()
    val scope = rememberCoroutineScope()

    var modeHistory by remember { mutableStateOf(false) }
    // v1.56: 分析模式（顶部三态：实时/历史/分析）——与 modeHistory 互斥
    var modeAnalysis by remember { mutableStateOf(false) }
    var filter by remember { mutableStateOf("") }
    var category by remember { mutableStateOf(LogCategory.ALL) }
    var autoScroll by remember { mutableStateOf(true) }
    // v1.33: 卡片 = 会话（目标进程每启动一次 = 一个会话）
    var selectedSession by remember { mutableStateOf<com.dustinky.spyprobe.util.HomeLogReader.SessionInfo?>(null) }
    // v1.33.1: 会话勾选分享——卡片层勾选要导出的会话（key = "date#session"），选中才分享
    var checkedSessions by remember { mutableStateOf<Set<String>>(emptySet()) }
    var showClearDialog by remember { mutableStateOf(false) }
    // v1.31: 历史三层导航
    var historyLevel by remember { mutableStateOf(HistoryLevel.DAYS) }
    var detailEntry by remember { mutableStateOf<Pair<Long, String>?>(null) }
    // v1.39 P3: 实时日志详情对话框（JSON/Hex 双视图）
    var detailDialog by remember { mutableStateOf<String?>(null) }
    // v1.48: 结构化 HTTP 请求详情页（小黄鸟式）——点击 [REQ#N] 请求行命中 HttpStore 时弹出
    var httpDetail by remember { mutableStateOf<com.dustinky.spyprobe.HttpEntry?>(null) }
    // v1.55: 通用结构化事件详情页（SQL/JSON/Crypto/TCP/DNS 卡片）——点击 [EVT#N] 行命中 HomeEventStore 时弹出
    var eventDetail by remember { mutableStateOf<com.dustinky.spyprobe.SpyEvent?>(null) }
    // v1.65: 实时层 EVT# 行文件回溯缓存——内存环形淘汰(MAX_MEM)后早期事件 find() miss 时，
    //   异步 findInDay 从 jsonl 文件找回并缓存，命中后重组渲染卡片（治"实时列表纯文本流"根因）
    val evtFileHits = remember { mutableStateMapOf<Long, com.dustinky.spyprobe.SpyEvent>() }
    val evtFileLoading = remember { mutableStateMapOf<Long, Boolean>() }
    // v1.72: 实时层 REQ# 行文件回溯缓存——同 EVT# 模式（HomeHttpStore 内存环形 MAX 200，淘汰后
    //   find() miss → 异步 findInDay 从 http_entries jsonl 找回，命中后渲染卡片 + 点击可弹详情页）
    val httpFileHits = remember { mutableStateMapOf<Long, com.dustinky.spyprobe.HttpEntry>() }
    val httpFileLoading = remember { mutableStateMapOf<Long, Boolean>() }
    // v1.25 P1-3: 暂停状态从局部 remember 改为 vm（此前暂停只停自动滚动不停轮询——日志还在积累；
    //   vm.paused 同时控制轮询停止 + 自动滚动暂停，语义一致）
    val paused by vm.paused.collectAsState()

    val displayLines = if (modeHistory && historyLevel != HistoryLevel.DAYS) historyLogs else logLines

    // v1.27: 进入历史模式拉会话列表
    LaunchedEffect(modeHistory) {
        if (modeHistory) {
            historyLevel = HistoryLevel.DAYS
            selectedSession = null
            checkedSessions = emptySet()
            vm.loadHistoryDays()
        }
    }
    // v1.31: 进入某会话 → 拉该会话日志
    LaunchedEffect(selectedSession, historyLevel) {
        if (modeHistory && historyLevel == HistoryLevel.LINES && selectedSession != null) {
            vm.loadHistory(selectedSession!!)
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
    // v1.50 P2-8: remember 缓存——实时 3000 行 × 3 次 regex 全量扫描每轮重组都做，只在 displayLines 变化时重算
    val netCount = remember(displayLines, modeHistory) {
        if (modeHistory) 0 else displayLines.count { (_, l) -> NET_REGEX.find(l) != null }
    }
    val mthCount = remember(displayLines, modeHistory) {
        if (modeHistory) 0 else displayLines.count { (_, l) -> l.contains("[Mth") }
    }
    val errCount = remember(displayLines, modeHistory) {
        if (modeHistory) 0 else displayLines.count { (_, l) -> l.contains("FAIL") || l.contains("ERROR") || l.contains("[ERR]") }
    }

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
                                selectedSession = null
                            }
                        }, modifier = Modifier.size(30.dp)) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回",
                                modifier = Modifier.size(18.dp))
                        }
                        Spacer(Modifier.width(4.dp))
                    }
                    // v1.27: 实时 / 历史 模式切换；v1.56: 三态（实时/历史/分析，互斥）
                    FilterChip(
                        selected = !modeHistory && !modeAnalysis,
                        onClick = { modeHistory = false; modeAnalysis = false; selectedSession = null; historyLevel = HistoryLevel.DAYS },
                        label = { Text("实时", fontSize = 11.sp) }
                    )
                    Spacer(Modifier.width(6.dp))
                    FilterChip(
                        selected = modeHistory,
                        onClick = { modeHistory = true; modeAnalysis = false },
                        label = { Text("历史", fontSize = 11.sp) }
                    )
                    Spacer(Modifier.width(6.dp))
                    // v1.56: 分析页入口——聚合统计（接口/SQL/加密/连接）
                    FilterChip(
                        selected = modeAnalysis,
                        onClick = { modeAnalysis = true; modeHistory = false },
                        label = { Text("分析", fontSize = 11.sp) }
                    )
                    Spacer(Modifier.width(8.dp))
                    if (!modeHistory && !modeAnalysis) {
                        StatChip("总计", logCount, MaterialTheme.colorScheme.primary)
                        Spacer(Modifier.width(8.dp))
                        StatChip("网络", netCount, Color(0xFF00E5FF))
                        Spacer(Modifier.width(8.dp))
                        StatChip("方法", mthCount, Color(0xFF42A5F5))
                        Spacer(Modifier.width(8.dp))
                        StatChip("错误", errCount, MaterialTheme.colorScheme.error)
                    } else if (modeHistory) {
                        // v1.31: 层级指示：卡片列表 → 某会话 → 详情
                        when (historyLevel) {
                            HistoryLevel.DAYS -> {
                                StatChip("历史会话", historySessions.size, MaterialTheme.colorScheme.primary)
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
                            if (historySessions.isEmpty()) "暂无历史日志（抓包时日志会自动落盘保存）" else "点击会话卡片查看该次抓包日志",
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
                        IconButton(onClick = { selectedSession?.let { vm.loadHistory(it) } }, modifier = Modifier.size(30.dp)) {
                            Icon(Icons.Filled.Refresh, contentDescription = "刷新该会话",
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

                // v1.31: 列表层/实时层显示分类筛选；详情层/分析模式不显示
                if (!modeAnalysis && !(modeHistory && historyLevel == HistoryLevel.DETAIL)) {
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
                // v1.31.4 P0: 实时模式加回「清空」按钮（v1.31 重构历史导航时丢失——用户反馈无法清空重抓）
                if (!modeHistory && !modeAnalysis) {
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
                        // v1.31.4 P0: 清空实时日志（目标进程内存 + UI 列表 + 增量游标重置），重抓前先清
                        FilterChip(
                            selected = false,
                            onClick = { vm.clearLogs() },
                            label = { Text("🗑 清空", fontSize = 11.sp, color = MaterialTheme.colorScheme.error) }
                        )
                    }
                }

                // v1.31: 搜索框 —— 实时/历史列表层显示；分析模式不显示
                if (!modeAnalysis && !(modeHistory && historyLevel == HistoryLevel.DETAIL)) {
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
                // ---- v1.56: 分析模式（聚合统计页）----
                modeAnalysis -> {
                    AnalysisScreen(modifier = Modifier.fillMaxSize())
                }

                // ---- 历史层 ①：会话卡片列表（小黄鸟式）----
                modeHistory && historyLevel == HistoryLevel.DAYS -> {
                    if (historySessions.isEmpty()) {
                        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                            Text(
                                if (historyLoading) "加载中…"
                                else "暂无历史日志（抓包时日志会自动落盘保存）",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    } else {
                        Column(Modifier.fillMaxSize()) {
                            // v1.33.1: 勾选提示
                            Text(
                                "勾选要分享的会话（点卡片右侧查看内容），再点右下角分享；未勾选时分享将提示",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 14.dp, vertical = 6.dp)
                            )
                            LazyColumn(
                                // v1.50 P1-6: 绑定 listState——历史卡片层 FAB 上下滚动按钮也有效
                                state = listState,
                                modifier = Modifier
                                    .fillMaxSize()
                                    .background(MaterialTheme.colorScheme.surfaceContainerLowest)
                                    .padding(horizontal = 10.dp, vertical = 4.dp),
                                verticalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                items(historySessions, key = { "${it.date}#${it.session}" }) { session ->
                                    val key = "${session.date}#${session.session}"
                                    HistorySessionCard(
                                        session = session,
                                        checked = key in checkedSessions,
                                        onToggleChecked = {
                                            checkedSessions = if (key in checkedSessions) checkedSessions - key
                                            else checkedSessions + key
                                        },
                                        onClick = {
                                            selectedSession = session
                                            historyLevel = HistoryLevel.LINES
                                        }
                                    )
                                }
                            }
                        }
                    }
                }

                // ---- 历史层 ②：某会话日志列表 ----
                modeHistory && historyLevel == HistoryLevel.LINES -> {
                    if (filtered.isEmpty()) {
                        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                            Text(
                                if (historyLoading) "加载中…"
                                else if (selectedSession == null) "未选择会话"
                                else "该会话/分类下暂无日志",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    } else {
                        LazyColumn(
                            // v1.50 P1-6: 绑定 listState——历史 LINES 层 FAB 上下滚动按钮才有效
                            //   （旧实现未绑，按钮操作的是实时列表的 state，历史层点了没反应）
                            state = listState,
                            modifier = Modifier
                                .fillMaxSize()
                                .background(MaterialTheme.colorScheme.surfaceContainerLowest)
                                .padding(horizontal = 8.dp, vertical = 4.dp)
                        ) {
                            items(filtered, key = { it.first }) { (idx, line) ->
                                // v1.49: 历史 LINES 层也支持 REQ# 结构化详情——内存优先，未命中按会话日期文件回溯
                                // v1.55: 同时支持 EVT# 通用事件（历史文件回溯）
                                val rid = parseReqId(line)
                                val heMem = rid?.let { com.dustinky.spyprobe.HomeHttpStore.get().find(it) }
                                if (heMem != null) {
                                    HttpRequestCard(
                                        entry = heMem,
                                        onClick = { httpDetail = heMem }
                                    )
                                } else {
                                    val eid = parseEvtId(line)
                                    val evMem = eid?.let { com.dustinky.spyprobe.HomeEventStore.get().find(it) }
                                    if (evMem != null) {
                                        EventCard(
                                            entry = evMem,
                                            onClick = { eventDetail = evMem }
                                        )
                                    } else {
                                        HistoryLineRow(
                                            idx = idx,
                                            line = line,
                                            onClick = {
                                                val rid2 = parseReqId(line)
                                                if (rid2 != null) {
                                                    val he2 = rid2?.let { com.dustinky.spyprobe.HomeHttpStore.get().find(it) }
                                                    if (he2 != null) {
                                                        httpDetail = he2
                                                    } else {
                                                        // 内存未命中 → 按会话日期从 http_entries 文件流式回溯（v1.63 P2-6: 原 readDay().firstOrNull 全量读 + 5000 截断，改为 findInDay 流式查找）
                                                        val day = selectedSession?.date
                                                        if (day != null) {
                                                            scope.launch {
                                                                val appCtx = context.applicationContext as android.app.Application
                                                                val fromDay = withContext(Dispatchers.IO) {
                                                                    com.dustinky.spyprobe.HomeHttpStore.get().findInDay(appCtx.filesDir, day, rid2)
                                                                }
                                                                if (fromDay != null) {
                                                                    httpDetail = fromDay
                                                                } else {
                                                                    detailEntry = idx to line
                                                                    historyLevel = HistoryLevel.DETAIL
                                                                }
                                                            }
                                                        } else {
                                                            detailEntry = idx to line
                                                            historyLevel = HistoryLevel.DETAIL
                                                        }
                                                    }
                                                } else {
                                                    val eid2 = parseEvtId(line)
                                                    if (eid2 != null) {
                                                        val ev2 = eid2?.let { com.dustinky.spyprobe.HomeEventStore.get().find(it) }
                                                        if (ev2 != null) {
                                                            eventDetail = ev2
                                                        } else {
                                                            // 内存未命中 → 按会话日期从 event_entries 文件流式回溯（v1.63 P2-6: 原 readDay().firstOrNull 全量读 + 5000 截断，改为 findInDay 流式查找）
                                                            val day = selectedSession?.date
                                                            if (day != null) {
                                                                scope.launch {
                                                                    val appCtx = context.applicationContext as android.app.Application
                                                                    val fromDay = withContext(Dispatchers.IO) {
                                                                        com.dustinky.spyprobe.HomeEventStore.get().findInDay(appCtx.filesDir, day, eid2)
                                                                    }
                                                                    if (fromDay != null) {
                                                                        eventDetail = fromDay
                                                                    } else {
                                                                        detailEntry = idx to line
                                                                        historyLevel = HistoryLevel.DETAIL
                                                                    }
                                                                }
                                                            } else {
                                                                detailEntry = idx to line
                                                                historyLevel = HistoryLevel.DETAIL
                                                            }
                                                        }
                                                    } else {
                                                        detailEntry = idx to line
                                                        historyLevel = HistoryLevel.DETAIL
                                                    }
                                                }
                                            }
                                        )
                                    }
                                }
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
                                // v1.49: 实时列表请求行卡片化——含 [REQ#N] 且命中 HomeHttpStore 的行渲染为小黄鸟式微卡片
                                //（方法色块+URL+状态码+耗时+响应体摘要），普通行保持纯文本
                                // v1.55: 含 [EVT#N] 且命中 HomeEventStore 的行渲染为通用事件卡片（SQL/JSON/Crypto/TCP/DNS）
                                // v1.72: REQ# 内存 miss → httpFileHits 文件回溯缓存兜底（同 EVT# 模式）
                                val rid = parseReqId(line)
                                val he = rid?.let { com.dustinky.spyprobe.HomeHttpStore.get().find(it) ?: httpFileHits[it] }
                                if (he != null) {
                                    HttpRequestCard(
                                        entry = he,
                                        onClick = { httpDetail = he }
                                    )
                                } else {
                                    // v1.72: 实时层 REQ# 内存+缓存都 miss → 异步按当天文件回溯补卡
                                    if (rid != null && !httpFileLoading.containsKey(rid)) {
                                        httpFileLoading[rid] = true
                                        LaunchedEffect(rid) {
                                            val appCtx = context.applicationContext as android.app.Application
                                            val day = java.text.SimpleDateFormat("yyyy-MM-dd", java.util.Locale.US)
                                                .format(java.util.Date())
                                            val fromDay = withContext(Dispatchers.IO) {
                                                com.dustinky.spyprobe.HomeHttpStore.get().findInDay(appCtx.filesDir, day, rid)
                                            }
                                            if (fromDay != null) { httpFileHits[rid] = fromDay; if (httpFileHits.size > 500) { httpFileHits.remove(httpFileHits.keys.first()) } }
                                            httpFileLoading.remove(rid)
                                        }
                                    }
                                    val eid = parseEvtId(line)
                                    val ev = eid?.let { eid2 ->
                                        com.dustinky.spyprobe.HomeEventStore.get().find(eid2)
                                            ?: evtFileHits[eid2]   // v1.65: 内存 miss → 文件回溯缓存
                                    }
                                    if (ev != null) {
                                        EventCard(
                                            entry = ev,
                                            onClick = { eventDetail = ev }
                                        )
                                    } else {
                                        // v1.65: 实时层内存+缓存都 miss → 异步按当天文件回溯补卡
                                        if (eid != null && !evtFileLoading.containsKey(eid)) {
                                            evtFileLoading[eid] = true
                                            LaunchedEffect(eid) {
                                                val appCtx = context.applicationContext as android.app.Application
                                                val day = java.text.SimpleDateFormat("yyyy-MM-dd", java.util.Locale.US)
                                                    .format(java.util.Date())
                                                val fromDay = withContext(Dispatchers.IO) {
                                                    com.dustinky.spyprobe.HomeEventStore.get().findInDay(appCtx.filesDir, day, eid)
                                                }
                                                if (fromDay != null) { evtFileHits[eid] = fromDay; if (evtFileHits.size > 500) { evtFileHits.remove(evtFileHits.keys.first()) } }
                                                evtFileLoading.remove(eid)
                                            }
                                        }
                                        StructLogRow(
                                            line = line,
                                            onClick = {
                                                    // v1.72: REQ# 内存 → httpFileHits 缓存 → 都 miss 异步文件回溯（同 EVT#）
                                                    val rid2 = parseReqId(line)
                                                    val he2 = rid2?.let {
                                                        com.dustinky.spyprobe.HomeHttpStore.get().find(it) ?: httpFileHits[it]
                                                    }
                                                    if (he2 != null) {
                                                        httpDetail = he2
                                                    } else if (rid2 != null && !httpFileLoading.containsKey(rid2)) {
                                                        httpFileLoading[rid2] = true
                                                        scope.launch {
                                                            val appCtx = context.applicationContext as android.app.Application
                                                            val day = java.text.SimpleDateFormat("yyyy-MM-dd", java.util.Locale.US)
                                                                .format(java.util.Date())
                                                            val fromDay = withContext(Dispatchers.IO) {
                                                                com.dustinky.spyprobe.HomeHttpStore.get().findInDay(appCtx.filesDir, day, rid2)
                                                            }
                                                            if (fromDay != null) {
                                                                httpFileHits[rid2] = fromDay
                                                                if (httpFileHits.size > 500) { httpFileHits.remove(httpFileHits.keys.first()) }
                                                                httpDetail = fromDay
                                                            } else {
                                                                detailDialog = line
                                                            }
                                                            httpFileLoading.remove(rid2)
                                                        }
                                                    } else {
                                                        val eid2 = parseEvtId(line)
                                                        val ev2 = eid2?.let { eid3 ->
                                                            com.dustinky.spyprobe.HomeEventStore.get().find(eid3)
                                                                ?: evtFileHits[eid3]   // v1.65: 文件回溯缓存兜底
                                                        }
                                                        if (ev2 != null) {
                                                            eventDetail = ev2
                                                        } else {
                                                            detailDialog = line
                                                        }
                                                    }
                                                }
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // v1.39 P3: 实时日志详情对话框 → v2.1.1 升级为全屏详情分析页 LogDetailPage
            //   （旧实现只是 AlertDialog 弹窗，用户反馈抓包结果要能点开有详情分析页）
            val dialogLine = detailDialog
            if (dialogLine != null) {
                LogDetailPage(line = dialogLine, onBack = { detailDialog = null })
            }

            // v1.51: 结构化 HTTP 请求详情页——从 Dialog 弹窗改为全屏页（小黄鸟式）
            // v1.59: 传目标包名（总览「应用程序」板块）
            val httpEntry = httpDetail
            if (httpEntry != null) {
                HttpDetailPage(entry = httpEntry, onBack = { httpDetail = null }, targetPackage = vm.targetPkg.value)
            }
            // v1.55: 通用结构化事件详情页（SQL/JSON/Crypto/TCP/DNS 卡片）
            val evEntry = eventDetail
            if (evEntry != null) {
                EventDetailScreen(entry = evEntry, onBack = { eventDetail = null })
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
                    // 列表层：导出当前会话（v1.33.1: 一律优先本地 readSession，免 root 免目标 App 在线——
                    //   旧逻辑普通模式走 api.exportDay 依赖目标进程，目标 App 闪退后分享必失败）
                    FloatingActionButton(
                        onClick = {
                            val session = selectedSession
                            scope.launch {
                                if (session == null) {
                                    android.widget.Toast.makeText(context, "请先选择会话", android.widget.Toast.LENGTH_SHORT).show()
                                    return@launch
                                }
                                val text = withContext(Dispatchers.IO) {
                                    val appCtx = context.applicationContext as android.app.Application
                                    val local = com.dustinky.spyprobe.util.HomeLogReader.readSession(appCtx.filesDir, session.date, session.session, 20000)
                                    if (local.isNotEmpty()) {
                                        val sb = StringBuilder()
                                        sb.append("===== 会话 ${session.date} #${session.session}（${local.size} 条）=====\n")
                                        for (e in local) {
                                            // v1.35 P2-1: 统一 formatLine（tag 右对齐 + msg 单行）
                                            sb.append(com.dustinky.spyprobe.util.ShareLogUtil.formatLine(e.time, e.tag, e.msg)).append('\n')
                                        }
                                        sb.toString()
                                    } else if (vm.rootMode.value) {
                                        vm.historyLogs.value.joinToString("\n") { it.second }
                                    } else {
                                        vm.api.exportDay(session.date)
                                    }
                                }
                                if (text == null || text.isEmpty()) {
                                    val why = if (text == null) vm.api.lastHttpError.ifEmpty { "HTTP 无响应" } else "日志内容为空"
                                    com.dustinky.spyprobe.util.UiLog.log("LogsScreen 导出失败: $why")
                                    android.widget.Toast.makeText(context, "导出失败：$why", android.widget.Toast.LENGTH_LONG).show()
                                    return@launch
                                }
                                android.widget.Toast.makeText(context, "正在导出会话 ${session.date.takeLast(5)} #${session.session}…", android.widget.Toast.LENGTH_SHORT).show()
                                val uri = withContext(Dispatchers.IO) {
                                    com.dustinky.spyprobe.util.ShareLogUtil.writeLogTxtFile(context, "spyprobe_logs_${session.date}_s${session.session}", text)
                                }
                                if (uri == null) {
                                    com.dustinky.spyprobe.util.UiLog.log("LogsScreen 写文件失败: ${session.date}#${session.session} len=${text.length}")
                                    android.widget.Toast.makeText(context, "导出失败：无法写入 txt 文件（详见 UiLog）", android.widget.Toast.LENGTH_LONG).show()
                                    return@launch
                                }
                                val err = com.dustinky.spyprobe.util.ShareLogUtil.shareUri(context, "SpyProbe 日志导出（会话 ${session.date.takeLast(5)} #${session.session}）", uri)
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
                        Icon(Icons.Filled.Share, contentDescription = "导出该会话",
                            modifier = Modifier.size(20.dp))
                    }
                } else if (!modeHistory || historyLevel == HistoryLevel.DAYS) {
                    // 实时层 / 历史卡片层：导出
                    FloatingActionButton(
                        onClick = {
                            scope.launch {
                                if (modeHistory && historyLevel == HistoryLevel.DAYS) {
                                    // v1.33.1: 卡片层分享 = 只导出勾选的会话（本地拼，免 root 免目标 App 在线）
                                    if (checkedSessions.isEmpty()) {
                                        android.widget.Toast.makeText(context, "请先勾选要分享的会话（点卡片左侧勾选框）", android.widget.Toast.LENGTH_SHORT).show()
                                        return@launch
                                    }
                                    val text = withContext(Dispatchers.IO) {
                                        val appCtx = context.applicationContext as android.app.Application
                                        val sessions = com.dustinky.spyprobe.util.HomeLogReader.sessions(appCtx.filesDir)
                                            .filter { "${it.date}#${it.session}" in checkedSessions }
                                        if (sessions.isEmpty()) null
                                        else {
                                            val sb = StringBuilder()
                                            for (s in sessions) {
                                                sb.append("===== 会话 ${s.date} #${s.session}（${s.count} 条，${s.firstTime} → ${s.lastTime}）=====\n")
                                                val entries = com.dustinky.spyprobe.util.HomeLogReader.readSession(appCtx.filesDir, s.date, s.session, 20000)
                                                for (e in entries) {
                                                    // v1.35 P2-1: 统一 formatLine（tag 右对齐 + msg 单行）
                                                    sb.append(com.dustinky.spyprobe.util.ShareLogUtil.formatLine(e.time, e.tag, e.msg)).append('\n')
                                                }
                                            }
                                            sb.toString()
                                        }
                                    }
                                    if (text == null || text.isEmpty()) {
                                        android.widget.Toast.makeText(context, "导出失败：勾选的会话在本地无日志（无法读取）", android.widget.Toast.LENGTH_LONG).show()
                                        return@launch
                                    }
                                    val uri = withContext(Dispatchers.IO) {
                                        // v1.50 P2-17: 文件名带日期，多天导出不混淆
                                        com.dustinky.spyprobe.util.ShareLogUtil.writeLogTxtFile(
                                            context,
                                            "spyprobe_logs_selected_${java.time.LocalDate.now()}_${checkedSessions.size}",
                                            text
                                        )
                                    }
                                    if (uri == null) {
                                        com.dustinky.spyprobe.util.UiLog.log("LogsScreen 写文件失败: selected ${checkedSessions.size} len=${text.length}")
                                        android.widget.Toast.makeText(context, "导出失败：无法写入 txt 文件（详见 UiLog）", android.widget.Toast.LENGTH_LONG).show()
                                    } else {
                                        val err = com.dustinky.spyprobe.util.ShareLogUtil.shareUri(context, "SpyProbe 日志导出（已选 ${checkedSessions.size} 个会话）", uri)
                                        if (err != null) {
                                            com.dustinky.spyprobe.util.UiLog.log("LogsScreen 分享失败: $err")
                                            android.widget.Toast.makeText(context, "导出失败：$err", android.widget.Toast.LENGTH_LONG).show()
                                        }
                                    }
                                    return@launch
                                }
                                // v1.41: 实时分享双通道——先读自己家（9900，永远可用，APP 不在线也成功）
                                // 9901 目标进程 export 仅作兜底（自己家不可用时）
                                val text = withContext(Dispatchers.IO) {
                                    vm.api.homeExport() ?: vm.api.export()
                                }
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

    // ===== v1.27: 清空历史确认弹窗（v1.33: LINES 层清当前会话；DAYS 层清全部）=====
    if (showClearDialog) {
        val clearingSession = selectedSession // LINES 层 selectedSession 非空 → 清当前会话；DAYS 层 → 清全部
        AlertDialog(
            onDismissRequest = { showClearDialog = false },
            title = { Text("清空历史日志") },
            text = {
                Text(
                    if (clearingSession != null) "删除 ${clearingSession.date} #${clearingSession.session} 该会话已落盘日志，不可恢复。"
                    else "已落盘的历史日志删除后不可恢复。\n\n当前层级：卡片列表（${historySessions.size} 个会话）"
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        showClearDialog = false
                        vm.clearHistorySession(clearingSession) { ok ->
                            android.widget.Toast.makeText(context,
                                if (ok) if (clearingSession != null) "已清空该会话历史" else "已清空全部历史"
                                else "清空失败（无权限/未连接）", android.widget.Toast.LENGTH_SHORT).show()
                            if (ok) {
                                // 清会话后回到卡片层刷新列表
                                if (clearingSession != null) {
                                    historyLevel = HistoryLevel.DAYS
                                    selectedSession = null
                                    vm.loadHistoryDays()
                                }
                            }
                        }
                    }
                ) { Text(if (clearingSession != null) "清空该会话" else "清空全部", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = {
                TextButton(onClick = { showClearDialog = false }) { Text("取消") }
            }
        )
    }
}

/** v1.31: 历史日期卡片（小黄鸟式：日期 + 记录数 + 时间范围 + 收藏星） */
@Composable
/** v1.33: 历史会话卡片（日期 + 会话号 + 条数 + 时间范围） */
/** v1.33.1: 会话卡片 = 会话 + 勾选框（勾选才分享；点卡片本体进详情） */
private fun HistorySessionCard(
    session: com.dustinky.spyprobe.util.HomeLogReader.SessionInfo,
    checked: Boolean,
    onToggleChecked: () -> Unit,
    onClick: () -> Unit
) {
    // 2026-08-09 -> 08-09
    val shortDate = session.date.takeLast(5)
    val timeRange = if (session.firstTime.isNotEmpty() && session.lastTime.isNotEmpty())
        "${session.firstTime} → ${session.lastTime}" else "时间未知"
    val countText = when {
        session.count > 0 -> "${session.count} 条"
        session.fileCount > 0 -> "${session.fileCount} 文件"
        else -> "—"
    }
    Card(
        colors = CardDefaults.cardColors(
            containerColor = if (checked) MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.45f)
            else MaterialTheme.colorScheme.surfaceContainer
        ),
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .border(
                if (checked) 1.5.dp else 1.dp,
                if (checked) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outlineVariant,
                RoundedCornerShape(12.dp)
            )
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 6.dp)
        ) {
            Checkbox(
                checked = checked,
                onCheckedChange = { onToggleChecked() },
                modifier = Modifier.size(36.dp)
            )
            Spacer(Modifier.width(4.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    "$shortDate  #${session.session}",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.primary
                )
                Spacer(Modifier.height(3.dp))
                Text(
                    "$countText · $timeRange",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 10.sp
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
            maxLines = 1,
            overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis, // v1.50 P2-19: 长 tag 截断不溢出
            modifier = Modifier.width(72.dp)
        )
        Text(
            msg,
            style = codeStyle,
            color = if (msg.contains("FAIL") || msg.contains("ERROR")) Color(0xFFFF5252) // v1.50 P2-18: 失败红色
            else MaterialTheme.colorScheme.onSurface,
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
                    color = lineColor(line), // v1.50 P2-18: 失败行红色高亮
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


// v1.50 P2-11: formatJson 统一到 CaptureScreen.kt（internal），本文件直接引用

/** hex dump：优先还原日志行里的 "[N B hex] xxxx" 段；否则对整行 UTF-8 字节 dump（最多 256B） */
internal fun hexDump(line: String): String {
    val bytes = try {
        val m = Regex("\\[(\\d+)B hex\\]\\s+([0-9a-fA-F ]+)").find(line)
        if (m != null) hexToBytes(m.groupValues[2])
        else line.toByteArray(Charsets.UTF_8).take(256).toByteArray()
    } catch (t: Throwable) {
        line.toByteArray(Charsets.UTF_8).take(256).toByteArray()
    }
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

private fun hexToBytes(s: String): ByteArray {
    val clean = s.replace(" ", "")
    val out = ByteArray(clean.length / 2)
    for (i in out.indices) {
        out[i] = clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
    }
    return out
}

// v1.48: 从日志行解析 [REQ#N] 关联 id（命中 HttpStore 则展示结构化详情页）
private fun parseReqId(line: String): Long? {
    val m = Regex("""\[REQ#(\d+)]""").find(line) ?: return null
    return m.groupValues[1].toLongOrNull()
}

/**
 * v1.49: 实时列表请求微卡片（小黄鸟式）——命中 HomeHttpStore 的 [REQ#N] 行渲染为结构化卡片：
 *   [GET]  api.example.com/v1/user             ●200
 *   REQ#7  342B→1.8KB  1.2s                    响应体摘要
 */
@Composable
private fun HttpRequestCard(entry: com.dustinky.spyprobe.HttpEntry, onClick: () -> Unit) {
    val done = entry.done
    val failed = done && entry.status <= 0
    val statusTxt = when {
        failed -> "FAIL"
        !done -> "…"
        else -> entry.status.toString()
    }
    val statusCol = when {
        failed -> MaterialTheme.colorScheme.error
        !done -> MaterialTheme.colorScheme.onSurfaceVariant
        else -> statusColor(entry.status)
    }
    // URL 摘要：host + path（截断）
    val urlSummary = try {
        val u = java.net.URI(entry.url)
        val path = u.path
        val q = u.rawQuery
        val p = if (!path.isNullOrEmpty()) path else "/"
        val full = "${u.host ?: entry.url}$p" + if (!q.isNullOrEmpty()) "?$q" else ""
        if (full.length > 60) full.take(60) + "…" else full
    } catch (t: Throwable) {
        entry.url
    }
    // 响应体摘要（首行，截断 60 字符）
    val bodySummary = if (entry.done && entry.respBody.isNotBlank()) {
        entry.respBody.replace("\n", " ").trim().let { if (it.length > 60) it.take(60) + "…" else it }
    } else if (failed) {
        "请求失败"
    } else {
        "请求中…"
    }

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
            // 第一行：方法色块 + URL + 状态
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    entry.method.uppercase(),
                    color = Color.White,
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier
                        .background(methodColor(entry.method), RoundedCornerShape(4.dp))
                        .padding(horizontal = 5.dp, vertical = 1.dp)
                )
                Spacer(Modifier.width(6.dp))
                Text(
                    urlSummary,
                    style = codeStyle,
                    fontSize = 11.sp,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f)
                )
                Spacer(Modifier.width(6.dp))
                // 状态码
                Text(
                    statusTxt,
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold,
                    color = statusCol,
                    fontSize = 11.sp
                )
                // 状态点
                Box(
                    Modifier
                        .padding(start = 4.dp)
                        .width(7.dp)
                        .height(7.dp)
                        .background(statusCol, RoundedCornerShape(50))
                )
            }
            // 第二行：REQ# + 大小 + 耗时 + 响应摘要
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    "REQ#${entry.id}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 9.sp
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    // v1.50 P2-9: 大小格式化（原 7340032B 改成 7.0MB 一眼可读）
                    "${fmtBytes(entry.reqBodyBytes.toLong())}→${fmtBytes(entry.respBodyBytes.toLong())}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 9.sp
                )
                if (entry.done) {
                    Spacer(Modifier.width(8.dp))
                    Text(
                        "${entry.durationMs}ms",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.secondary,
                        fontSize = 9.sp
                    )
                }
                Spacer(Modifier.weight(1f))
                Text(
                    bodySummary,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 9.sp,
                    maxLines = 1,
                    overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis
                )
            }
        }
    }
}
