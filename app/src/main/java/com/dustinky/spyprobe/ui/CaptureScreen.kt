package com.dustinky.spyprobe.ui

import android.graphics.Bitmap
import androidx.compose.foundation.Image
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
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.dustinky.spyprobe.ui.theme.codeStyle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.regex.Pattern

// v1.24: 抓包页重做 —— 大状态卡 + 分组开关 + 日志预览 + 终端风格
// v1.18: 抓包页 —— 目标/端口/状态/记录开关 + 日志入口（日志流已移到独立 LogsScreen）
// v1.43: 整页可滚动 + 批量开关（全开/全关/恢复默认）+ 重放快捷入口

/** v1.43: 抓包页全部开关 key（用于"全开/全关"） */
private val ALL_SWITCH_KEYS = listOf(
    "sslBypass", "okhttp", "url", "dns", "tcp",
    "tls", "connect", "cronet", "native",
    "webView", "logcat", "sqlite", "urlBuild",
    "crypto", "activity", "json", "env", "classes"
)

/** v1.43: 抓包开关默认值（与下方各 SwitchItem 的 fallback 默认一致，恢复默认用） */
private val DEFAULT_SWITCHES: Map<String, Any> = mapOf(
    "sslBypass" to true, "okhttp" to true, "url" to true, "dns" to true, "tcp" to true,
    "tls" to true, "connect" to true, "cronet" to false, "native" to true,
    "webView" to true, "logcat" to true, "sqlite" to true, "urlBuild" to true,
    "crypto" to false, "activity" to false, "json" to false, "env" to true, "classes" to true
)

@Composable
fun CaptureScreen(vm: SpyViewModel, onOpenLogs: () -> Unit, modifier: Modifier = Modifier) {
    val target by vm.targetPkg.collectAsState()
    val port by vm.port.collectAsState()
    val status by vm.status.collectAsState()
    val connected by vm.connected.collectAsState()
    val logCount by vm.logCount.collectAsState()
    val logLines by vm.logLines.collectAsState()
    val context = LocalContext.current

    var cfg by remember { mutableStateOf<Map<String, Any>>(emptyMap()) }
    var expanded by remember { mutableStateOf("basic") } // basic/advanced/app

    // v1.25 P0-2: 统一配置入口——保存到目标 App 覆盖层（本地权威）+ 推送；
    // 未连接时也保存本地（连接恢复后自动补发），不再"未连接就丢弃"
    fun setSwitch(key: String, value: Boolean) {
        val ok = vm.setEffectiveSwitch(key, value)
        cfg = cfg + (key to value)
        if (!ok) {
            android.widget.Toast.makeText(context, "未连接，已保存本地，连接后自动生效", android.widget.Toast.LENGTH_SHORT).show()
        }
    }

    // v1.43: 批量应用开关（全开/全关/恢复默认）——一次保存+一次推送
    fun applySwitches(values: Map<String, Any>) {
        val ok = vm.setSwitches(values)
        cfg = cfg + values
        if (!ok) {
            android.widget.Toast.makeText(context, "未连接，已保存本地，连接后自动生效", android.widget.Toast.LENGTH_SHORT).show()
        }
    }

    LaunchedEffect(Unit) {
        vm.refreshStatus()
        val c = withContext(Dispatchers.IO) { vm.api.fetchConfig() }
        if (c != null) cfg = c
    }

    // v1.25 P2-7: 连接恢复时重新拉取后端配置（轮询断线→重连后 UI 快照与后端对齐）
    LaunchedEffect(connected) {
        if (connected) {
            val c = withContext(Dispatchers.IO) { vm.api.fetchConfig() }
            if (c != null) cfg = c
        }
    }

    // 日志预览（最后 3 条）
    val previewLines = logLines.takeLast(3)

    // v1.40 P1: 请求重放状态
    val scope = rememberCoroutineScope()
    var showReplay by remember { mutableStateOf(false) }
    var replayItems by remember { mutableStateOf<List<ReplayEntry>>(emptyList()) }
    var replayLoading by remember { mutableStateOf(false) }
    fun refreshReplay() {
        scope.launch {
            replayLoading = true
            replayItems = withContext(Dispatchers.IO) { vm.api.replayHistory() } ?: emptyList()
            replayLoading = false
        }
    }
    LaunchedEffect(connected) {
        if (connected && showReplay) refreshReplay()
    }

    // v1.43 P0-1: 整页加 verticalScroll——此前 Column 不可滚动，展开"高级抓包/应用层记录"
    //   后内容超出屏幕底部无法操作（状态卡+3组开关+日志预览+重放卡总高约 920dp，主流屏 640-800dp）
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp)
    ) {

        // ===== 状态大卡（v1.24 核心：App 图标 + 状态 + 端口 + 目标切换）=====
        Card(
            colors = CardDefaults.cardColors(
                containerColor = if (connected)
                    MaterialTheme.colorScheme.primaryContainer
                else
                    MaterialTheme.colorScheme.surfaceContainerHigh
            ),
            shape = RoundedCornerShape(16.dp),
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 8.dp)
                .border(
                    1.dp,
                    if (connected) MaterialTheme.colorScheme.primary.copy(alpha = 0.4f)
                    else MaterialTheme.colorScheme.outline,
                    RoundedCornerShape(16.dp)
                )
        ) {
            Column(Modifier.padding(16.dp)) {
                // 状态灯 + 状态文本
                Row(verticalAlignment = Alignment.CenterVertically) {
                    // v1.24: 脉冲状态灯
                    Box(
                        modifier = Modifier
                            .size(10.dp)
                            .background(
                                if (connected) Color(0xFF00E676) else Color(0xFFFF5252),
                                RoundedCornerShape(50)
                            )
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(
                        if (connected) "● 已连接" else "○ 未连接",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                        color = if (connected) MaterialTheme.colorScheme.primary
                        else MaterialTheme.colorScheme.error
                    )
                    Spacer(Modifier.weight(1f))
                    // v1.28 P1: 端口只读展示（手动改端口是误导，server 端口固定 9901 / scanPorts 自动发现）
                    Text(
                        "端口 $port",
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.padding(horizontal = 4.dp, vertical = 2.dp)
                    )
                }

                Spacer(Modifier.height(12.dp))

                // 目标 App 行：图标 + 包名 + 切换
                var showPicker by remember { mutableStateOf(false) }
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(10.dp))
                        .background(MaterialTheme.colorScheme.surface)
                        .clickable { showPicker = true }
                        .padding(horizontal = 12.dp, vertical = 10.dp)
                ) {
                    if (target.isNotEmpty()) {
                        AppIcon(pkg = target, modifier = Modifier.size(36.dp))
                        Spacer(Modifier.width(10.dp))
                    } else {
                        Box(
                            modifier = Modifier
                                .size(36.dp)
                                .background(
                                    MaterialTheme.colorScheme.surfaceVariant,
                                    RoundedCornerShape(8.dp)
                                )
                        )
                        Spacer(Modifier.width(10.dp))
                    }
                    Column(Modifier.weight(1f)) {
                        Text(
                            if (target.isEmpty()) "选择目标 App" else target,
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Medium,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Text(
                            if (target.isEmpty()) "点击选择" else "点击切换",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            fontSize = 11.sp
                        )
                    }
                    Text("›", color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                if (showPicker) {
                    TargetPickerDialog(vm, onDismiss = { showPicker = false })
                }
            }
        }

        // ===== 开关分组（v1.24：可折叠卡片，分三组）=====
        Spacer(Modifier.height(12.dp))

        // v1.43 P1: 批量开关——调试常要"全开抓一把"，逐个点 18 个开关太累
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth().padding(bottom = 2.dp)
        ) {
            Text(
                "抓包开关",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.weight(1f)
            )
            TextButton(onClick = { applySwitches(ALL_SWITCH_KEYS.associateWith { true }) }) { Text("全开", fontSize = 12.sp) }
            TextButton(onClick = { applySwitches(ALL_SWITCH_KEYS.associateWith { false }) }) { Text("全关", fontSize = 12.sp) }
            TextButton(onClick = { applySwitches(DEFAULT_SWITCHES) }) { Text("恢复默认", fontSize = 12.sp) }
        }

        // 基础抓包
        SwitchGroupCard(
            title = "基础抓包",
            subtitle = "SSL / OkHttp / URL / DNS / TCP",
            expanded = expanded == "basic",
            onToggle = { expanded = if (expanded == "basic") "" else "basic" }
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                SwitchItem("SSL 绕过", cfg["sslBypass"] as? Boolean ?: true) { setSwitch("sslBypass", it) }
                SwitchItem("OkHttp", cfg["okhttp"] as? Boolean ?: true) { setSwitch("okhttp", it) }
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                SwitchItem("URLConn", cfg["url"] as? Boolean ?: true) { setSwitch("url", it) }
                SwitchItem("DNS 解析", cfg["dns"] as? Boolean ?: true) { setSwitch("dns", it) }
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                SwitchItem("TCP 连接", cfg["tcp"] as? Boolean ?: true) { setSwitch("tcp", it) }
            }
        }

        // 高级抓包
        Spacer(Modifier.height(8.dp))
        SwitchGroupCard(
            title = "高级抓包",
            subtitle = "TLS 明文 / 连接点 / Cronet / native",
            expanded = expanded == "advanced",
            onToggle = { expanded = if (expanded == "advanced") "" else "advanced" }
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                SwitchItem("TLS 明文", cfg["tls"] as? Boolean ?: true) { setSwitch("tls", it) }
                SwitchItem("万能连接", cfg["connect"] as? Boolean ?: true) { setSwitch("connect", it) }
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                SwitchItem("Cronet", cfg["cronet"] as? Boolean ?: false) { setSwitch("cronet", it) }
                SwitchItem("native 层*", cfg["native"] as? Boolean ?: true) { setSwitch("native", it) }
            }
            // v1.36 P1-4b: native 是"装不装 native hook"级别的全局开关（重启目标 App 生效），
            //   加显式提示避免用户以为即时生效
            Text(
                "* native 层开关需重启目标 App 后生效（影响 native hook 装载）",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontSize = 10.sp,
                modifier = Modifier.padding(top = 2.dp, bottom = 4.dp)
            )
        }

        // 应用层记录
        Spacer(Modifier.height(8.dp))
        SwitchGroupCard(
            title = "应用层记录",
            subtitle = "WebView / Log / SQLite / URL构造 / Crypto / 类加载",
            expanded = expanded == "app",
            onToggle = { expanded = if (expanded == "app") "" else "app" }
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                SwitchItem("WebView", cfg["webView"] as? Boolean ?: true) { setSwitch("webView", it) }
                SwitchItem("App Log", cfg["logcat"] as? Boolean ?: true) { setSwitch("logcat", it) }
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                SwitchItem("SQLite", cfg["sqlite"] as? Boolean ?: true) { setSwitch("sqlite", it) }
                SwitchItem("URL 构造", cfg["urlBuild"] as? Boolean ?: true) { setSwitch("urlBuild", it) }
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                SwitchItem("加密", cfg["crypto"] as? Boolean ?: false) { setSwitch("crypto", it) }
                SwitchItem("Activity", cfg["activity"] as? Boolean ?: false) { setSwitch("activity", it) }
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                SwitchItem("JSON", cfg["json"] as? Boolean ?: false) { setSwitch("json", it) }
                SwitchItem("环境检测", cfg["env"] as? Boolean ?: true) { setSwitch("env", it) }
            }
            // v1.36 P1-4a: 类加载（ClassLoadProbe 应用层探测）从「基础抓包」移入「应用层记录」
            Row(verticalAlignment = Alignment.CenterVertically) {
                SwitchItem("类加载", cfg["classes"] as? Boolean ?: true) { setSwitch("classes", it) }
            }
        }

        Spacer(Modifier.height(12.dp))

        // ===== 日志预览卡（v1.24 新增：抓包页直接看最近几条）=====
        Card(
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceContainerHigh
            ),
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(12.dp))
        ) {
            Column(Modifier.fillMaxWidth()) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable(onClick = onOpenLogs)
                        .padding(horizontal = 14.dp, vertical = 10.dp)
                ) {
                    Text(
                        "实时日志",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(Modifier.width(8.dp))
                    // v1.24: 日志条数徽章
                    Box(
                        modifier = Modifier
                            .background(
                                MaterialTheme.colorScheme.primary.copy(alpha = 0.15f),
                                RoundedCornerShape(8.dp)
                            )
                            .padding(horizontal = 6.dp, vertical = 2.dp)
                    ) {
                        Text(
                            "$logCount 条",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.primary,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                    Spacer(Modifier.weight(1f))
                    // v1.43 P2: 请求重放快捷入口——ReplayCard 折叠在页底可发现性差，
                    //   日志预览卡右上角直接给入口（有缓存请求才显示）
                    if (replayItems.isNotEmpty()) {
                        TextButton(
                            onClick = {
                                showReplay = true
                                refreshReplay()
                            },
                            modifier = Modifier.height(28.dp)
                        ) { Text("重放 ${replayItems.size}", fontSize = 11.sp) }
                        Spacer(Modifier.width(4.dp))
                    }
                    Text(
                        "查看全部 ›",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary,
                        fontWeight = FontWeight.Medium
                    )
                }

                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)

                // 预览区（最后 3 条）
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp)
                        .background(MaterialTheme.colorScheme.surfaceContainerLowest)
                        .clickable(onClick = onOpenLogs)
                        .padding(horizontal = 12.dp, vertical = 6.dp)
                ) {
                    if (previewLines.isEmpty()) {
                        Text(
                            "暂无日志，启动目标 App 后自动开始记录…",
                            style = codeStyle,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    } else {
                        Column {
                            previewLines.forEach { p ->
                                Text(
                                    p.second.take(120),
                                    style = codeStyle,
                                    color = logColor(p.second),
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                            }
                        }
                    }
                }
            }
        }

        Spacer(Modifier.height(12.dp))

        // ===== 请求重放卡（v1.40 P1：OkHttpLogger-Frida/poker 借鉴）=====
        ReplayCard(
            expanded = showReplay,
            onToggle = {
                showReplay = !showReplay
                if (showReplay) refreshReplay()
            },
            items = replayItems,
            loading = replayLoading,
            onRefresh = { refreshReplay() },
            onClear = {
                scope.launch {
                    withContext(Dispatchers.IO) { vm.api.replayClear() }
                    replayItems = emptyList()
                    android.widget.Toast.makeText(context, "重放缓存已清空", android.widget.Toast.LENGTH_SHORT).show()
                }
            },
            onReplay = { e ->
                scope.launch {
                    val ok = withContext(Dispatchers.IO) { vm.api.replay(e.id) }
                    android.widget.Toast.makeText(
                        context,
                        if (ok) "已重放 #${e.id}，结果见日志流" else "重放失败：未连接或后端错误",
                        android.widget.Toast.LENGTH_SHORT
                    ).show()
                }
            },
            connected = connected
        )
    }
}

// ---------- 可折叠开关分组卡片（v1.24 新增）----------
@Composable
private fun SwitchGroupCard(
    title: String,
    subtitle: String,
    expanded: Boolean,
    onToggle: () -> Unit,
    content: @Composable () -> Unit
) {
    Card(
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer
        ),
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(12.dp))
    ) {
        Column(Modifier.fillMaxWidth()) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable(onClick = onToggle)
                    .padding(horizontal = 14.dp, vertical = 10.dp)
            ) {
                Column(Modifier.weight(1f)) {
                    Text(
                        title,
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        subtitle,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        fontSize = 11.sp
                    )
                }
                Text(
                    if (expanded) "˄" else "˅",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 16.sp
                )
            }
            if (expanded) {
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                Column(
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp)
                ) {
                    content()
                }
            }
        }
    }
}

@Composable
private fun androidx.compose.foundation.layout.RowScope.SwitchItem(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
        Text(
            label,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.weight(1f),
            fontSize = 13.sp
        )
        Switch(checked = checked, onCheckedChange = { onChange(it) })
    }
}

// 过滤快捷短语（v1.16 P2-11）
internal const val NET_FILTER = "(Net|DNS|TCP|HUC|OkHttp|SSL)"
internal const val MTH_FILTER = "(Mth)"

/** v1.16 P2-9: 日志按 tag 类型着色
 *  v1.24: 调色适配新主题（荧光绿/青蓝/橙/紫/粉/红）*/
internal fun logColor(line: String): Color {
    return when {
        line.contains("[DBG]") -> Color(0xFF00E5FF)          // 青蓝 - 调试
        line.startsWith("[TCP] FAIL") -> Color(0xFFFF5252)    // 红 - 失败
        line.startsWith("[Net") || line.startsWith("[DNS") || line.startsWith("[TCP") ||
                line.startsWith("[SSL") || line.startsWith("[HUC") || line.startsWith("[OkHttp") ||
                line.startsWith("[Cronet") -> Color(0xFF00E676) // 荧光绿 - 网络
        line.startsWith("[Mth") || line.startsWith("[Cls") -> Color(0xFF42A5F5)  // 蓝 - 方法
        line.startsWith("[RULE") -> Color(0xFFFF9100)         // 橙 - 规则
        line.startsWith("[anti") -> Color(0xFFCE93D8)         // 紫 - 反检测
        line.startsWith("[SQL") || line.startsWith("[JSON") || line.startsWith("[Gson") -> Color(0xFFFFB300) // 琥珀 - 数据
        line.startsWith("[VPN") || line.startsWith("[属性") || line.startsWith("[传感器") ||
                line.startsWith("[防截屏") || line.startsWith("[IMEI") || line.startsWith("[设备") -> Color(0xFFF06292) // 粉 - 环境
        line.startsWith("[") -> Color(0xFF78909C)             // 灰蓝 - 其他
        else -> Color(0xFF90A4AE)
    }
}

/** v1.8: 公共过滤匹配（正则优先，非法正则 fallback 字面匹配） */
fun matchesFilter(line: String, kw: String): Boolean {
    if (kw.isEmpty()) return true
    val pat = try { Pattern.compile(kw, Pattern.CASE_INSENSITIVE) } catch (t: Throwable) { null }
    if (pat != null) return pat.matcher(line).find()
    return line.lowercase().contains(kw.lowercase())
}

// ---------- 目标选择对话框 ----------
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun TargetPickerDialog(vm: SpyViewModel, onDismiss: () -> Unit) {
    var apps by remember { mutableStateOf<List<AppInfo>>(emptyList()) }
    var query by remember { mutableStateOf("") }
    var showManual by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    LaunchedEffect(Unit) {
        apps = withContext(Dispatchers.IO) { vm.loadApps() }
    }

    if (showManual) {
        ManualPkgDialog(vm, onDismiss = { showManual = false; onDismiss() })
        return
    }

    val filtered = if (query.isBlank()) apps else apps.filter {
        it.label.contains(query, true) || it.pkg.contains(query, true)
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("选择目标 App（${apps.size} 个）", fontWeight = FontWeight.Bold) },
        text = {
            Column {
                Text(
                    "需先在 LSPosed 模块作用域中勾选该 App",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it },
                    placeholder = { Text("搜索应用名 / 包名") },
                    singleLine = true,
                    leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                    modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp)
                )
                LazyColumn(modifier = Modifier.height(320.dp)) {
                    itemsIndexed(filtered) { _, app ->
                        Surface(
                            color = Color.Transparent,
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    vm.setTarget(app.pkg)
                                    onDismiss()
                                }
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 8.dp)
                            ) {
                                AppIcon(
                                    pkg = app.pkg,
                                    modifier = Modifier.size(36.dp).padding(end = 10.dp)
                                )
                                Column {
                                    Text(app.label, style = MaterialTheme.typography.bodyMedium)
                                    Text(
                                        app.pkg,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        fontSize = 11.sp
                                    )
                                }
                            }
                        }
                        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { showManual = true }) { Text("手输包名") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("取消") }
        }
    )
}

/** v1.12: 应用图标（懒加载 + 8MiB LRU） */
@Composable
private fun AppIcon(pkg: String, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val bmp by produceState<Bitmap?>(null, pkg) {
        value = withContext(Dispatchers.IO) { AppIconCache.get(context, pkg) }
    }
    val b = bmp
    if (b != null) {
        Image(bitmap = b.asImageBitmap(), contentDescription = null, modifier = modifier)
    } else {
        Box(
            modifier = modifier.background(
                MaterialTheme.colorScheme.surfaceVariant,
                RoundedCornerShape(6.dp)
            )
        )
    }
}

@Composable
private fun ManualPkgDialog(vm: SpyViewModel, onDismiss: () -> Unit) {
    var pkg by remember { mutableStateOf(vm.targetPkg.value) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("手输包名", fontWeight = FontWeight.Bold) },
        text = {
            Column {
                Text(
                    "请输入目标 App 包名（需先在 LSPosed 中为本模块勾选该包作用域）：",
                    style = MaterialTheme.typography.bodySmall
                )
                OutlinedTextField(
                    value = pkg,
                    onValueChange = { pkg = it },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp)
                )
            }
        },
        confirmButton = {
            TextButton(onClick = { vm.setTarget(pkg.trim()); onDismiss() }) { Text("确定") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("取消") }
        }
    )
}

// ---------- 端口对话框（v1.28 P1: 删除——手动改端口是误导：
//  server 端口由目标进程固定(9901)/scanPorts 自动发现(9901-9910)，手动设 UI 端口不会让 server 换端口） ----------

// ---------- 请求重放卡（v1.40 P1：OkHttpLogger-Frida/poker 借鉴） ----------
// 显示 OkHttpClient.newCall 缓存的请求列表，点击「重放」在目标进程重新执行（结果写日志流）。
@Composable
private fun ReplayCard(
    expanded: Boolean,
    onToggle: () -> Unit,
    items: List<ReplayEntry>,
    loading: Boolean,
    onRefresh: () -> Unit,
    onClear: () -> Unit,
    onReplay: (ReplayEntry) -> Unit,
    connected: Boolean
) {
    Card(
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer
        ),
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(12.dp))
    ) {
        Column(Modifier.fillMaxWidth()) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable(onClick = onToggle)
                    .padding(horizontal = 14.dp, vertical = 10.dp)
            ) {
                Column(Modifier.weight(1f)) {
                    Text(
                        "请求重放",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        "newCall 缓存请求 · 点击重放（GET 最可靠，POST body 可能失效）",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        fontSize = 11.sp
                    )
                }
                Box(
                    modifier = Modifier
                        .background(
                            MaterialTheme.colorScheme.primary.copy(alpha = 0.15f),
                            RoundedCornerShape(8.dp)
                        )
                        .padding(horizontal = 6.dp, vertical = 2.dp)
                ) {
                    Text(
                        "${items.size} 条",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.primary,
                        fontWeight = FontWeight.SemiBold
                    )
                }
                Spacer(Modifier.width(8.dp))
                Text(
                    if (expanded) "˄" else "˅",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 16.sp
                )
            }
            if (expanded) {
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                // 操作按钮行
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 12.dp, vertical = 6.dp)
                ) {
                    TextButton(onClick = onRefresh, enabled = !loading) { Text("刷新") }
                    Spacer(Modifier.width(4.dp))
                    TextButton(onClick = onClear) { Text("清空") }
                    Spacer(Modifier.weight(1f))
                    if (!connected) {
                        Text(
                            "未连接",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                            fontSize = 11.sp
                        )
                    }
                }
                if (loading) {
                    Text(
                        "加载中…",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp)
                    )
                } else if (items.isEmpty()) {
                    Text(
                        "暂无缓存请求。\n目标 App 发出 OkHttp 请求后自动出现在这里（需开启「OkHttp」开关）。",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp)
                    )
                } else {
                    Column(Modifier.padding(horizontal = 8.dp, vertical = 4.dp)) {
                        items.forEach { e ->
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 6.dp)
                            ) {
                                // 方法标签
                                Box(
                                    modifier = Modifier
                                        .background(
                                            methodColor(e.method),
                                            RoundedCornerShape(4.dp)
                                        )
                                        .padding(horizontal = 6.dp, vertical = 2.dp)
                                ) {
                                    Text(
                                        e.method,
                                        style = MaterialTheme.typography.labelSmall,
                                        color = Color.White,
                                        fontWeight = FontWeight.Bold
                                    )
                                }
                                Spacer(Modifier.width(8.dp))
                                Column(Modifier.weight(1f)) {
                                    Text(
                                        e.url,
                                        style = codeStyle,
                                        fontSize = 11.sp,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                    Text(
                                        "#${e.id} · ${e.timeText()}${if (e.body.isNotEmpty()) " · body ${e.body.length}B" else ""}",
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        fontSize = 10.sp
                                    )
                                }
                                Spacer(Modifier.width(8.dp))
                                OutlinedButton(
                                    onClick = { onReplay(e) },
                                    modifier = Modifier.height(30.dp)
                                ) {
                                    Text("重放", fontSize = 12.sp)
                                }
                            }
                            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f))
                        }
                    }
                }
            }
        }
    }
}

