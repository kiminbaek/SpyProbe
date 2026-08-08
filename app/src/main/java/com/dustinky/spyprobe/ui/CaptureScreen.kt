package com.dustinky.spyprobe.ui

import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
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
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.List
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.regex.Pattern

// v1.18: 抓包页 —— 目标/端口/状态/记录开关 + 日志入口（日志流已移到独立 LogsScreen）
// v1.11: 原抓包页含过滤 + LazyColumn 日志流

@Composable
fun CaptureScreen(vm: SpyViewModel, onOpenLogs: () -> Unit, modifier: Modifier = Modifier) {
    val target by vm.targetPkg.collectAsState()
    val port by vm.port.collectAsState()
    val status by vm.status.collectAsState()
    val connected by vm.connected.collectAsState()
    val logCount by vm.logCount.collectAsState()

    // v1.15 P0-3: 后端配置快照（开关从后端真实值初始化，不再硬编码默认）
    var cfg by remember { mutableStateOf<Map<String, Any>>(emptyMap()) }

    // v1.18.1: 轮询已移到 ViewModel init 常驻，页面不再 start/stop（否则切页会停掉日志更新）
    LaunchedEffect(Unit) {
        vm.refreshStatus()
        val c = withContext(Dispatchers.IO) { vm.api.fetchConfig() }
        if (c != null) cfg = c
    }

    Column(modifier = modifier.fillMaxSize().padding(horizontal = 12.dp)) {
        // v1.16 P2-16: 顶部大标题由 TopAppBar 统一提供，此处删除（控制台版本信息保留在设置页关于）

        // ===== 状态卡片（v1.17: 连接状态 + 目标 + 端口 合一卡片） =====
        Card(
            colors = CardDefaults.cardColors(
                containerColor = if (connected)
                    MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.3f)
                else
                    MaterialTheme.colorScheme.surfaceContainerHigh
            ),
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp)
        ) {
            Column(Modifier.padding(12.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(8.dp)
                            .background(
                                if (connected) Color(0xFF4CAF50) else Color(0xFFEF5350),
                                RoundedCornerShape(4.dp)
                            )
                    )
                    Spacer(Modifier.width(6.dp))
                    Text(
                        status,
                        style = MaterialTheme.typography.bodySmall,
                        color = if (connected) MaterialTheme.colorScheme.onSurface
                        else MaterialTheme.colorScheme.tertiary,
                        modifier = Modifier.weight(1f)
                    )
                }
                Spacer(Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    var showPicker by remember { mutableStateOf(false) }
                    OutlinedButton(
                        onClick = { showPicker = true },
                        modifier = Modifier.weight(1.6f)
                    ) {
                        Icon(Icons.Filled.Search, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(4.dp))
                        Text(if (target.isEmpty()) "选择目标 App" else target, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                    var showPortDialog by remember { mutableStateOf(false) }
                    OutlinedButton(onClick = { showPortDialog = true }, modifier = Modifier.weight(1f)) {
                        Text("端口:$port")
                    }
                    if (showPicker) {
                        TargetPickerDialog(vm, onDismiss = { showPicker = false })
                    }
                    if (showPortDialog) {
                        PortDialog(vm, currentPort = port, onDismiss = { showPortDialog = false })
                    }
                }
            }
        }

        // ===== 记录开关卡片（v1.17: 分组卡片） =====
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerHigh),
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp)
        ) {
            Column(Modifier.padding(horizontal = 12.dp, vertical = 6.dp)) {
                Text("记录开关", style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(bottom = 2.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    SwitchItem("SSL绕过", cfg["sslBypass"] as? Boolean ?: true) { vm.sendConfig(mapOf("sslBypass" to it)); cfg = cfg + ("sslBypass" to it) }
                    SwitchItem("OkHttp", cfg["okhttp"] as? Boolean ?: true) { vm.sendConfig(mapOf("okhttp" to it)); cfg = cfg + ("okhttp" to it) }
                    SwitchItem("URLConn", cfg["url"] as? Boolean ?: true) { vm.sendConfig(mapOf("url" to it)); cfg = cfg + ("url" to it) }
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    SwitchItem("DNS解析", cfg["dns"] as? Boolean ?: true) { vm.sendConfig(mapOf("dns" to it)); cfg = cfg + ("dns" to it) }
                    SwitchItem("TCP连接", cfg["tcp"] as? Boolean ?: true) { vm.sendConfig(mapOf("tcp" to it)); cfg = cfg + ("tcp" to it) }
                    SwitchItem("类加载", cfg["classes"] as? Boolean ?: true) { vm.sendConfig(mapOf("classes" to it)); cfg = cfg + ("classes" to it) }
                }
            }
        }

        HorizontalDivider(modifier = Modifier.padding(vertical = 6.dp))

        // ===== 日志入口卡片（v1.18: 日志流已独立成第 5 Tab，抓包页只留入口） =====
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerHigh),
            modifier = Modifier.fillMaxWidth().padding(top = 4.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth().clickable(onClick = onOpenLogs).padding(horizontal = 12.dp, vertical = 12.dp)
            ) {
                Icon(Icons.Filled.List, contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(20.dp))
                Spacer(Modifier.width(10.dp))
                Column(Modifier.weight(1f)) {
                    Text("查看日志", style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Bold)
                    Text("已记录 $logCount 条", style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Text("›", style = MaterialTheme.typography.titleLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

// v1.15 P0-3: SwitchItem 改为受控组件（checked 由外部传入，onChange 同时更新下发+本地快照）
// v1.16 P1-8: Checkbox → M3 Switch（语义是开关，观感统一）
@Composable
private fun androidx.compose.foundation.layout.RowScope.SwitchItem(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
        Switch(checked = checked, onCheckedChange = { onChange(it) })
        Text(label, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(start = 4.dp))
    }
}

// 过滤快捷短语（v1.16 P2-11: FilterChip 选中态判断用；v1.18 internal 供 LogsScreen 引用）
internal const val NET_FILTER = "(Net|DNS|TCP|HUC|OkHttp|SSL)"
internal const val MTH_FILTER = "(Mth)"

/** v1.16 P2-9: 日志按 tag 类型着色（网络绿/函数蓝/规则橙/反检测紫/数据橙黄/环境粉/失败红/其它灰） */
internal fun logColor(line: String): Color {
    return when {
        line.startsWith("[TCP] FAIL") -> Color(0xFFEF5350)
        line.startsWith("[Net") || line.startsWith("[DNS") || line.startsWith("[TCP") ||
                line.startsWith("[SSL") || line.startsWith("[HUC") || line.startsWith("[OkHttp") ||
                line.startsWith("[Cronet") -> Color(0xFF4CAF50)
        line.startsWith("[Mth") || line.startsWith("[Cls") -> Color(0xFF42A5F5)
        line.startsWith("[RULE") -> Color(0xFFFF7043)
        line.startsWith("[anti") -> Color(0xFFAB47BC)
        line.startsWith("[SQL") || line.startsWith("[JSON") || line.startsWith("[Gson") -> Color(0xFFFFA726)
        line.startsWith("[VPN") || line.startsWith("[属性") || line.startsWith("[传感器") ||
                line.startsWith("[防截屏") || line.startsWith("[IMEI") || line.startsWith("[设备") -> Color(0xFFEC407A)
        line.startsWith("[") -> Color(0xFFBDBDBD)
        else -> Color(0xFF9E9E9E)
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
        title = { Text("选择目标 App（${apps.size} 个）") },
        text = {
            Column {
                Text("需先在 LSPosed 模块作用域中勾选该 App", style = MaterialTheme.typography.bodySmall)
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it },
                    placeholder = { Text("搜索应用名 / 包名") },
                    singleLine = true,
                    leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                    modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp)
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
                            // v1.12: 应用图标（懒加载 + 8MiB LRU）
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
                                    Text(app.pkg, style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                                }
                            }
                        }
                        HorizontalDivider()
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

/** v1.12: 应用图标（懒加载 + 8MiB LRU）；未加载完成显示占位块，加载失败也显示占位块 */
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
        androidx.compose.foundation.layout.Box(
            modifier = modifier.background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(6.dp))
        )
    }
}

@Composable
private fun ManualPkgDialog(vm: SpyViewModel, onDismiss: () -> Unit) {
    var pkg by remember { mutableStateOf(vm.targetPkg.value) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("手输包名") },
        text = {
            Column {
                Text("请输入目标 App 包名（需先在 LSPosed 中为本模块勾选该包作用域）：",
                    style = MaterialTheme.typography.bodySmall)
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

// ---------- 端口对话框 ----------
@Composable
private fun PortDialog(vm: SpyViewModel, currentPort: Int, onDismiss: () -> Unit) {
    var portText by remember { mutableStateOf(currentPort.toString()) }
    val context = LocalContext.current
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Server 端口（默认 9901）") },
        text = {
            OutlinedTextField(
                value = portText,
                onValueChange = { portText = it },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.fillMaxWidth()
            )
        },
        confirmButton = {
            TextButton(onClick = {
                val p = portText.trim().toIntOrNull()
                if (p != null) {
                    vm.setPort(p)
                    android.widget.Toast.makeText(context, "端口已改，需重启目标 App 生效", android.widget.Toast.LENGTH_SHORT).show()
                }
                onDismiss()
            }) { Text("确定") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("取消") }
        }
    )
}
