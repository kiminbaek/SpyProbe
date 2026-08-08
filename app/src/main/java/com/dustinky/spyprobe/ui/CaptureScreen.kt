package com.dustinky.spyprobe.ui

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
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
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.dustinky.spyprobe.BuildConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.nio.charset.StandardCharsets
import java.util.regex.Pattern

// v1.11: 抓包页 —— 目标/端口/状态/开关/过滤 + LazyColumn 日志流

@Composable
fun CaptureScreen(vm: SpyViewModel, modifier: Modifier = Modifier) {
    val target by vm.targetPkg.collectAsState()
    val port by vm.port.collectAsState()
    val status by vm.status.collectAsState()
    val connected by vm.connected.collectAsState()
    val logLines by vm.logLines.collectAsState()
    val filter by vm.filter.collectAsState()

    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    // 生命周期轮询
    LaunchedEffect(Unit) {
        vm.startPolling()
        vm.refreshStatus()
    }
    androidx.compose.runtime.DisposableEffect(Unit) {
        onDispose { vm.stopPolling() }
    }

    // SAF 导出
    var exportText by remember { mutableStateOf<String?>(null) }
    val exportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/plain")
    ) { uri: Uri? ->
        val text = exportText
        if (uri != null && text != null) {
            scope.launch {
                withContext(Dispatchers.IO) {
                    runCatching {
                        val os = context.contentResolver.openOutputStream(uri)
                        if (os != null) {
                            os.write(text.toByteArray(StandardCharsets.UTF_8))
                            os.flush()
                            os.close()
                        }
                    }
                }
            }
        }
        exportText = null
    }

    Column(modifier = modifier.fillMaxSize().padding(horizontal = 12.dp)) {
        // 标题
        Text(
            "SpyProbe 逆向探测控制台 v${BuildConfig.VERSION_NAME}",
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(top = 10.dp, bottom = 4.dp)
        )

        // 目标 + 端口行
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            var showPicker by remember { mutableStateOf(false) }
            Button(
                onClick = { showPicker = true },
                modifier = Modifier.weight(1.6f)
            ) {
                Text(if (target.isEmpty()) "选择目标 App" else target, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            var showPortDialog by remember { mutableStateOf(false) }
            Button(onClick = { showPortDialog = true }, modifier = Modifier.weight(1f)) {
                Text("端口:$port")
            }
            if (showPicker) {
                TargetPickerDialog(vm, onDismiss = { showPicker = false })
            }
            if (showPortDialog) {
                PortDialog(vm, currentPort = port, onDismiss = { showPortDialog = false })
            }
        }

        // 状态
        Text(
            status,
            style = MaterialTheme.typography.bodySmall,
            color = if (connected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.tertiary,
            modifier = Modifier.padding(vertical = 6.dp)
        )

        // 开关行 1
        Row(verticalAlignment = Alignment.CenterVertically) {
            SwitchItem("SSL绕过", true) { vm.sendConfig(mapOf("sslBypass" to it)) }
            SwitchItem("OkHttp", true) { vm.sendConfig(mapOf("okhttp" to it)) }
            SwitchItem("URLConn", true) { vm.sendConfig(mapOf("url" to it)) }
        }
        // 开关行 2
        Row(verticalAlignment = Alignment.CenterVertically) {
            SwitchItem("DNS解析", true) { vm.sendConfig(mapOf("dns" to it)) }
            SwitchItem("TCP连接", true) { vm.sendConfig(mapOf("tcp" to it)) }
            SwitchItem("类加载", true) { vm.sendConfig(mapOf("classes" to it)) }
        }

        HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))

        // 过滤行
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            OutlinedTextField(
                value = filter,
                onValueChange = { vm.setFilter(it) },
                placeholder = { Text("过滤 /api/ Token") },
                singleLine = true,
                textStyle = MaterialTheme.typography.bodySmall,
                modifier = Modifier.weight(2f).height(48.dp)
            )
            FilterChip(selected = false, onClick = { vm.setFilter("(Net|DNS|TCP|HUC|OkHttp|SSL)") }, label = { Text("网络") })
            FilterChip(selected = false, onClick = { vm.setFilter("(Mth)") }, label = { Text("函数") })
            FilterChip(selected = false, onClick = { vm.setFilter("") }, label = { Text("全部") })
        }

        // 操作行：清空 / 导出
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(vertical = 6.dp)) {
            Button(onClick = { vm.clearLogs() }, modifier = Modifier.weight(1f)) {
                Icon(Icons.Filled.Delete, contentDescription = null)
                Spacer(Modifier.width(4.dp))
                Text("清空")
            }
            Button(onClick = {
                scope.launch {
                    val resp = withContext(Dispatchers.IO) { vm.api.export() }
                    if (resp == null) return@launch
                    val text = runCatching {
                        val o = org.json.JSONObject(resp)
                        var t = o.optString("text", "")
                        val kw = vm.filter.value.trim()
                        if (kw.isNotEmpty()) {
                            t = t.split("\n").filter { matchesFilter(it, kw) }.joinToString("\n")
                        }
                        t
                    }.getOrDefault("")
                    exportText = text
                    exportLauncher.launch("SpyProbe_${System.currentTimeMillis()}.log")
                }
            }, modifier = Modifier.weight(1f)) {
                Icon(Icons.Filled.Share, contentDescription = null)
                Spacer(Modifier.width(4.dp))
                Text("导出")
            }
        }

        // 日志流
        val listState = rememberLazyListState()
        LaunchedEffect(logLines.size) {
            if (logLines.isNotEmpty()) listState.animateScrollToItem(logLines.size - 1)
        }
        LazyColumn(
            state = listState,
            modifier = Modifier.fillMaxSize()
        ) {
            val kw = filter.trim()
            val shown = if (kw.isEmpty()) logLines else logLines.filter { matchesFilter(it, kw) }
            itemsIndexed(shown, key = { i, _ -> i }) { _, line ->
                Text(
                    line,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.padding(vertical = 1.dp)
                )
            }
        }
    }
}

@Composable
private fun androidx.compose.foundation.layout.RowScope.SwitchItem(label: String, default: Boolean, onChange: (Boolean) -> Unit) {
    var checked by remember { mutableStateOf(default) }
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
        Checkbox(checked = checked, onCheckedChange = { checked = it; onChange(it) })
        Text(label, style = MaterialTheme.typography.bodySmall)
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
                            Column(Modifier.padding(horizontal = 8.dp, vertical = 8.dp)) {
                                Text(app.label, style = MaterialTheme.typography.bodyMedium)
                                Text(app.pkg, style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant)
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
