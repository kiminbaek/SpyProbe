package com.dustinky.spyprobe.ui

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
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

// v1.11: 探测页 —— 函数扫描 + hook + 类加载记录查询

@Composable
fun ProbeScreen(vm: SpyViewModel, modifier: Modifier = Modifier) {
    Column(modifier = modifier.fillMaxSize().padding(horizontal = 12.dp)) {
        Text("函数探测", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(top = 10.dp, bottom = 6.dp))

        FunctionScanCard(vm)
        HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
        ClassLoadCard(vm)
    }
}

// ---------- 函数扫描 ----------
@Composable
private fun FunctionScanCard(vm: SpyViewModel) {
    var className by remember { mutableStateOf("") }
    var scanning by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<ScanResult?>(null) }
    var methodPickerOpen by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current

    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedTextField(
            value = className,
            onValueChange = { className = it },
            placeholder = { Text("类名，如 com.example.app.Api") },
            singleLine = true,
            modifier = Modifier.weight(1f).height(52.dp)
        )
        Button(
            onClick = {
                val cls = className.trim()
                if (cls.isEmpty()) return@Button
                scanning = true
                result = null
                scope.launch {
                    val r = withContext(Dispatchers.IO) { vm.api.scanClass(cls) }
                    result = r
                    scanning = false
                }
            },
            enabled = !scanning
        ) {
            Icon(Icons.Filled.Search, contentDescription = null)
            Spacer(Modifier.width(4.dp))
            Text(if (scanning) "扫描中" else "扫描")
        }
    }

    val res = result
    if (res != null) {
        if (!res.ok) {
            Text(res.error, color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 6.dp))
        } else {
            Text(
                "类 ${res.className} 共 ${res.methods.size} 个成员（点击方法 hook；字段为只读探测）",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 6.dp, bottom = 2.dp)
            )
            LazyColumn(modifier = Modifier.height(260.dp)) {
                items(res.methods) { m ->
                    Surface(
                        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f),
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 1.dp)
                            .clickable {
                                scope.launch {
                                    val resp = withContext(Dispatchers.IO) {
                                        vm.api.hook(res.className, m.signature, m.params)
                                    }
                                    val msg = if (resp == null) "未连接" else {
                                        try {
                                            val o = org.json.JSONObject(resp)
                                            "hook ${o.optInt("hooked", 0)} 个: ${o.optString("note", resp)}"
                                        } catch (t: Throwable) { resp }
                                    }
                                    android.widget.Toast.makeText(context, msg, android.widget.Toast.LENGTH_LONG).show()
                                }
                            }
                    ) {
                        Column(Modifier.padding(horizontal = 8.dp, vertical = 6.dp)) {
                            Text(
                                "[${m.kind}] ${m.modifiers} ${m.signature}".trim(),
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 11.sp
                            )
                        }
                    }
                }
            }
        }
    }
}

// ---------- 类加载记录 ----------
@Composable
private fun ClassLoadCard(vm: SpyViewModel) {
    var keyword by remember { mutableStateOf("") }
    var logAll by remember { mutableStateOf(false) }
    var resultText by remember { mutableStateOf<String?>(null) }
    var loading by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    Text("类加载记录（ClassLoader.loadClass）", style = MaterialTheme.typography.titleSmall,
        modifier = Modifier.padding(bottom = 4.dp))
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedTextField(
            value = keyword,
            onValueChange = { keyword = it },
            placeholder = { Text("类名关键字，如 api / network") },
            singleLine = true,
            modifier = Modifier.weight(1f).height(52.dp)
        )
        Button(
            onClick = {
                loading = true
                resultText = null
                val kw = keyword.trim()
                val la = logAll
                scope.launch {
                    val r = withContext(Dispatchers.IO) { vm.api.queryClasses(kw, la) }
                    loading = false
                    if (r == null) {
                        resultText = "未连接"
                    } else {
                        val (count, total, classes) = r
                        val sb = StringBuilder("共 $total 个类，匹配 $count 个：\n\n")
                        classes.take(2000).forEach { sb.append(it).append('\n') }
                        if (classes.size > 2000) sb.append("... 仅显示前 2000 个\n")
                        resultText = sb.toString()
                    }
                }
            },
            enabled = !loading
        ) { Text(if (loading) "查询中" else "查询") }
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = logAll, onCheckedChange = { logAll = it })
        Text("匹配的类刷屏到日志", style = MaterialTheme.typography.bodySmall)
    }
    val rt = resultText
    if (rt != null) {
        Text(
            rt,
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            fontSize = 10.sp,
            modifier = Modifier
                .fillMaxWidth()
                .height(220.dp)
        )
    }
}
