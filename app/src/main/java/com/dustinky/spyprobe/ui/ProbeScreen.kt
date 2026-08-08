package com.dustinky.spyprobe.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
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
// v1.17: 卡片化重构（两个功能各一个卡片，视觉分组清晰）

@Composable
fun ProbeScreen(vm: SpyViewModel, modifier: Modifier = Modifier) {
    // v1.16 P2-16: 顶部标题由 TopAppBar 统一提供，此处不再重复
    Column(modifier = modifier.fillMaxSize().padding(horizontal = 12.dp)) {
        FunctionScanCard(vm)
        Spacer(Modifier.height(10.dp))
        ClassLoadCard(vm)
    }
}

// ---------- 函数扫描 ----------
// v1.16 P2-15: ColumnScope 扩展 —— 扫描结果 LazyColumn 用 weight(1f) 撑满剩余空间（不再固定 260dp）
@Composable
private fun androidx.compose.foundation.layout.ColumnScope.FunctionScanCard(vm: SpyViewModel) {
    var className by remember { mutableStateOf("") }
    var scanning by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<ScanResult?>(null) }
    var methodPickerOpen by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current

    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerHigh),
        modifier = Modifier.fillMaxWidth().padding(top = 8.dp)
    ) {
        Column(Modifier.padding(12.dp)) {
            Text("函数扫描", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
            Text("输入完整类名，扫描成员后点击方法即可 hook（构造器自动识别）",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(bottom = 6.dp))

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
                    LazyColumn(modifier = Modifier.heightIn(max = 260.dp)) {
                        items(res.methods) { m ->
                            Surface(
                                color = MaterialTheme.colorScheme.surfaceContainerHighest.copy(alpha = 0.6f),
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 2.dp)
                                    .clickable {
                                        scope.launch {
                                            // v1.15 P1-5: 传 m.kind —— 构造器走 "<init>" 分支
                                            val resp = withContext(Dispatchers.IO) {
                                                vm.api.hook(res.className, m.signature, m.params, m.kind)
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
                                Column(Modifier.padding(horizontal = 10.dp, vertical = 6.dp)) {
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
    }
}

// ---------- 类加载记录 ----------
@Composable
private fun ClassLoadCard(vm: SpyViewModel) {
    var keyword by remember { mutableStateOf("") }
    var logAll by remember { mutableStateOf(false) }
    // v1.16 P1-10: 结果从拼字符串 Text 一次性渲染 → LazyColumn 逐行（2000 行不再卡顿）
    var resultList by remember { mutableStateOf<List<String>?>(null) }
    var resultMeta by remember { mutableStateOf("") }
    var loading by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerHigh),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(Modifier.padding(12.dp)) {
            Text("类加载记录", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
            Text("ClassLoader.loadClass 查询 —— 找接口 / 网络 / 关键业务类",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(bottom = 6.dp))
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
                        resultList = null
                        resultMeta = ""
                        val kw = keyword.trim()
                        val la = logAll
                        scope.launch {
                            val r = withContext(Dispatchers.IO) { vm.api.queryClasses(kw, la) }
                            loading = false
                            if (r == null) {
                                resultMeta = "未连接"
                                resultList = emptyList()
                            } else {
                                val (count, total, classes) = r
                                resultMeta = "共 $total 个类，匹配 $count 个" +
                                        (if (classes.size > 2000) "（仅显示前 2000 个）" else "")
                                resultList = classes.take(2000)
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
            val rl = resultList
            if (rl != null) {
                Text(resultMeta, style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(vertical = 2.dp))
                LazyColumn(modifier = Modifier.fillMaxWidth().heightIn(max = 220.dp)) {
                    items(rl) { c ->
                        Text(c, style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace, fontSize = 10.sp,
                            modifier = Modifier.padding(vertical = 1.dp))
                    }
                }
            }
        }
    }
}
