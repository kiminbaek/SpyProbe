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
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.TabRowDefaults
import androidx.compose.material3.TabRowDefaults.tabIndicatorOffset
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.dustinky.spyprobe.ui.theme.codeStyle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

// v1.24: 探测页重做 —— Tab 切换（函数扫描 / 类加载 / 全自动探测）+ 统一卡片风格

@Composable
fun ProbeScreen(vm: SpyViewModel, modifier: Modifier = Modifier) {
    var tab by rememberSaveable { mutableIntStateOf(0) }
    val tabs = listOf("函数扫描", "类加载", "全自动")

    Column(modifier = modifier.fillMaxSize()) {
        TabRow(
            selectedTabIndex = tab,
            containerColor = MaterialTheme.colorScheme.surface,
            contentColor = MaterialTheme.colorScheme.primary,
            indicator = { tabPositions ->
                TabRowDefaults.Indicator(
                    modifier = Modifier.tabIndicatorOffset(tabPositions[tab]),
                    color = MaterialTheme.colorScheme.primary,
                    height = 2.dp
                )
            },
            divider = {
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            }
        ) {
            tabs.forEachIndexed { i, title ->
                Tab(
                    selected = tab == i,
                    onClick = { tab = i },
                    text = {
                        Text(
                            title,
                            fontWeight = if (tab == i) FontWeight.Bold else FontWeight.Medium,
                            fontSize = 13.sp,
                            color = if (tab == i) MaterialTheme.colorScheme.primary
                            else MaterialTheme.colorScheme.onSurface
                        )
                    },
                    selectedContentColor = MaterialTheme.colorScheme.primary,
                    unselectedContentColor = MaterialTheme.colorScheme.onSurface
                )
            }
        }

        when (tab) {
            0 -> FunctionScanTab(vm, Modifier.fillMaxSize())
            1 -> ClassLoadTab(vm, Modifier.fillMaxSize())
            else -> AutoProbeTab(vm, Modifier.fillMaxSize())
        }
    }
}

// ===== 函数扫描 =====
@Composable
private fun FunctionScanTab(vm: SpyViewModel, modifier: Modifier = Modifier) {
    var className by remember { mutableStateOf("") }
    var scanning by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<ScanResult?>(null) }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current

    Column(modifier = modifier.padding(horizontal = 16.dp, vertical = 12.dp)) {
        Card(
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceContainer
            ),
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(12.dp))
        ) {
            Column(Modifier.padding(14.dp)) {
                Text(
                    "输入完整类名，扫描成员后点击方法即可 hook",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.height(8.dp))
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        value = className,
                        onValueChange = { className = it },
                        placeholder = { Text("类名，如 com.example.app.Api", fontSize = 12.sp) },
                        singleLine = true,
                        modifier = Modifier.weight(1f)
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
                        Icon(Icons.Filled.Search, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(4.dp))
                        Text(if (scanning) "扫描中" else "扫描", fontSize = 12.sp)
                    }
                }
            }
        }

        val res = result
        if (res != null) {
            Spacer(Modifier.height(10.dp))
            if (!res.ok) {
                Text(res.error, color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 6.dp))
            } else {
                val mCount = res.methods.count { it.kind == "method" }
                val cCount = res.methods.count { it.kind == "constructor" }
                val fCount = res.methods.count { it.kind == "field" }

                Text(
                    res.className,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp,
                    maxLines = 1,
                    modifier = Modifier.padding(bottom = 4.dp)
                )
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp), modifier = Modifier.padding(bottom = 6.dp)) {
                    MiniBadge("方法 $mCount", MaterialTheme.colorScheme.primary)
                    MiniBadge("构造 $cCount", MaterialTheme.colorScheme.secondary)
                    MiniBadge("字段 $fCount", MaterialTheme.colorScheme.tertiary)
                }

                LazyColumn(modifier = Modifier.fillMaxWidth().weight(1f)) {
                    items(res.methods) { m ->
                        val isField = m.kind == "field"
                        Surface(
                            color = MaterialTheme.colorScheme.surfaceContainer,
                            shape = RoundedCornerShape(6.dp),
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 2.dp)
                                .clickable(enabled = !isField) {
                                    scope.launch {
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
                            Row(verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp)) {
                                KindChip(kind = m.kind)
                                Spacer(Modifier.width(6.dp))
                                Text(
                                    "${m.modifiers} ${m.signature}".trim(),
                                    style = codeStyle,
                                    maxLines = 1,
                                    modifier = Modifier.weight(1f),
                                    color = if (isField) MaterialTheme.colorScheme.onSurfaceVariant
                                    else MaterialTheme.colorScheme.onSurface
                                )
                            }
                        }
                    }
                }
            }
        } else {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.fillMaxWidth().padding(top = 80.dp)
            ) {
                Icon(
                    Icons.Filled.Search, contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(48.dp)
                )
                Spacer(Modifier.height(12.dp))
                Text(
                    "输入类名开始扫描",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    "扫描后点击方法一键 hook",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 11.sp,
                    modifier = Modifier.padding(top = 2.dp)
                )
            }
        }
    }
}

// ===== 类加载 =====
@Composable
private fun ClassLoadTab(vm: SpyViewModel, modifier: Modifier = Modifier) {
    var keyword by remember { mutableStateOf("") }
    var logAll by remember { mutableStateOf(false) }
    var resultList by remember { mutableStateOf<List<String>?>(null) }
    var resultMeta by remember { mutableStateOf("") }
    var loading by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    Column(modifier = modifier.padding(horizontal = 16.dp, vertical = 12.dp)) {
        Card(
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceContainer
            ),
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(12.dp))
        ) {
            Column(Modifier.padding(14.dp)) {
                Text(
                    "ClassLoader.loadClass 查询",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    "找接口 / 网络 / 关键业务类",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 2.dp, bottom = 8.dp)
                )
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        value = keyword,
                        onValueChange = { keyword = it },
                        placeholder = { Text("类名关键字，如 api / network", fontSize = 12.sp) },
                        singleLine = true,
                        modifier = Modifier.weight(1f)
                    )
                    Button(
                        onClick = {
                            loading = true
                            resultList = null
                            resultMeta = ""
                            scope.launch {
                                val r = withContext(Dispatchers.IO) { vm.api.queryClasses(keyword.trim(), logAll) }
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
                    ) { Text(if (loading) "查询中" else "查询", fontSize = 12.sp) }
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = logAll, onCheckedChange = { logAll = it })
                    Text("匹配的类刷屏到日志", style = MaterialTheme.typography.bodySmall, fontSize = 12.sp)
                }
            }
        }

        val rl = resultList
        if (rl != null) {
            Spacer(Modifier.height(8.dp))
            Text(
                resultMeta,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontSize = 11.sp,
                modifier = Modifier.padding(bottom = 4.dp)
            )
            LazyColumn(modifier = Modifier.fillMaxWidth().weight(1f)) {
                items(rl) { c ->
                    Text(c, style = codeStyle, modifier = Modifier.padding(vertical = 1.dp))
                }
            }
        } else {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.fillMaxWidth().padding(top = 80.dp)
            ) {
                Icon(
                    Icons.Filled.Search, contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(48.dp)
                )
                Spacer(Modifier.height(12.dp))
                Text(
                    "查询已加载的类",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    "支持关键字过滤",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 11.sp,
                    modifier = Modifier.padding(top = 2.dp)
                )
            }
        }
    }
}

// ===== 全自动探测 =====
@Composable
private fun AutoProbeTab(vm: SpyViewModel, modifier: Modifier = Modifier) {
    var autoProbe by remember { mutableStateOf(false) }
    var autoFilter by remember { mutableStateOf("") }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val targetPkg by vm.targetPkg.collectAsState()

    // v1.25 P2-6: 从配置库读取（本地权威），不再依赖远程 fetchConfig（未连接时也能显示真实生效值）
    LaunchedEffect(Unit, targetPkg) {
        val c = vm.effectiveConfig(targetPkg)
        autoProbe = c["autoProbe"] as? Boolean ?: false
        autoFilter = c["autoProbeFilter"] as? String ?: ""
    }

    Column(modifier = modifier.padding(horizontal = 16.dp, vertical = 12.dp)) {
        Card(
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceContainer
            ),
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(12.dp))
        ) {
            Column(Modifier.padding(14.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Switch(checked = autoProbe, onCheckedChange = { v ->
                        autoProbe = v
                        // v1.25 P0-2: 统一配置入口（保存本地覆盖层 + 推送；未连接也保存，连接后自动生效）
                        val ok = vm.setEffectiveSwitch("autoProbe", v)
                        if (!ok) {
                            android.widget.Toast.makeText(context, "未连接，已保存本地", android.widget.Toast.LENGTH_SHORT).show()
                        }
                    })
                    Spacer(Modifier.width(8.dp))
                    Column(Modifier.weight(1f)) {
                        Text("全自动探测", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                        Text(
                            "类加载时自动 hook 该类全部方法",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            fontSize = 11.sp
                        )
                    }
                }
                HorizontalDivider(modifier = Modifier.padding(vertical = 10.dp), color = MaterialTheme.colorScheme.outlineVariant)
                Text(
                    "过滤关键字（空 = 所有非系统类）",
                    style = MaterialTheme.typography.bodySmall,
                    fontWeight = FontWeight.Medium
                )
                Spacer(Modifier.height(6.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        value = autoFilter,
                        onValueChange = { autoFilter = it },
                        placeholder = { Text("如 api / network / util", fontSize = 12.sp) },
                        singleLine = true,
                        enabled = autoProbe,
                        modifier = Modifier.weight(1f)
                    )
                    Button(
                        onClick = {
                            // v1.25 P0-2: 统一配置入口
                            val ok = vm.setEffectiveSwitch("autoProbeFilter", autoFilter.trim())
                            android.widget.Toast.makeText(context,
                                if (ok) "已应用" else "未连接，已保存本地", android.widget.Toast.LENGTH_SHORT).show()
                        },
                        enabled = autoProbe
                    ) { Text("应用", fontSize = 12.sp) }
                }
                Spacer(Modifier.height(8.dp))
                Text(
                    "⚠ 跳过系统类/接口/Object 方法；开启后日志量可能激增",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.tertiary,
                    fontSize = 11.sp
                )
            }
        }

        Spacer(Modifier.height(12.dp))

        // 使用提示卡
        Card(
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceContainerLow
            ),
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(12.dp))
        ) {
            Column(Modifier.padding(14.dp)) {
                Text(
                    "💡 使用提示",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.secondary
                )
                Spacer(Modifier.height(6.dp))
                Text(
                    "• 过滤关键字建议用包名特征（如 network/api/request）\n" +
                    "• 每次冷启动目标 App 后重新加载类会生效\n" +
                    "• 建议先在「类加载」Tab 搜索确认类名再开全自动\n" +
                    "• 日志量过大时关掉总开关或收紧过滤条件",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 11.sp,
                    lineHeight = 16.sp
                )
            }
        }
    }
}

// ===== 小组件 =====
@Composable
private fun MiniBadge(text: String, color: androidx.compose.ui.graphics.Color) {
    Box(
        modifier = Modifier
            .background(color.copy(alpha = 0.15f), RoundedCornerShape(6.dp))
            .padding(horizontal = 8.dp, vertical = 3.dp)
    ) {
        Text(text, style = MaterialTheme.typography.labelSmall, color = color,
            fontWeight = FontWeight.SemiBold, fontSize = 10.sp)
    }
}

@Composable
private fun KindChip(kind: String) {
    val (bg, fg, label) = when (kind) {
        "method" -> Triple(
            MaterialTheme.colorScheme.primary.copy(alpha = 0.15f),
            MaterialTheme.colorScheme.primary, "方法"
        )
        "constructor" -> Triple(
            MaterialTheme.colorScheme.secondary.copy(alpha = 0.15f),
            MaterialTheme.colorScheme.secondary, "构造"
        )
        else -> Triple(
            MaterialTheme.colorScheme.tertiary.copy(alpha = 0.15f),
            MaterialTheme.colorScheme.tertiary, "字段"
        )
    }
    Box(
        modifier = Modifier
            .background(bg, RoundedCornerShape(4.dp))
            .padding(horizontal = 6.dp, vertical = 2.dp)
    ) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = fg,
            fontWeight = FontWeight.Medium, fontSize = 9.sp)
    }
}
