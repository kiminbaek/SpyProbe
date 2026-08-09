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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.TabRowDefaults
import androidx.compose.material3.TabRowDefaults.tabIndicatorOffset
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

// v1.24.1: 设置页两级配置架构（全局默认 / 当前App覆盖）+ 未连接 banner + 卡片边框
// v1.24: 设置页重做 —— 可折叠分组卡片，按类别组织，信息密度提升
// v1.12: 日志容量可配置
// v1.13: 反检测 13 项开关
// v1.14: 3 记录模式开关 + 随机返回值
// v1.16: 重新读取配置 + 通配符
// v1.17: DexKit + 关于

@Composable
fun SettingsScreen(vm: SpyViewModel, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val targetPkg by vm.targetPkg.collectAsState()

    // 0 = 全局默认, 1 = 当前 App 覆盖
    var cfgLevel by remember { mutableIntStateOf(0) }
    val levelLabels = listOf("全局默认", "当前 App")

    // 当前级别的配置（全局=default+global覆盖；当前App=该App覆盖项）
    var displayCfg by remember { mutableStateOf<Map<String, Any>>(emptyMap()) }
    // 全局配置（用于"当前 App" Tab 对比哪些是覆盖项）
    var globalCfg by remember { mutableStateOf<Map<String, Any>>(emptyMap()) }
    // 是否从目标 App 拉取了实时配置
    var remoteCfg by remember { mutableStateOf<Map<String, Any>?>(null) }
    var loading by remember { mutableStateOf(true) }

    fun reload() {
        loading = true
        scope.launch {
            val g = withContext(Dispatchers.IO) { vm.loadGlobalConfig() }
            globalCfg = g
            val r = withContext(Dispatchers.IO) { vm.api.fetchConfig() }
            remoteCfg = r
            displayCfg = if (cfgLevel == 0) g
            else withContext(Dispatchers.IO) { vm.loadAppConfig(targetPkg) }
            loading = false
        }
    }

    LaunchedEffect(Unit) { reload() }

    // 切换级别时重新加载 displayCfg
    LaunchedEffect(cfgLevel, targetPkg) {
        if (loading) return@LaunchedEffect
        displayCfg = if (cfgLevel == 0) globalCfg
        else withContext(Dispatchers.IO) { vm.loadAppConfig(targetPkg) }
    }

    fun setCfg(key: String, value: Any) {
        displayCfg = displayCfg + (key to value)
        scope.launch {
            withContext(Dispatchers.IO) {
                if (cfgLevel == 0) {
                    // 全局：保存 + 推送到当前连接的 App（如果有）
                    vm.saveGlobalConfig(displayCfg)
                    if (targetPkg.isNotEmpty()) vm.pushConfig(targetPkg)
                } else {
                    // 当前 App 覆盖：保存覆盖项 + 推送
                    vm.saveAppConfig(targetPkg, displayCfg)
                    if (targetPkg.isNotEmpty()) vm.pushConfig(targetPkg)
                }
            }
        }
    }

    // 重置当前 App 覆盖（仅在"当前 App" Tab 有意义）
    fun resetAppOverrides() {
        scope.launch {
            withContext(Dispatchers.IO) { vm.saveAppConfig(targetPkg, emptyMap()) }
            displayCfg = emptyMap()
            android.widget.Toast.makeText(context, "已重置为全局默认", android.widget.Toast.LENGTH_SHORT).show()
        }
    }

    // 分组折叠状态
    var expanded by remember { mutableStateOf(setOf("basic")) }

    fun toggle(key: String) {
        expanded = if (expanded.contains(key))
            expanded - key
        else
            expanded + key
    }

    // 显示用：当前 Tab 的配置值（全局用 displayCfg，当前 App 用 effectiveConfig）
    val effective: Map<String, Any> = if (cfgLevel == 0) displayCfg
    else globalCfg + displayCfg

    // v1.25 P2-2: 「当前 App」Tab 中未覆盖的项显示"继承全局默认"标记
    // （cfgLevel==0 全局 Tab 恒为 false；cfgLevel==1 时 displayCfg 是该 App 覆盖项，不在其中=继承）
    fun inh(key: String): Boolean = cfgLevel == 1 && !displayCfg.containsKey(key)

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
    ) {

        // ===== 顶部：两级切换 Tab =====
        TabRow(
            selectedTabIndex = cfgLevel,
            containerColor = MaterialTheme.colorScheme.surface,
            contentColor = MaterialTheme.colorScheme.primary,
            indicator = { tabPositions ->
                TabRowDefaults.Indicator(
                    modifier = Modifier.tabIndicatorOffset(tabPositions[cfgLevel]),
                    color = MaterialTheme.colorScheme.primary,
                    height = 2.dp
                )
            },
            divider = { HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant) }
        ) {
            levelLabels.forEachIndexed { i, label ->
                Tab(
                    selected = cfgLevel == i,
                    onClick = { cfgLevel = i },
                    text = {
                        Text(
                            label,
                            fontWeight = if (cfgLevel == i) FontWeight.Bold else FontWeight.Medium,
                            fontSize = 13.sp,
                            color = if (cfgLevel == i) MaterialTheme.colorScheme.primary
                            else MaterialTheme.colorScheme.onSurface
                        )
                    },
                    selectedContentColor = MaterialTheme.colorScheme.primary,
                    unselectedContentColor = MaterialTheme.colorScheme.onSurface
                )
            }
        }

        Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {

            // 当前级说明
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(
                        if (cfgLevel == 0) "全局默认配置" else "${targetPkg.ifEmpty { "未选择目标" }}",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        fontSize = 14.sp
                    )
                    Text(
                        when {
                            cfgLevel == 0 -> "所有 App 的默认值，未单独覆盖的 App 继承此配置"
                            targetPkg.isEmpty() -> "请先在抓包页选择目标 App"
                            displayCfg.isEmpty() -> "当前 App 完全继承全局默认"
                            else -> "已覆盖 ${displayCfg.size} 项，其余继承全局"
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        fontSize = 11.sp
                    )
                }
                TextButton(onClick = { reload() }, enabled = !loading) {
                    Text("↻ 重新读取", fontSize = 12.sp)
                }
                if (cfgLevel == 1 && targetPkg.isNotEmpty() && displayCfg.isNotEmpty()) {
                    TextButton(onClick = { resetAppOverrides() }) {
                        Text("重置", fontSize = 12.sp, color = MaterialTheme.colorScheme.error)
                    }
                }
            }

            Spacer(Modifier.height(6.dp))

            // 未连接 banner
            if (remoteCfg == null) {
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.3f)
                    ),
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 4.dp)
                        .border(
                            1.dp,
                            MaterialTheme.colorScheme.error.copy(alpha = 0.4f),
                            RoundedCornerShape(10.dp)
                        )
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp)
                    ) {
                        Text("🔒", fontSize = 18.sp)
                        Spacer(Modifier.width(8.dp))
                        Column(Modifier.weight(1f)) {
                            Text(
                                "未连接到目标 App",
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.SemiBold,
                                color = MaterialTheme.colorScheme.error
                            )
                            Text(
                                "修改保存在本地，连接后自动生效",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                fontSize = 11.sp
                            )
                        }
                    }
                }
            }

        // ===== 通用设置 =====
        SettingsGroup(
            title = "通用",
            subtitle = "日志 / 抓包基础",
            expanded = expanded.contains("basic"),
            onToggle = { toggle("basic") }
        ) {
            IntSetting(effective, "logLimit", "日志上限(条)", 4096, 100..20000,
                inherited = inh("logLimit"),
                onSet = { setCfg("logLimit", it) })
            Divider()
            IntSetting(effective, "bodyLimit", "Body 限制(KB)", 2, 1..1024,
                inherited = inh("bodyLimit"),
                onSet = { setCfg("bodyLimit", it) })
            Divider()
            // v1.25 P0-1: verboseDetail 是假字段（后端只有 detailMode），修正键名
            BoolSetting(effective, "detailMode", "详细模式", true,
                inherited = inh("detailMode"),
                onSet = { setCfg("detailMode", it) })
            Divider()
            // v1.25 P0-1: sslBypass 是真实字段（SSL 绕过），从反检测组移入通用组
            BoolSetting(effective, "sslBypass", "SSL 绕过", true,
                inherited = inh("sslBypass"),
                onSet = { setCfg("sslBypass", it) })
            Divider()
            // v1.25 P1-5: 补 debug 开关（此前设置页无入口，后端 debugEnabled 只能抓包页/手动下发）
            BoolSetting(effective, "debug", "调试日志", false,
                inherited = inh("debug"),
                onSet = { setCfg("debug", it) })
        }

        Spacer(Modifier.height(8.dp))

        // ===== 反检测 =====
        // v1.25 P0-1: 删除 8 个假开关（antiDetect/antiEmulator/antiFrida/antiDebug/fakeDevice/fakeLocation/
        //   pinBypass/rootCloak——后端无对应字段，下发无效且误导用户）；保留真实字段 antiRoot/antiXposed
        SettingsGroup(
            title = "反检测",
            subtitle = "隐藏 root / Xposed",
            expanded = expanded.contains("anti"),
            onToggle = { toggle("anti") }
        ) {
            BoolSetting(effective, "antiRoot", "隐藏 Root", false,
                inherited = inh("antiRoot"),
                onSet = { setCfg("antiRoot", it) })
            Divider()
            BoolSetting(effective, "antiXposed", "隐藏 Xposed", false,
                inherited = inh("antiXposed"),
                onSet = { setCfg("antiXposed", it) })
        }

        Spacer(Modifier.height(8.dp))

        // ===== Hook 引擎 =====
        // v1.25 P0-1: 删除 5 个假开关（wildcardHook/randomReturn/randomRefreshMs/recordParams/recordReturn——
        //   后端 MethodProbe 无全局随机返回/默认记录模式，通配符 hook 是内置能力无需开关）；保留 autoProbe
        SettingsGroup(
            title = "Hook 引擎",
            subtitle = "全自动探测",
            expanded = expanded.contains("hook"),
            onToggle = { toggle("hook") }
        ) {
            BoolSetting(effective, "autoProbe", "全自动探测", false,
                inherited = inh("autoProbe"),
                onSet = { setCfg("autoProbe", it) })
        }

        Spacer(Modifier.height(8.dp))

        // ===== DexKit =====
        SettingsGroup(
            title = "DexKit",
            subtitle = "DEX 导出 / 字符串反查",
            expanded = expanded.contains("dex"),
            onToggle = { toggle("dex") }
        ) {
            var dexStatus by remember { mutableStateOf("") }
            var findStr by remember { mutableStateOf("") }
            var findResult by remember { mutableStateOf("") }

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = {
                    scope.launch {
                        dexStatus = "导出中…"
                        val r = withContext(Dispatchers.IO) { vm.api.dexdump() }
                        dexStatus = r ?: "导出失败"
                    }
                }) { Text("导出 DEX", fontSize = 12.sp) }
                Button(onClick = {
                    scope.launch {
                        withContext(Dispatchers.IO) { vm.api.dexclose() }
                        dexStatus = "已释放"
                    }
                }) { Text("释放", fontSize = 12.sp) }
            }
            if (dexStatus.isNotEmpty()) {
                Text(dexStatus, style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 4.dp), fontSize = 11.sp)
            }

            Divider()

            OutlinedTextField(
                value = findStr,
                onValueChange = { findStr = it },
                label = { Text("字符串反查", fontSize = 12.sp) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(6.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = {
                    scope.launch {
                        findResult = withContext(Dispatchers.IO) { vm.api.stringFind(findStr) }
                            ?: "失败"
                    }
                }, enabled = findStr.isNotEmpty()) {
                    Text("查找", fontSize = 12.sp)
                }
            }
            if (findResult.isNotEmpty()) {
                Text(
                    findResult.take(500),
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.padding(top = 6.dp)
                )
            }
        }

        Spacer(Modifier.height(8.dp))

        // ===== 关于 =====
        SettingsGroup(
            title = "关于",
            subtitle = "版本 / 开源",
            expanded = expanded.contains("about"),
            onToggle = { toggle("about") }
        ) {
            AboutRow("版本", "v1.24.1")
            Divider()
            AboutRow("作者", "SpyProbe Team")
            Divider()
            AboutRow("许可证", "自定义 (非商用)")
        }

        Spacer(Modifier.height(16.dp))
        }
    }
}

// ===== 分组卡片 =====
@Composable
private fun SettingsGroup(
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
                    .padding(horizontal = 14.dp, vertical = 12.dp)
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
                Column(Modifier.padding(horizontal = 14.dp, vertical = 6.dp)) {
                    content()
                }
            }
        }
    }
}

// ===== 开关行 =====
@Composable
private fun BoolSetting(cfg: Map<String, Any>?, key: String, label: String, default: Boolean,
                        inherited: Boolean = false,
                        onSet: (Boolean) -> Unit) {
    val value = cfg?.get(key) as? Boolean ?: default
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.bodySmall, fontSize = 12.sp)
            if (inherited) {
                Text(
                    "继承全局默认",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 10.sp
                )
            }
        }
        Switch(checked = value, onCheckedChange = { onSet(it) })
    }
}

// ===== 数值设置行 =====
@Composable
private fun IntSetting(cfg: Map<String, Any>?, key: String, label: String, default: Int,
                       range: IntRange, inherited: Boolean = false,
                       onSet: (Int) -> Unit) {
    val value = cfg?.get(key) as? Int ?: default
    // v1.25 P2-3: key+value 双 key——切换 Tab（全局→当前App）后 value 变化时输入框刷新
    var text by remember(key, value) { mutableStateOf(value.toString()) }

    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.bodySmall, fontSize = 12.sp)
            if (inherited) {
                Text(
                    "继承全局默认",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 10.sp
                )
            }
        }
        OutlinedTextField(
            value = text,
            onValueChange = {
                // v1.25 P2-3: 越界输入不生效（保持合法值），避免显示无效配置误导；空输入允许（方便重输）
                val v = it.toIntOrNull()
                if (it.isEmpty()) {
                    text = it
                } else if (v != null && v in range) {
                    text = it
                    onSet(v)
                }
            },
            singleLine = true,
            isError = text.isNotEmpty() && (text.toIntOrNull() == null || text.toIntOrNull() !in range),
            modifier = Modifier.width(80.dp)
        )
    }
}

// ===== 关于行 =====
@Composable
private fun AboutRow(label: String, value: String) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp)
    ) {
        Text(label, style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            fontSize = 12.sp, modifier = Modifier.weight(1f))
        Text(value, style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.Medium, fontSize = 12.sp)
    }
}

// ===== 分隔线 =====
@Composable
private fun Divider() {
    HorizontalDivider(
        color = MaterialTheme.colorScheme.outlineVariant,
        thickness = 0.5.dp,
        modifier = Modifier.padding(vertical = 2.dp)
    )
}
