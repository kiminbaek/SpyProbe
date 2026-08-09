package com.dustinky.spyprobe.ui

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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

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

    // 配置值
    var cfg by remember { mutableStateOf<Map<String, Any>?>(null) }
    var loading by remember { mutableStateOf(true) }

    fun load() {
        loading = true
        scope.launch {
            val c = withContext(Dispatchers.IO) { vm.api.fetchConfig() }
            cfg = c
            loading = false
        }
    }

    LaunchedEffect(Unit) { load() }

    fun setCfg(key: String, value: Any) {
        val c = cfg ?: return
        cfg = c + (key to value)
        vm.sendConfig(mapOf(key to value))
    }

    // 分组折叠状态
    var expanded by remember { mutableStateOf(setOf("basic")) }

    fun toggle(key: String) {
        expanded = if (expanded.contains(key))
            expanded - key
        else
            expanded + key
    }

    val c = cfg
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 8.dp)
    ) {

        // 顶部操作：重新读取
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(
                    "模块配置",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    if (loading) "加载中…" else "对当前已连接 App 生效",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 11.sp
                )
            }
            TextButton(onClick = { load() }) {
                Text("↻ 重新读取", fontSize = 12.sp)
            }
        }

        Spacer(Modifier.height(8.dp))

        if (c == null) {
            Text(
                "未连接到目标 App",
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall
            )
        }

        // ===== 通用设置 =====
        SettingsGroup(
            title = "通用",
            subtitle = "日志 / 抓包基础",
            expanded = expanded.contains("basic"),
            onToggle = { toggle("basic") }
        ) {
            IntSetting(c, "logLimit", "日志上限(条)", 4096, 100..20000,
                onSet = { setCfg("logLimit", it) })
            Divider()
            IntSetting(c, "bodyLimit", "Body 限制(KB)", 32, 1..1024,
                onSet = { setCfg("bodyLimit", it) })
            Divider()
            BoolSetting(c, "verboseDetail", "详细模式", false,
                onSet = { setCfg("verboseDetail", it) })
        }

        Spacer(Modifier.height(8.dp))

        // ===== 反检测 =====
        SettingsGroup(
            title = "反检测",
            subtitle = "隐藏 root / Xposed / 调试",
            expanded = expanded.contains("anti"),
            onToggle = { toggle("anti") }
        ) {
            BoolSetting(c, "antiDetect", "反检测总开关", true,
                onSet = { setCfg("antiDetect", it) })
            Divider()
            BoolSetting(c, "antiRoot", "隐藏 Root", true,
                onSet = { setCfg("antiRoot", it) })
            Divider()
            BoolSetting(c, "antiXposed", "隐藏 Xposed", true,
                onSet = { setCfg("antiXposed", it) })
            Divider()
            BoolSetting(c, "antiEmulator", "隐藏模拟器", true,
                onSet = { setCfg("antiEmulator", it) })
            Divider()
            BoolSetting(c, "antiFrida", "隐藏 Frida", false,
                onSet = { setCfg("antiFrida", it) })
            Divider()
            BoolSetting(c, "antiDebug", "隐藏调试", true,
                onSet = { setCfg("antiDebug", it) })
            Divider()
            BoolSetting(c, "fakeDevice", "设备伪装", false,
                onSet = { setCfg("fakeDevice", it) })
            Divider()
            BoolSetting(c, "fakeLocation", "伪定位", false,
                onSet = { setCfg("fakeLocation", it) })
            Divider()
            BoolSetting(c, "sslBypass", "SSL 绕过", true,
                onSet = { setCfg("sslBypass", it) })
            Divider()
            BoolSetting(c, "pinBypass", "证书锁定绕过", true,
                onSet = { setCfg("pinBypass", it) })
            Divider()
            BoolSetting(c, "rootCloak", "Root 隐藏(增强)", false,
                onSet = { setCfg("rootCloak", it) })
        }

        Spacer(Modifier.height(8.dp))

        // ===== Hook 引擎 =====
        SettingsGroup(
            title = "Hook 引擎",
            subtitle = "通配符 / 随机返回 / 记录模式",
            expanded = expanded.contains("hook"),
            onToggle = { toggle("hook") }
        ) {
            BoolSetting(c, "wildcardHook", "通配符 Hook", true,
                onSet = { setCfg("wildcardHook", it) })
            Divider()
            BoolSetting(c, "randomReturn", "随机返回值", false,
                onSet = { setCfg("randomReturn", it) })
            Divider()
            IntSetting(c, "randomRefreshMs", "随机刷新(ms)", 5000, 100..60000,
                onSet = { setCfg("randomRefreshMs", it) })
            Divider()
            BoolSetting(c, "recordParams", "默认记录参数", false,
                onSet = { setCfg("recordParams", it) })
            Divider()
            BoolSetting(c, "recordReturn", "默认记录返回", false,
                onSet = { setCfg("recordReturn", it) })
            Divider()
            BoolSetting(c, "autoProbe", "全自动探测", false,
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
            AboutRow("版本", "v1.24")
            Divider()
            AboutRow("作者", "SpyProbe Team")
            Divider()
            AboutRow("许可证", "自定义 (非商用)")
        }

        Spacer(Modifier.height(16.dp))
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
        modifier = Modifier.fillMaxWidth()
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
                        onSet: (Boolean) -> Unit) {
    val value = cfg?.get(key) as? Boolean ?: default
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)
    ) {
        Text(label, style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.weight(1f), fontSize = 12.sp)
        Switch(checked = value, onCheckedChange = { onSet(it) },
            enabled = cfg != null)
    }
}

// ===== 数值设置行 =====
@Composable
private fun IntSetting(cfg: Map<String, Any>?, key: String, label: String, default: Int,
                       range: IntRange, onSet: (Int) -> Unit) {
    val value = cfg?.get(key) as? Int ?: default
    var text by remember(key) { mutableStateOf(value.toString()) }

    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)
    ) {
        Text(label, style = MaterialTheme.typography.bodySmall,
            fontSize = 12.sp, modifier = Modifier.weight(1f))
        OutlinedTextField(
            value = text,
            onValueChange = {
                text = it
                val v = it.toIntOrNull()
                if (v != null && v in range) onSet(v)
            },
            singleLine = true,
            enabled = cfg != null,
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
