package com.dustinky.spyprobe.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
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

// v1.11: Hook 页 —— 已 hook 列表（卸载/劫持）+ 劫持规则

@Composable
fun HooksScreen(vm: SpyViewModel, modifier: Modifier = Modifier) {
    var hooks by remember { mutableStateOf<List<HookEntry>>(emptyList()) }
    var hijacks by remember { mutableStateOf<List<HijackEntry>>(emptyList()) }
    var refreshing by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current

    fun refresh() {
        refreshing = true
        scope.launch {
            val h = withContext(Dispatchers.IO) { vm.api.listHooks() }
            val hj = withContext(Dispatchers.IO) { vm.api.listHijacks() }
            hooks = h
            hijacks = hj
            refreshing = false
        }
    }

    LaunchedEffect(Unit) { refresh() }

    Column(modifier = modifier.fillMaxSize().padding(horizontal = 12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(top = 10.dp, bottom = 6.dp)) {
            Text("已 Hook 列表（${hooks.size}）", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold,
                modifier = Modifier.weight(1f))
            Button(onClick = { refresh() }, enabled = !refreshing) {
                Icon(Icons.Filled.Refresh, contentDescription = null)
                Spacer(Modifier.width(4.dp))
                Text("刷新")
            }
            Spacer(Modifier.width(8.dp))
            Button(onClick = {
                scope.launch {
                    val h = withContext(Dispatchers.IO) { vm.api.listHooks() }
                    withContext(Dispatchers.IO) {
                        h.forEach { vm.api.unhook(it.cls, it.method, it.params) }
                    }
                    refresh()
                    android.widget.Toast.makeText(context, "已全部卸载", android.widget.Toast.LENGTH_SHORT).show()
                }
            }, enabled = hooks.isNotEmpty()) {
                Icon(Icons.Filled.Clear, contentDescription = null)
                Spacer(Modifier.width(4.dp))
                Text("全部卸载")
            }
        }

        if (hooks.isEmpty()) {
            Text("当前没有活跃 hook", style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(vertical = 12.dp))
        } else {
            LazyColumn(modifier = Modifier.height(280.dp)) {
                items(hooks) { h ->
                    HookItem(vm, h, onChanged = { refresh() })
                }
            }
        }

        HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

        Text("当前 Hook 规则（${hijacks.size}）", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
        if (hijacks.isEmpty()) {
            Text("没有 Hook 规则", style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(vertical = 8.dp))
        } else {
            LazyColumn(modifier = Modifier.weight(1f)) {
                items(hijacks) { hj ->
                    Text(hj.display(), style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace, fontSize = 11.sp,
                        modifier = Modifier.padding(vertical = 2.dp))
                }
            }
        }
    }
}

@Composable
private fun HookItem(vm: SpyViewModel, h: HookEntry, onChanged: () -> Unit) {
    var showOps by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current

    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f),
        modifier = Modifier.fillMaxWidth().padding(vertical = 1.dp)
    ) {
        Column(Modifier.padding(horizontal = 8.dp, vertical = 6.dp)) {
            Text(h.display(), style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace, fontSize = 11.sp)
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                TextButton(onClick = {
                    scope.launch {
                        withContext(Dispatchers.IO) { vm.api.unhook(h.cls, h.method, h.params) }
                        onChanged()
                    }
                }) { Text("卸载", style = MaterialTheme.typography.labelSmall) }
                TextButton(onClick = { showOps = true }) {
                    Text("加规则", style = MaterialTheme.typography.labelSmall)
                }
            }
        }
    }

    if (showOps) {
        HijackDialog(vm, h, onDismiss = { showOps = false; onChanged() })
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun HijackDialog(vm: SpyViewModel, h: HookEntry, onDismiss: () -> Unit) {
    var mode by remember { mutableStateOf(MODE_RETURN) }
    var value by remember { mutableStateOf("") }
    var paramValue by remember { mutableStateOf("") }
    var fieldName by remember { mutableStateOf("") }
    var fieldType by remember { mutableStateOf("") }
    var fieldValue by remember { mutableStateOf("") }
    val context = LocalContext.current
    // v1.14: 7 模式（+3 记录模式，SimpleHook 借鉴）
    val modes = listOf(MODE_RETURN, MODE_PARAM, MODE_BLOCK, MODE_STATIC,
        MODE_RECORD_PARAMS, MODE_RECORD_RETURN, MODE_RECORD_BOTH)

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Hook 规则 ${h.method}") },
        text = {
            // v1.16 P1-9: 内容超高 → 垂直滚动 + 限高（窄屏 7 模式+输入框放得下）
            Column(
                modifier = Modifier
                    .verticalScroll(rememberScrollState())
                    .heightIn(max = 420.dp)
            ) {
                Text("class: ${h.cls}\nparams: ${if (h.params.isEmpty()) "全部重载" else h.params}",
                    style = MaterialTheme.typography.bodySmall)

                // v1.13: 4 模式选择（fckvip HookConfigManager 借鉴）
                Text("模式：", style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 8.dp, bottom = 4.dp))
                // v1.16 P1-7: Row+weight 挤一行显示不全 → FlowRow 自动换行
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    modes.forEach { m ->
                        val selected = mode == m
                        Button(
                            onClick = { mode = m },
                            enabled = true
                        ) {
                            Text(
                                modeName(m),
                                style = MaterialTheme.typography.labelSmall,
                                color = if (selected) MaterialTheme.colorScheme.onPrimary
                                else MaterialTheme.colorScheme.onSurface
                            )
                        }
                    }
                }

                when (mode) {
                    MODE_RETURN -> {
                        Text(
                            // v1.15 P2-2: 补充 void 语义提示
                            "输入强制返回值（命中后不执行原方法，直接返回）：\n" +
                                "• true / false —— boolean\n• 123 / 3.14 —— 数字\n" +
                                "• 任意文本 —— String\n• null —— 返回空\n• 留空 = 空串\n" +
                                "• 若方法是 void（无返回值）：强制返回会跳过原方法执行（副作用丢失）",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(vertical = 6.dp)
                        )
                        OutlinedTextField(
                            value = value,
                            onValueChange = { value = it },
                            placeholder = { Text("如 true（会员 isVip()→true）") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                    MODE_PARAM -> {
                        Text(
                            "输入参数改写（格式：索引:值,索引:值，从 0 开始）：\n" +
                                "• 0:3 —— 第 1 个参数改成 3\n• 0:true,1:100 —— 多参数\n" +
                                "• 支持 int/long/boolean/float/double/String",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(vertical = 6.dp)
                        )
                        OutlinedTextField(
                            value = paramValue,
                            onValueChange = { paramValue = it },
                            placeholder = { Text("如 0:3（vipLevel→3）") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                    MODE_BLOCK -> {
                        Text(
                            "拦截执行：方法不执行，直接返回 null/0。\n" +
                                "适合绕过支付校验 / 广告加载 / 弹窗逻辑。",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(vertical = 6.dp)
                        )
                    }
                    MODE_STATIC -> {
                        Text(
                            "写静态字段（如 UserInfo.IS_VIP = true）：",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(vertical = 6.dp)
                        )
                        OutlinedTextField(
                            value = fieldName,
                            onValueChange = { fieldName = it },
                            placeholder = { Text("字段名，如 IS_VIP") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth().padding(bottom = 4.dp)
                        )
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedTextField(
                                value = fieldType,
                                onValueChange = { fieldType = it },
                                placeholder = { Text("类型 boolean") },
                                singleLine = true,
                                modifier = Modifier.weight(1f)
                            )
                            OutlinedTextField(
                                value = fieldValue,
                                onValueChange = { fieldValue = it },
                                placeholder = { Text("值 true") },
                                singleLine = true,
                                modifier = Modifier.weight(1f)
                            )
                        }
                    }
                    // v1.14: 记录模式（SimpleHook 借鉴）—— 纯观测，不需要额外输入
                    MODE_RECORD_PARAMS, MODE_RECORD_RETURN, MODE_RECORD_BOTH -> {
                        Text(
                            when (mode) {
                                MODE_RECORD_PARAMS -> "记录参数：每次调用把入参记入日志，不改程序行为。\n适合逆向分析：先观察方法每次收到什么。"
                                MODE_RECORD_RETURN -> "记录返回值：调用后把结果记入日志，不改程序行为。\n适合逆向分析：观察方法实际返回什么。"
                                else -> "记录参数+返回值：调用前后都记，不改程序行为。\n最完整的观测模式。"
                            },
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(vertical = 6.dp)
                        )
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                when (mode) {
                    MODE_RETURN -> vm.api.setHijack(h.cls, h.method, h.params, MODE_RETURN, value.trim())
                    MODE_PARAM -> vm.api.setHijack(h.cls, h.method, h.params, MODE_PARAM, value = "", paramValue = paramValue.trim())
                    MODE_BLOCK -> vm.api.setHijack(h.cls, h.method, h.params, MODE_BLOCK, value = "")
                    MODE_STATIC -> vm.api.setHijack(h.cls, h.method, h.params, MODE_STATIC, value = "",
                        fieldName = fieldName.trim(), fieldType = fieldType.trim(), fieldValue = fieldValue.trim())
                    // v1.14: 记录模式不需要额外参数
                    MODE_RECORD_PARAMS -> vm.api.setHijack(h.cls, h.method, h.params, MODE_RECORD_PARAMS, value = "")
                    MODE_RECORD_RETURN -> vm.api.setHijack(h.cls, h.method, h.params, MODE_RECORD_RETURN, value = "")
                    MODE_RECORD_BOTH -> vm.api.setHijack(h.cls, h.method, h.params, MODE_RECORD_BOTH, value = "")
                }
                android.widget.Toast.makeText(context, "规则已设置: ${h.method} [${modeName(mode)}]",
                    android.widget.Toast.LENGTH_LONG).show()
                onDismiss()
            }) { Text("确定") }
        },
        dismissButton = {
            TextButton(onClick = {
                vm.api.setHijack(h.cls, h.method, h.params, value = null)
                android.widget.Toast.makeText(context, "已取消规则: ${h.method}", android.widget.Toast.LENGTH_SHORT).show()
                onDismiss()
            }) { Text("取消规则") }
        }
    )
}
