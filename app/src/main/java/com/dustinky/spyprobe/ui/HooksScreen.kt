package com.dustinky.spyprobe.ui

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

        Text("当前劫持规则（${hijacks.size}）", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
        if (hijacks.isEmpty()) {
            Text("没有劫持规则", style = MaterialTheme.typography.bodySmall,
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
                    Text("劫持", style = MaterialTheme.typography.labelSmall)
                }
            }
        }
    }

    if (showOps) {
        HijackDialog(vm, h, onDismiss = { showOps = false; onChanged() })
    }
}

@Composable
private fun HijackDialog(vm: SpyViewModel, h: HookEntry, onDismiss: () -> Unit) {
    var value by remember { mutableStateOf("") }
    val context = LocalContext.current
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("劫持 ${h.method}") },
        text = {
            Column {
                Text("class: ${h.cls}\nparams: ${if (h.params.isEmpty()) "全部重载" else h.params}",
                    style = MaterialTheme.typography.bodySmall)
                Text(
                    "输入强制返回值（命中后不执行原方法，直接返回）：\n" +
                        "• true / false —— boolean\n• 123 / 3.14 —— 数字\n" +
                        "• 任意文本 —— String\n• null —— 返回空\n• 留空 = 空串",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(vertical = 6.dp)
                )
                OutlinedTextField(
                    value = value,
                    onValueChange = { value = it },
                    placeholder = { Text("如 true") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        },
        confirmButton = {
            TextButton(onClick = {
                val v = value.trim()
                vm.api.setHijack(h.cls, h.method, h.params, v)
                android.widget.Toast.makeText(context, "劫持已设置: ${h.method} -> $v", android.widget.Toast.LENGTH_LONG).show()
                onDismiss()
            }) { Text("确定劫持") }
        },
        dismissButton = {
            TextButton(onClick = {
                vm.api.setHijack(h.cls, h.method, h.params, null)
                android.widget.Toast.makeText(context, "已取消劫持: ${h.method}", android.widget.Toast.LENGTH_SHORT).show()
                onDismiss()
            }) { Text("取消劫持") }
        }
    )
}
