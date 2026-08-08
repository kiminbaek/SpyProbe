package com.dustinky.spyprobe.ui

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.nio.charset.StandardCharsets

// v1.18: 独立日志页 —— 从抓包页抽出的日志流（过滤/暂停/清空/导出/着色/自动滚动）
// 数据源与抓包页共用 vm.logLines / vm.filter；抓包页瘦身为纯控制区

@Composable
fun LogsScreen(vm: SpyViewModel, modifier: Modifier = Modifier) {
    val logLines by vm.logLines.collectAsState()
    val filter by vm.filter.collectAsState()

    val context = LocalContext.current
    val scope = rememberCoroutineScope()

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
        // ===== 统计行 =====
        val kw = filter.trim()
        val shown = if (kw.isEmpty()) logLines else logLines.filter { matchesFilter(it.second, kw) }
        Text(
            "共 ${logLines.size} 条 · 显示 ${shown.size} 条",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.padding(top = 8.dp)
        )

        // ===== 过滤行 =====
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            OutlinedTextField(
                value = filter,
                onValueChange = { vm.setFilter(it) },
                placeholder = { Text("过滤 /api/ Token") },
                singleLine = true,
                textStyle = MaterialTheme.typography.bodySmall,
                modifier = Modifier.weight(2f).height(48.dp)
            )
            FilterChip(selected = filter == NET_FILTER, onClick = { vm.setFilter(if (filter == NET_FILTER) "" else NET_FILTER) }, label = { Text("网络") })
            FilterChip(selected = filter == MTH_FILTER, onClick = { vm.setFilter(if (filter == MTH_FILTER) "" else MTH_FILTER) }, label = { Text("函数") })
            FilterChip(selected = filter.isEmpty(), onClick = { vm.setFilter("") }, label = { Text("全部") })
        }

        // ===== 操作行：暂停 / 清空 / 导出 =====
        // v1.19 P2-2: 暂停状态由 ViewModel 持有（页面重建不丢失，轮询与按钮始终一致）
        val paused by vm.paused.collectAsState()
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(vertical = 6.dp)) {
            OutlinedButton(onClick = { vm.togglePaused() }, modifier = Modifier.weight(1f)) {
                Text(if (paused) "继续" else "暂停")
            }
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
                        val k = vm.filter.value.trim()
                        if (k.isNotEmpty()) {
                            t = t.split("\n").filter { matchesFilter(it, k) }.joinToString("\n")
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

        HorizontalDivider(modifier = Modifier.padding(bottom = 4.dp))

        // ===== 日志流（P0-2 key 用 seq、P1-6 仅底部才滚、P2-9 按 tag 着色） =====
        val listState = rememberLazyListState()
        LaunchedEffect(shown.size, filter) {
            // P1-6: 用户上翻看历史时不强制拉回底部——只在接近底部时才滚
            val info = listState.layoutInfo
            val lastVisible = info.visibleItemsInfo.lastOrNull()?.index ?: -1
            val nearBottom = lastVisible < 0 || lastVisible >= info.totalItemsCount - 2
            if (nearBottom && shown.isNotEmpty()) listState.animateScrollToItem(shown.size - 1)
        }
        LazyColumn(
            state = listState,
            modifier = Modifier.fillMaxSize()
        ) {
            itemsIndexed(shown, key = { _, p -> p.first }) { _, p ->
                Text(
                    p.second,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                    color = logColor(p.second),
                    modifier = Modifier.padding(vertical = 1.dp)
                )
            }
        }
    }
}
