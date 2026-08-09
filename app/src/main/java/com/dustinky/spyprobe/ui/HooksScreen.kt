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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
// v1.25 P2-4: 用 M3 官方 menuAnchor API（material3 1.3.1 是 MenuAnchorType；ExposedDropdownMenuAnchorType 需 1.4+）
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuAnchorType
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.TabRowDefaults
import androidx.compose.material3.TabRowDefaults.tabIndicatorOffset
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
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
import com.dustinky.spyprobe.ui.theme.codeStyle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

// v1.24: Hook 页优化 —— Tab 切换（已Hook / Hook 规则）+ 浮动添加按钮 + 卡片紧凑化
// v1.17: Hook 页重构 —— 醒目添加入口 + 卡片化规则列表 + 7 模式彩色 + 编辑/删除

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HooksScreen(vm: SpyViewModel, modifier: Modifier = Modifier) {
    var tab by remember { mutableIntStateOf(0) }
    val tabs = listOf("已 Hook", "Hook 规则")
    var hooks by remember { mutableStateOf(emptyList<HookEntry>()) }
    var rules by remember { mutableStateOf(emptyList<HijackEntry>()) }
    val scope = rememberCoroutineScope()

    fun refresh() {
        scope.launch {
            hooks = withContext(Dispatchers.IO) { vm.api.listHooks() }
            rules = withContext(Dispatchers.IO) { vm.api.listHijacks() }
        }
    }

    LaunchedEffect(Unit) { refresh() }

    var showAddRule by remember { mutableStateOf(false) }
    if (showAddRule) {
        AddRuleDialog(vm, onDismiss = { showAddRule = false }, onSaved = { refresh() })
    }

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
            divider = { HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant) }
        ) {
            tabs.forEachIndexed { i, title ->
                Tab(
                    selected = tab == i,
                    onClick = { tab = i; refresh() },
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

        Box(Modifier.fillMaxSize()) {
            when (tab) {
                0 -> HooksList(vm, hooks, onRefresh = { refresh() }, Modifier.fillMaxSize())
                1 -> RulesList(vm, rules, onRefresh = { refresh() }, Modifier.fillMaxSize())
            }

            // 浮动添加按钮（规则 Tab）
            if (tab == 1) {
                FloatingActionButton(
                    onClick = { showAddRule = true },
                    containerColor = MaterialTheme.colorScheme.primary,
                    contentColor = MaterialTheme.colorScheme.onPrimary,
                    shape = RoundedCornerShape(16.dp),
                    modifier = Modifier
                        .align(Alignment.BottomEnd)
                        .padding(end = 16.dp, bottom = 16.dp)
                        .size(52.dp)
                ) {
                    Icon(Icons.Filled.Add, contentDescription = "添加规则")
                }
            }
        }
    }
}

// ===== 已 Hook 列表 =====
@Composable
private fun HooksList(vm: SpyViewModel, hooks: List<HookEntry>, onRefresh: () -> Unit, modifier: Modifier = Modifier) {
    val scope = rememberCoroutineScope()
    val context = LocalContext.current

    if (hooks.isEmpty()) {
        EmptyState(Icons.Filled.Search, "暂无 hook", "在「探测」页点击方法即可 hook")
    } else {
        LazyColumn(modifier = modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
            items(hooks) { h ->
                var expanded by remember { mutableStateOf(false) }
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surfaceContainer
                    ),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 3.dp)
                        .clickable { expanded = !expanded }
                ) {
                    Column(Modifier.padding(horizontal = 10.dp, vertical = 8.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            MiniBadge("HOOK", MaterialTheme.colorScheme.primary)
                            Spacer(Modifier.width(8.dp))
                            Text(
                                h.method,
                                style = codeStyle,
                                maxLines = 2,
                                modifier = Modifier.weight(1f),
                                fontSize = 11.sp,
                                lineHeight = 14.sp
                            )
                        }
                        if (h.cls.isNotEmpty()) {
                            Text(
                                h.cls,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 10.sp,
                                maxLines = 1,
                                modifier = Modifier.padding(top = 2.dp)
                            )
                        }
                        if (expanded) {
                            HorizontalDivider(modifier = Modifier.padding(vertical = 6.dp),
                                color = MaterialTheme.colorScheme.outlineVariant)
                            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                TextButton(onClick = {
                                    scope.launch {
                                        withContext(Dispatchers.IO) { vm.api.unhook(h.cls, h.method, h.params) }
                                        withContext(Dispatchers.Main) { onRefresh() }
                                    }
                                }) {
                                    Text("卸载", fontSize = 11.sp,
                                        color = MaterialTheme.colorScheme.error)
                                }
                                TextButton(onClick = {
                                    android.widget.Toast.makeText(context,
                                        "请在探测页重新扫描该类", android.widget.Toast.LENGTH_SHORT).show()
                                }) {
                                    Text("查看详情", fontSize = 11.sp)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// ===== Hook 规则列表 =====
@Composable
private fun RulesList(vm: SpyViewModel, rules: List<HijackEntry>, onRefresh: () -> Unit,
                      modifier: Modifier = Modifier) {
    val scope = rememberCoroutineScope()
    if (rules.isEmpty()) {
        EmptyState(Icons.Filled.Build, "暂无 Hook 规则", "点击右下角 + 添加自定义规则")
    } else {
        LazyColumn(modifier = modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
            items(rules) { r ->
                val (modeColor, modeLabel) = modeColorLabel(r.mode)
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surfaceContainer
                    ),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 3.dp)
                ) {
                    Column(Modifier.padding(horizontal = 10.dp, vertical = 8.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                modifier = Modifier
                                    .background(modeColor.copy(alpha = 0.15f), RoundedCornerShape(6.dp))
                                    .padding(horizontal = 6.dp, vertical = 2.dp)
                            ) {
                                Text(
                                    modeLabel,
                                    style = MaterialTheme.typography.labelSmall,
                                    color = modeColor,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 10.sp
                                )
                            }
                            Spacer(Modifier.width(6.dp))
                            Text(
                                r.method.ifEmpty { r.cls },
                                style = codeStyle,
                                maxLines = 1,
                                modifier = Modifier.weight(1f),
                                fontSize = 11.sp
                            )
                            // v1.25 P1-4: 删除规则按钮（value=null 取消，与后端 removeHijack 契约一致）
                            IconButton(
                                onClick = {
                                    scope.launch {
                                        withContext(Dispatchers.IO) {
                                            vm.api.setHijack(r.cls, r.method, r.params, r.mode, null)
                                        }
                                        withContext(Dispatchers.Main) { onRefresh() }
                                    }
                                },
                                modifier = Modifier.size(30.dp)
                            ) {
                                Icon(
                                    Icons.Filled.Delete,
                                    contentDescription = "删除规则",
                                    tint = MaterialTheme.colorScheme.error,
                                    modifier = Modifier.size(16.dp)
                                )
                            }
                        }
                        if (r.cls.isNotEmpty() && r.method.isNotEmpty()) {
                            Text(
                                r.cls,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 10.sp,
                                modifier = Modifier.padding(top = 2.dp)
                            )
                        }
                        val detail = when (r.mode) {
                            MODE_RETURN -> "返回值: ${r.value}"
                            MODE_PARAM -> "改参: ${r.paramValue}"
                            MODE_BLOCK -> "拦截执行"
                            MODE_STATIC -> "静态字段 ${r.fieldName}=${r.fieldValue}"
                            MODE_RECORD_PARAMS -> "纯观测: 记录参数"
                            MODE_RECORD_RETURN -> "纯观测: 记录返回"
                            MODE_RECORD_BOTH -> "纯观测: 记参数+返回"
                            else -> ""
                        }
                        if (detail.isNotEmpty()) {
                            Text(
                                detail,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                fontSize = 11.sp,
                                modifier = Modifier.padding(top = 4.dp)
                            )
                        }
                    }
                }
            }
        }
    }
}

// ===== 空状态 =====
@Composable
private fun EmptyState(icon: androidx.compose.ui.graphics.vector.ImageVector, title: String, subtitle: String) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = Modifier.fillMaxSize().padding(top = 100.dp)
    ) {
        Icon(
            icon, contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(56.dp)
        )
        Spacer(Modifier.height(12.dp))
        Text(title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(4.dp))
        Text(
            subtitle,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            fontSize = 12.sp
        )
    }
}

// ===== 模式颜色/标签 =====
private fun modeColorLabel(mode: Int): Pair<Color, String> {
    return when (mode) {
        MODE_RETURN -> Color(0xFF00E676) to "返回值"
        MODE_PARAM -> Color(0xFF00E5FF) to "改参数"
        MODE_BLOCK -> Color(0xFFFF5252) to "拦截"
        MODE_STATIC -> Color(0xFFFFB300) to "静态"
        MODE_RECORD_PARAMS -> Color(0xFF42A5F5) to "记参数"
        MODE_RECORD_RETURN -> Color(0xFFCE93D8) to "记返回"
        MODE_RECORD_BOTH -> Color(0xFFF06292) to "记两者"
        else -> Color(0xFF90A4AE) to "模式$mode"
    }
}

// ===== 小组件：小徽章 =====
@Composable
private fun MiniBadge(text: String, color: Color) {
    Box(
        modifier = Modifier
            .background(color.copy(alpha = 0.15f), RoundedCornerShape(6.dp))
            .padding(horizontal = 6.dp, vertical = 2.dp)
    ) {
        Text(text, style = MaterialTheme.typography.labelSmall, color = color,
            fontWeight = FontWeight.Bold, fontSize = 10.sp)
    }
}

// ===== 添加规则对话框 =====
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AddRuleDialog(vm: SpyViewModel, onDismiss: () -> Unit, onSaved: () -> Unit) {
    val modes = listOf(
        MODE_RETURN to "强制返回值",
        MODE_PARAM to "修改参数",
        MODE_BLOCK to "拦截执行",
        MODE_STATIC to "写静态字段",
        MODE_RECORD_PARAMS to "记录参数",
        MODE_RECORD_RETURN to "记录返回值",
        MODE_RECORD_BOTH to "记录参数+返回"
    )
    var className by remember { mutableStateOf("") }
    var method by remember { mutableStateOf("") }
    var params by remember { mutableStateOf("") }
    var modeIdx by remember { mutableStateOf(0) }
    var returnValue by remember { mutableStateOf("true") }
    var paramValue by remember { mutableStateOf("") }
    var fieldName by remember { mutableStateOf("") }
    var fieldType by remember { mutableStateOf("boolean") }
    var fieldValue by remember { mutableStateOf("true") }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("添加 Hook 规则", fontWeight = FontWeight.Bold) },
        text = {
            Column {
                OutlinedTextField(className, { className = it },
                    label = { Text("类名", fontSize = 12.sp) }, singleLine = true,
                    modifier = Modifier.fillMaxWidth())
                Spacer(Modifier.height(6.dp))
                OutlinedTextField(method, { method = it },
                    label = { Text("方法名", fontSize = 12.sp) }, singleLine = true,
                    modifier = Modifier.fillMaxWidth())
                Spacer(Modifier.height(6.dp))
                OutlinedTextField(params, { params = it },
                    label = { Text("参数签名（可空）", fontSize = 12.sp) },
                    placeholder = { Text("如 int,String", fontSize = 11.sp) },
                    singleLine = true, modifier = Modifier.fillMaxWidth())
                Spacer(Modifier.height(6.dp))

                var expanded by remember { mutableStateOf(false) }
                ExposedDropdownMenuBox(expanded = expanded, onExpandedChange = { expanded = it }) {
                    OutlinedTextField(
                        value = modes[modeIdx].second,
                        onValueChange = {},
                        readOnly = true,
                        label = { Text("模式", fontSize = 12.sp) },
                        trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
                        modifier = Modifier.fillMaxWidth()
                            .menuAnchor(MenuAnchorType.PrimaryNotEditable) // v1.25 P2-4
                    )
                    ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
                        modes.forEachIndexed { i, (_, label) ->
                            DropdownMenuItem(
                                text = { Text(label, fontSize = 13.sp) },
                                onClick = { modeIdx = i; expanded = false }
                            )
                        }
                    }
                }

                Spacer(Modifier.height(6.dp))
                when (modes[modeIdx].first) {
                    MODE_RETURN -> OutlinedTextField(returnValue, { returnValue = it },
                        label = { Text("返回值", fontSize = 12.sp) }, singleLine = true,
                        modifier = Modifier.fillMaxWidth())
                    MODE_PARAM -> OutlinedTextField(paramValue, { paramValue = it },
                        label = { Text("参数值", fontSize = 12.sp) }, singleLine = true,
                        modifier = Modifier.fillMaxWidth())
                    MODE_STATIC -> {
                        OutlinedTextField(fieldName, { fieldName = it },
                            label = { Text("字段名", fontSize = 12.sp) }, singleLine = true,
                            modifier = Modifier.fillMaxWidth())
                        Spacer(Modifier.height(4.dp))
                        OutlinedTextField(fieldType, { fieldType = it },
                            label = { Text("字段类型", fontSize = 12.sp) }, singleLine = true,
                            modifier = Modifier.fillMaxWidth())
                        Spacer(Modifier.height(4.dp))
                        OutlinedTextField(fieldValue, { fieldValue = it },
                            label = { Text("字段值", fontSize = 12.sp) }, singleLine = true,
                            modifier = Modifier.fillMaxWidth())
                    }
                    else -> {}
                }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                val mode = modes[modeIdx].first
                scope.launch {
                    withContext(Dispatchers.IO) {
                        vm.api.setHijack(className.trim(), method.trim(), params.trim(),
                            mode, returnValue, paramValue, fieldName, fieldType, fieldValue)
                    }
                    withContext(Dispatchers.Main) {
                        onSaved()
                        onDismiss()
                    }
                }
            }) { Text("保存") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("取消") } }
    )
}

// v1.25 P2-4: 用 M3 官方 menuAnchor API（此前自定义 no-op 扩展导致下拉菜单锚点不对/不展开）
