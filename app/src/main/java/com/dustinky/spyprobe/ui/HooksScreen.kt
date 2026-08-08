package com.dustinky.spyprobe.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

// v1.17: Hook 页全面重构 —— 卡片化 UI + 「添加自定义规则」入口（手动输入类/方法/参数）
// 核心逻辑：规则是"被动"的，只在已 hook 方法的回调里查 findHijack
//          → 添加规则必须「先 hook 方法，再设规则」，否则不生效（已封装在 AddRuleDialog）

@Composable
fun HooksScreen(vm: SpyViewModel, modifier: Modifier = Modifier) {
    var hooks by remember { mutableStateOf<List<HookEntry>>(emptyList()) }
    var hijacks by remember { mutableStateOf<List<HijackEntry>>(emptyList()) }
    var refreshing by remember { mutableStateOf(false) }
    var showAddDialog by remember { mutableStateOf(false) }
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

        // ===== 醒目的"添加自定义规则"入口 =====
        Card(
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.35f)
            ),
            modifier = Modifier.fillMaxWidth().padding(top = 10.dp)
        ) {
            Column(Modifier.padding(12.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Filled.Add, contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(20.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("添加自定义 Hook 规则", style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold)
                }
                Text(
                    "手动输入类名 / 方法名 / 参数，选模式并填值，一键 Hook + 生效。\n" +
                        "例：com.example.app.UserApi 的 isVip() → 返回值 true",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 4.dp, bottom = 8.dp)
                )
                Button(onClick = { showAddDialog = true }, modifier = Modifier.fillMaxWidth()) {
                    Icon(Icons.Filled.Add, contentDescription = null)
                    Spacer(Modifier.width(6.dp))
                    Text("＋ 添加自定义规则")
                }
            }
        }

        // ===== 标题行：已 Hook 列表 =====
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(top = 14.dp, bottom = 4.dp)) {
            Text("已 Hook 方法（${hooks.size}）", style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
            TextButton(onClick = { refresh() }, enabled = !refreshing) {
                Icon(Icons.Filled.Refresh, contentDescription = null, modifier = Modifier.size(16.dp))
                Spacer(Modifier.width(2.dp))
                Text("刷新")
            }
        }

        if (hooks.isEmpty()) {
            EmptyHint(
                icon = Icons.Filled.Lock,
                title = "还没有活跃 Hook",
                desc = "点上方「添加自定义规则」手动添加，或到「探测」页扫描类后点击方法一键 hook"
            )
        } else {
            LazyColumn(modifier = Modifier.fillMaxWidth().heightIn(max = 260.dp)) {
                items(hooks) { h ->
                    HookItemCard(vm, h, onChanged = { refresh() })
                }
            }
        }

        HorizontalDivider(modifier = Modifier.padding(vertical = 10.dp))

        // ===== 当前规则列表 =====
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(bottom = 4.dp)) {
            Text("当前规则（${hijacks.size}）", style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
            if (hijacks.isNotEmpty()) {
                TextButton(onClick = {
                    scope.launch {
                        withContext(Dispatchers.IO) {
                            hijacks.forEach { vm.api.setHijack(it.cls, it.method, it.params, value = null) }
                        }
                        refresh()
                        android.widget.Toast.makeText(context, "已清空全部规则", android.widget.Toast.LENGTH_SHORT).show()
                    }
                }) {
                    Icon(Icons.Filled.Clear, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(2.dp))
                    Text("清空")
                }
            }
        }

        if (hijacks.isEmpty()) {
            EmptyHint(
                icon = Icons.Filled.Info,
                title = "没有 Hook 规则",
                desc = "点上方「添加自定义规则」→ 选模式（如：返回值/参数改写/拦截执行）",
                compact = true
            )
        } else {
            LazyColumn(modifier = Modifier.fillMaxWidth().weight(1f)) {
                items(hijacks) { hj ->
                    HijackRuleCard(vm, hj, onChanged = { refresh() })
                }
            }
        }
    }

    if (showAddDialog) {
        AddRuleDialog(vm, onDismiss = { showAddDialog = false; refresh() })
    }
}

// ---------- 空状态提示 ----------
@Composable
private fun EmptyHint(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    desc: String,
    compact: Boolean = false
) {
    Surface(
        color = Color.Transparent,
        modifier = Modifier.fillMaxWidth().padding(vertical = if (compact) 6.dp else 10.dp)
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
            Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.outline, modifier = Modifier.size(28.dp))
            Text(title, style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 4.dp))
            Text(desc, style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.outline,
                modifier = Modifier.padding(top = 2.dp), fontSize = 11.sp)
        }
    }
}

// ---------- 已 Hook 方法卡片 ----------
@Composable
private fun HookItemCard(vm: SpyViewModel, h: HookEntry, onChanged: () -> Unit) {
    var showHijack by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current

    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerHigh),
        modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp)
    ) {
        Column(Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
            Text(
                h.display(),
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                fontSize = 11.sp,
                color = MaterialTheme.colorScheme.onSurface
            )
            Row(horizontalArrangement = Arrangement.spacedBy(4.dp), modifier = Modifier.padding(top = 2.dp)) {
                FilledTonalButton(onClick = { showHijack = true }) {
                    Icon(Icons.Filled.Edit, contentDescription = null, modifier = Modifier.size(14.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("加规则", style = MaterialTheme.typography.labelSmall)
                }
                OutlinedButton(onClick = {
                    scope.launch {
                        withContext(Dispatchers.IO) { vm.api.unhook(h.cls, h.method, h.params) }
                        onChanged()
                    }
                }) {
                    Icon(Icons.Filled.Delete, contentDescription = null, modifier = Modifier.size(14.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("卸载", style = MaterialTheme.typography.labelSmall)
                }
            }
        }
    }

    if (showHijack) {
        HijackDialog(vm, h, onDismiss = { showHijack = false; onChanged() })
    }
}

// ---------- 规则卡片 ----------
@Composable
private fun HijackRuleCard(vm: SpyViewModel, hj: HijackEntry, onChanged: () -> Unit) {
    var showEdit by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current

    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerHigh),
        modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp)
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(start = 10.dp, end = 4.dp, top = 6.dp, bottom = 6.dp)
        ) {
            ModeBadge(mode = hj.mode)
            Column(Modifier.weight(1f).padding(horizontal = 8.dp)) {
                Text(
                    "${hj.cls}.${hj.method}(${hj.params})",
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 10.sp,
                    maxLines = 2
                )
                Text(
                    hijackDetail(hj),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 11.sp,
                    modifier = Modifier.padding(top = 1.dp)
                )
            }
            IconButtonSmall(onClick = { showEdit = true }, icon = Icons.Filled.Edit,
                tint = MaterialTheme.colorScheme.secondary)
            IconButtonSmall(onClick = {
                scope.launch {
                    withContext(Dispatchers.IO) { vm.api.setHijack(hj.cls, hj.method, hj.params, value = null) }
                    onChanged()
                    android.widget.Toast.makeText(context, "已删除规则", android.widget.Toast.LENGTH_SHORT).show()
                }
            }, icon = Icons.Filled.Delete, tint = MaterialTheme.colorScheme.error)
        }
    }

    if (showEdit) {
        EditRuleDialog(vm, hj, onDismiss = { showEdit = false; onChanged() })
    }
}

@Composable
private fun androidx.compose.foundation.layout.RowScope.IconButtonSmall(
    onClick: () -> Unit,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    tint: Color
) {
    TextButton(onClick = onClick) {
        Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.size(16.dp))
    }
}

private fun hijackDetail(hj: HijackEntry): String = when (hj.mode) {
    MODE_RETURN -> "强制返回 → ${hj.value}"
    MODE_PARAM -> "改写参数 [${hj.paramValue}]"
    MODE_BLOCK -> "拦截执行（不运行，返回空）"
    MODE_STATIC -> "写字段 ${hj.fieldName}(${hj.fieldType}) = ${hj.fieldValue}"
    MODE_RECORD_PARAMS -> "纯观测 · 记录参数"
    MODE_RECORD_RETURN -> "纯观测 · 记录返回"
    MODE_RECORD_BOTH -> "纯观测 · 记录参数+返回"
    else -> ""
}

// ---------- 模式徽章 ----------
@Composable
private fun ModeBadge(mode: Int) {
    val (bg, fg) = modeColors(mode)
    Box(
        modifier = Modifier
            .background(bg, RoundedCornerShape(6.dp))
            .padding(horizontal = 6.dp, vertical = 3.dp)
    ) {
        Text(modeName(mode), style = MaterialTheme.typography.labelSmall,
            color = fg, fontWeight = FontWeight.Medium, fontSize = 10.sp)
    }
}

/** v1.17: 7 模式各自配色（徽章/选择按钮用） */
private fun modeColors(mode: Int): Pair<Color, Color> = when (mode) {
    MODE_RETURN -> Color(0xFF2E7D32) to Color(0xFFC8E6C9)
    MODE_PARAM -> Color(0xFF0277BD) to Color(0xFFB3E5FC)
    MODE_BLOCK -> Color(0xFFC62828) to Color(0xFFFFCDD2)
    MODE_STATIC -> Color(0xFFE65100) to Color(0xFFFFE0B2)
    MODE_RECORD_PARAMS -> Color(0xFF4A4A4A) to Color(0xFFE0E0E0)
    MODE_RECORD_RETURN -> Color(0xFF5D4037) to Color(0xFFD7CCC8)
    else -> Color(0xFF37474F) to Color(0xFFCFD8DC)
}

// ============================================================
// 添加自定义规则对话框（v1.17 核心新增 —— 用户可手动输入）
// 流程：输入 类名/方法名/参数 → 选模式 → 填值 → 「Hook 并添加规则」
// ============================================================
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun AddRuleDialog(vm: SpyViewModel, onDismiss: () -> Unit) {
    var cls by remember { mutableStateOf("") }
    var method by remember { mutableStateOf("") }
    var params by remember { mutableStateOf("") }
    var isConstructor by remember { mutableStateOf(false) }
    var mode by remember { mutableStateOf(MODE_RETURN) }
    var value by remember { mutableStateOf("") }
    var paramValue by remember { mutableStateOf("") }
    var fieldName by remember { mutableStateOf("") }
    var fieldType by remember { mutableStateOf("") }
    var fieldValue by remember { mutableStateOf("") }
    var submitting by remember { mutableStateOf(false) }
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val modes = listOf(MODE_RETURN, MODE_PARAM, MODE_BLOCK, MODE_STATIC,
        MODE_RECORD_PARAMS, MODE_RECORD_RETURN, MODE_RECORD_BOTH)

    AlertDialog(
        onDismissRequest = { if (!submitting) onDismiss() },
        title = { Text("添加自定义 Hook 规则", fontWeight = FontWeight.Bold) },
        text = {
            Column(
                modifier = Modifier
                    .verticalScroll(rememberScrollState())
                    .heightIn(max = 520.dp)
            ) {
                Text("规则是「先 Hook 方法，再设规则」：点确定会自动 hook 目标方法并让规则生效。",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)

                OutlinedTextField(
                    value = cls,
                    onValueChange = { cls = it },
                    label = { Text("类名（必填）") },
                    placeholder = { Text("com.example.app.UserApi") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp)
                )
                OutlinedTextField(
                    value = method,
                    onValueChange = { method = it },
                    label = { Text("方法名（必填）") },
                    placeholder = { Text("isVip / checkVip / loadAd") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().padding(top = 6.dp)
                )
                OutlinedTextField(
                    value = params,
                    onValueChange = { params = it },
                    label = { Text("参数类型（可选，逗号分隔）") },
                    placeholder = { Text("留空 = 全部重载，如 int,java.lang.String") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().padding(top = 6.dp)
                )

                // 模式选择（7 模式，彩色）
                Text("模式：", style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 10.dp, bottom = 4.dp))
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    modes.forEach { m ->
                        val selected = mode == m
                        val (bg, fg) = modeColors(m)
                        Surface(
                            color = if (selected) bg else Color.Transparent,
                            shape = RoundedCornerShape(8.dp),
                            border = if (selected) null else
                                androidx.compose.foundation.BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
                            onClick = { mode = m }
                        ) {
                            Text(modeName(m),
                                style = MaterialTheme.typography.labelSmall,
                                color = if (selected) fg else MaterialTheme.colorScheme.onSurface,
                                modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp))
                        }
                    }
                }

                // 模式参数输入
                when (mode) {
                    MODE_RETURN -> {
                        HelpText("强制返回值（命中后不执行原方法，直接返回）：\n" +
                            "• true/false → boolean  • 123/3.14 → 数字\n" +
                            "• 任意文本 → String  • null → 空\n" +
                            "• void 方法强制返回 = 跳过原方法执行")
                        OutlinedTextField(
                            value = value,
                            onValueChange = { value = it },
                            placeholder = { Text("如 true（isVip()→true）") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                    MODE_PARAM -> {
                        HelpText("参数改写（索引:值，从 0 起，逗号分隔）：\n" +
                            "0:3 改第 1 参为 3 ｜ 0:true,1:100 多参数\n" +
                            "支持 int/long/boolean/float/double/String")
                        OutlinedTextField(
                            value = paramValue,
                            onValueChange = { paramValue = it },
                            placeholder = { Text("如 0:3") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                    MODE_BLOCK -> {
                        HelpText("拦截执行：方法不执行，直接返回 null/0。\n" +
                            "适合绕过支付校验 / 广告加载 / 弹窗逻辑。")
                    }
                    MODE_STATIC -> {
                        HelpText("写静态字段（如 UserInfo.IS_VIP = true）：")
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
                    MODE_RECORD_PARAMS, MODE_RECORD_RETURN, MODE_RECORD_BOTH -> {
                        HelpText(
                            when (mode) {
                                MODE_RECORD_PARAMS -> "记录参数：每次调用把入参记入日志，不改行为。\n适合逆向分析：先看方法每次收到什么。"
                                MODE_RECORD_RETURN -> "记录返回值：调用后把结果记入日志，不改行为。\n适合逆向分析：观察方法实际返回什么。"
                                else -> "记录参数+返回值：调用前后都记，最完整的观测模式。"
                            }
                        )
                    }
                }
            }
        },
        confirmButton = {
            Button(onClick = {
                val c = cls.trim()
                val m = method.trim()
                if (c.isEmpty() || m.isEmpty()) {
                    android.widget.Toast.makeText(context, "类名和方法名不能为空", android.widget.Toast.LENGTH_SHORT).show()
                    return@Button
                }
                submitting = true
                scope.launch {
                    val p = params.trim()
                    val kind = if (isConstructor) "constructor" else "method"
                    // 1) 先 hook（规则只在已 hook 方法回调里查）
                    val hookResp = withContext(Dispatchers.IO) {
                        vm.api.hookMethod(c, m, p, kind)
                    }
                    // 2) 再设规则
                    withContext(Dispatchers.IO) {
                        when (mode) {
                            MODE_RETURN -> vm.api.setHijack(c, m, p, MODE_RETURN, value.trim())
                            MODE_PARAM -> vm.api.setHijack(c, m, p, MODE_PARAM, value = "", paramValue = paramValue.trim())
                            MODE_BLOCK -> vm.api.setHijack(c, m, p, MODE_BLOCK, value = "")
                            MODE_STATIC -> vm.api.setHijack(c, m, p, MODE_STATIC, value = "",
                                fieldName = fieldName.trim(), fieldType = fieldType.trim(), fieldValue = fieldValue.trim())
                            MODE_RECORD_PARAMS -> vm.api.setHijack(c, m, p, MODE_RECORD_PARAMS, value = "")
                            MODE_RECORD_RETURN -> vm.api.setHijack(c, m, p, MODE_RECORD_RETURN, value = "")
                            else -> vm.api.setHijack(c, m, p, MODE_RECORD_BOTH, value = "")
                        }
                    }
                    // 解析 hook 结果提示
                    val hookMsg = if (hookResp == null) "未连接"
                    else try {
                        val o = org.json.JSONObject(hookResp)
                        if (o.optBoolean("ok", false)) "已 hook ${o.optInt("hooked", 0)} 个重载"
                        else "hook 失败: ${o.optString("note", o.optString("error", ""))}"
                    } catch (t: Throwable) { hookResp }
                    android.widget.Toast.makeText(context,
                        "$hookMsg ｜ 规则: $c.$m [${modeName(mode)}]",
                        android.widget.Toast.LENGTH_LONG).show()
                    onDismiss()
                }
            }, enabled = !submitting) {
                Text(if (submitting) "提交中…" else "Hook 并添加规则")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss, enabled = !submitting) { Text("取消") }
        }
    )
}

@Composable
private fun HelpText(text: String) {
    Text(text, style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(vertical = 6.dp))
}

// ============================================================
// 编辑已有规则（v1.17 新增：预填模式与值，更新规则不删规则）
// ============================================================
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun EditRuleDialog(vm: SpyViewModel, hj: HijackEntry, onDismiss: () -> Unit) {
    var mode by remember { mutableStateOf(hj.mode) }
    var value by remember { mutableStateOf(hj.value) }
    var paramValue by remember { mutableStateOf(hj.paramValue) }
    var fieldName by remember { mutableStateOf(hj.fieldName) }
    var fieldType by remember { mutableStateOf(hj.fieldType) }
    var fieldValue by remember { mutableStateOf(hj.fieldValue) }
    val context = LocalContext.current
    val modes = listOf(MODE_RETURN, MODE_PARAM, MODE_BLOCK, MODE_STATIC,
        MODE_RECORD_PARAMS, MODE_RECORD_RETURN, MODE_RECORD_BOTH)

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("编辑规则 · ${hj.method}", fontWeight = FontWeight.Bold) },
        text = {
            Column(
                modifier = Modifier
                    .verticalScroll(rememberScrollState())
                    .heightIn(max = 460.dp)
            ) {
                Text("class: ${hj.cls}\nparams: ${if (hj.params.isEmpty()) "全部重载" else hj.params}",
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace, fontSize = 11.sp)

                Text("模式：", style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 10.dp, bottom = 4.dp))
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    modes.forEach { m ->
                        val selected = mode == m
                        val (bg, fg) = modeColors(m)
                        Surface(
                            color = if (selected) bg else Color.Transparent,
                            shape = RoundedCornerShape(8.dp),
                            border = if (selected) null else
                                androidx.compose.foundation.BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
                            onClick = { mode = m }
                        ) {
                            Text(modeName(m),
                                style = MaterialTheme.typography.labelSmall,
                                color = if (selected) fg else MaterialTheme.colorScheme.onSurface,
                                modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp))
                        }
                    }
                }

                when (mode) {
                    MODE_RETURN -> {
                        HelpText("强制返回值（命中后不执行原方法，直接返回）：\n" +
                            "• true/false → boolean  • 123/3.14 → 数字\n" +
                            "• 任意文本 → String  • null → 空")
                        OutlinedTextField(
                            value = value,
                            onValueChange = { value = it },
                            placeholder = { Text("如 true（isVip()→true）") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                    MODE_PARAM -> {
                        HelpText("参数改写（索引:值，从 0 起，逗号分隔）：\n0:3 改第 1 参为 3 ｜ 0:true,1:100 多参数")
                        OutlinedTextField(
                            value = paramValue,
                            onValueChange = { paramValue = it },
                            placeholder = { Text("如 0:3") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                    MODE_BLOCK -> {
                        HelpText("拦截执行：方法不执行，直接返回 null/0。\n适合绕过支付校验 / 广告加载 / 弹窗逻辑。")
                    }
                    MODE_STATIC -> {
                        HelpText("写静态字段（如 UserInfo.IS_VIP = true）：")
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
                    MODE_RECORD_PARAMS, MODE_RECORD_RETURN, MODE_RECORD_BOTH -> {
                        HelpText(
                            when (mode) {
                                MODE_RECORD_PARAMS -> "记录参数：每次调用把入参记入日志，不改程序行为。"
                                MODE_RECORD_RETURN -> "记录返回值：调用后把结果记入日志，不改程序行为。"
                                else -> "记录参数+返回值：调用前后都记，最完整的观测模式。"
                            }
                        )
                    }
                }
            }
        },
        confirmButton = {
            Button(onClick = {
                when (mode) {
                    MODE_RETURN -> vm.api.setHijack(hj.cls, hj.method, hj.params, MODE_RETURN, value.trim())
                    MODE_PARAM -> vm.api.setHijack(hj.cls, hj.method, hj.params, MODE_PARAM, value = "", paramValue = paramValue.trim())
                    MODE_BLOCK -> vm.api.setHijack(hj.cls, hj.method, hj.params, MODE_BLOCK, value = "")
                    MODE_STATIC -> vm.api.setHijack(hj.cls, hj.method, hj.params, MODE_STATIC, value = "",
                        fieldName = fieldName.trim(), fieldType = fieldType.trim(), fieldValue = fieldValue.trim())
                    MODE_RECORD_PARAMS -> vm.api.setHijack(hj.cls, hj.method, hj.params, MODE_RECORD_PARAMS, value = "")
                    MODE_RECORD_RETURN -> vm.api.setHijack(hj.cls, hj.method, hj.params, MODE_RECORD_RETURN, value = "")
                    MODE_RECORD_BOTH -> vm.api.setHijack(hj.cls, hj.method, hj.params, MODE_RECORD_BOTH, value = "")
                }
                android.widget.Toast.makeText(context, "规则已更新: ${hj.method} [${modeName(mode)}]",
                    android.widget.Toast.LENGTH_LONG).show()
                onDismiss()
            }) { Text("保存") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("取消") }
        }
    )
}

// ============================================================
// 对"已 hook 方法"加规则（原 HijackDialog 保留，UI 与 AddRuleDialog 统一）
// ============================================================
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
    val modes = listOf(MODE_RETURN, MODE_PARAM, MODE_BLOCK, MODE_STATIC,
        MODE_RECORD_PARAMS, MODE_RECORD_RETURN, MODE_RECORD_BOTH)

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("为 ${h.method} 加规则", fontWeight = FontWeight.Bold) },
        text = {
            Column(
                modifier = Modifier
                    .verticalScroll(rememberScrollState())
                    .heightIn(max = 460.dp)
            ) {
                Text("class: ${h.cls}\nparams: ${if (h.params.isEmpty()) "全部重载" else h.params}",
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace, fontSize = 11.sp)

                Text("模式：", style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 10.dp, bottom = 4.dp))
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    modes.forEach { m ->
                        val selected = mode == m
                        val (bg, fg) = modeColors(m)
                        Surface(
                            color = if (selected) bg else Color.Transparent,
                            shape = RoundedCornerShape(8.dp),
                            border = if (selected) null else
                                androidx.compose.foundation.BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
                            onClick = { mode = m }
                        ) {
                            Text(modeName(m),
                                style = MaterialTheme.typography.labelSmall,
                                color = if (selected) fg else MaterialTheme.colorScheme.onSurface,
                                modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp))
                        }
                    }
                }

                when (mode) {
                    MODE_RETURN -> {
                        HelpText("强制返回值（命中后不执行原方法，直接返回）：\n" +
                            "• true/false → boolean  • 123/3.14 → 数字\n" +
                            "• 任意文本 → String  • null → 空\n" +
                            "• void 方法强制返回 = 跳过原方法执行")
                        OutlinedTextField(
                            value = value,
                            onValueChange = { value = it },
                            placeholder = { Text("如 true（isVip()→true）") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                    MODE_PARAM -> {
                        HelpText("参数改写（索引:值，从 0 起，逗号分隔）：\n" +
                            "0:3 改第 1 参为 3 ｜ 0:true,1:100 多参数")
                        OutlinedTextField(
                            value = paramValue,
                            onValueChange = { paramValue = it },
                            placeholder = { Text("如 0:3") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                    MODE_BLOCK -> {
                        HelpText("拦截执行：方法不执行，直接返回 null/0。\n适合绕过支付校验 / 广告加载 / 弹窗逻辑。")
                    }
                    MODE_STATIC -> {
                        HelpText("写静态字段（如 UserInfo.IS_VIP = true）：")
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
                    MODE_RECORD_PARAMS, MODE_RECORD_RETURN, MODE_RECORD_BOTH -> {
                        HelpText(
                            when (mode) {
                                MODE_RECORD_PARAMS -> "记录参数：每次调用把入参记入日志，不改程序行为。\n适合逆向分析：先观察方法每次收到什么。"
                                MODE_RECORD_RETURN -> "记录返回值：调用后把结果记入日志，不改程序行为。\n适合逆向分析：观察方法实际返回什么。"
                                else -> "记录参数+返回值：调用前后都记，不改程序行为。\n最完整的观测模式。"
                            }
                        )
                    }
                }
            }
        },
        confirmButton = {
            Button(onClick = {
                when (mode) {
                    MODE_RETURN -> vm.api.setHijack(h.cls, h.method, h.params, MODE_RETURN, value.trim())
                    MODE_PARAM -> vm.api.setHijack(h.cls, h.method, h.params, MODE_PARAM, value = "", paramValue = paramValue.trim())
                    MODE_BLOCK -> vm.api.setHijack(h.cls, h.method, h.params, MODE_BLOCK, value = "")
                    MODE_STATIC -> vm.api.setHijack(h.cls, h.method, h.params, MODE_STATIC, value = "",
                        fieldName = fieldName.trim(), fieldType = fieldType.trim(), fieldValue = fieldValue.trim())
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
