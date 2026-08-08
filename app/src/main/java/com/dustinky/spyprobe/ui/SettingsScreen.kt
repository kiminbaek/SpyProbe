package com.dustinky.spyprobe.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.dustinky.spyprobe.BuildConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

// v1.11: 设置页 —— 高级配置（bodyLimit/webView/prefs/sqlite/urlBuild/logcat/crypto/activity/json/detailMode/env/tls/connect/cronet）+ DexKit + 关于
// v1.23: 配置架构重构 —— 全局默认 + 分应用覆盖（UI 本地为权威）：
//   - 模式切换：全局默认 / 当前App
//   - 全局默认：全量项（含模块参数 bodyLimit/logLimit/detailMode/debug），适用于所有未覆盖 App
//   - 当前App：只编辑该 App 覆盖项，未覆盖的继承全局（灰色小字显示继承值）；已覆盖标紫色
//   - 拨开关 = 立即存本地 + 自动推送目标进程；未连接时提示"已保存，暂未生效"
//   - 去掉「重新读取配置」按钮（本地即真相）

// v1.23: 可分应用覆盖的开关项（模块参数 bodyLimit/logLimit/detailMode/debug 只放全局）
private val OVERRIDABLE_SWITCHES = listOf(
    "webView" to "记录 WebView.loadUrl",
    "prefs" to "记录 SharedPreferences key（读取高频，建议按需开）",
    "sqlite" to "记录 SQLite 增删改查",
    "urlBuild" to "记录 URL 构造（找接口地址/CDN 域名）",
    "logcat" to "记录 App 自身 Log 输出（信息量大）",
    "crypto" to "记录加密算法/密钥/IV（Cipher，默认关防刷屏）",
    "activity" to "记录 Activity 生命周期 + Intent 跳转",
    "json" to "记录 JSON/Gson 序列化结构",
    "env" to "记录环境检测（root/vpn/传感器/防截屏/设备指纹）",
    "tls" to "TLS 明文抓包（ConscryptEngine，HTTPS 明文头）",
    "connect" to "万能连接点记录（BlockGuardOs.connect，QUIC/自建TCP）",
    "cronet" to "Cronet 网络栈记录（字节系 app，默认关防重复）",
    "native" to "native 层抓包（libc+SSL+HTTP2，高频刷屏可关）",
    "antiRoot" to "隐藏 root：File.exists(su)/Runtime.exec/SystemProperties 过滤",
    "antiXposed" to "隐藏 Xposed：loadClass/StackTrace/DexPathList/Modifier 净化"
)

@Composable
fun SettingsScreen(vm: SpyViewModel, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val target by vm.targetPkg.collectAsState()

    // v1.23: 模式 0=全局默认 1=当前App
    var mode by remember { mutableStateOf(0) }

    // ---- 全局默认配置状态（UI 本地权威）----
    var gSwitches by remember { mutableStateOf<Map<String, Boolean>>(emptyMap()) }
    var gBodyLimit by remember { mutableStateOf("2048") }
    var gLogLimit by remember { mutableStateOf("4096") }
    var gDebug by remember { mutableStateOf(false) }

    // ---- 当前 App 覆盖状态（只存"不一样"的项）----
    var overrideMap by remember { mutableStateOf<Map<String, Any>>(emptyMap()) }

    // 初始化：加载全局默认（本地）
    LaunchedEffect(Unit) {
        val g = vm.loadGlobalConfig()
        gSwitches = g.filterValues { it is Boolean }.mapValues { it.value as Boolean }
        g["bodyLimit"]?.toString()?.let { gBodyLimit = it }
        g["logLimit"]?.toString()?.let { gLogLimit = it }
        gDebug = g["debug"] as? Boolean ?: false
    }

    // 切换目标 → 加载该 App 的覆盖配置
    LaunchedEffect(target) {
        overrideMap = vm.loadAppConfig(target)
    }

    fun globalBool(key: String): Boolean = gSwitches[key] ?: false
    fun effBool(key: String): Boolean = (overrideMap[key] as? Boolean) ?: globalBool(key)
    fun isOverridden(key: String): Boolean = overrideMap.containsKey(key)

    /** 收集全局配置并保存本地（成功）；随后推送当前目标生效配置 */
    fun saveGlobalAndPush() {
        vm.saveGlobalConfig(mapOf(
            "bodyLimit" to (gBodyLimit.trim().toIntOrNull() ?: 2048),
            "logLimit" to (gLogLimit.trim().toIntOrNull() ?: 4096),
            "webView" to globalBool("webView"),
            "prefs" to globalBool("prefs"),
            "sqlite" to globalBool("sqlite"),
            "urlBuild" to globalBool("urlBuild"),
            "logcat" to globalBool("logcat"),
            "crypto" to globalBool("crypto"),
            "activity" to globalBool("activity"),
            "json" to globalBool("json"),
            "detailMode" to globalBool("detailMode"),
            "env" to globalBool("env"),
            "tls" to globalBool("tls"),
            "connect" to globalBool("connect"),
            "cronet" to globalBool("cronet"),
            "antiRoot" to globalBool("antiRoot"),
            "antiXposed" to globalBool("antiXposed"),
            "native" to globalBool("native"),
            "debug" to gDebug
        ))
        val ok = vm.pushConfig(target)
        android.widget.Toast.makeText(context,
            if (ok) "全局配置已保存并下发" else "已保存本地（未连接，暂未生效）",
            android.widget.Toast.LENGTH_SHORT).show()
    }

    /** 推送当前目标生效配置（手动同步） */
    fun pushNow() {
        scope.launch {
            val ok = withContext(Dispatchers.IO) { vm.pushConfig(target) }
            android.widget.Toast.makeText(context,
                if (ok) "已同步到目标 App" else "未连接，无法下发（配置已存本地）",
                android.widget.Toast.LENGTH_SHORT).show()
        }
    }

    /** 当前App模式：拨开关 = 写入覆盖 + 存本地 + 推送 */
    fun toggleOverride(key: String, v: Boolean) {
        val m = HashMap(overrideMap)
        m[key] = v
        overrideMap = m
        vm.saveAppConfig(target, m)
        val ok = vm.pushConfig(target)
        android.widget.Toast.makeText(context,
            if (ok) "已生效（${target}）" else "已保存覆盖（未连接，重连后自动生效）",
            android.widget.Toast.LENGTH_SHORT).show()
    }

    /** 重置为全局：清空该 App 全部覆盖 */
    fun resetApp() {
        overrideMap = emptyMap()
        vm.saveAppConfig(target, emptyMap())
        val ok = vm.pushConfig(target)
        android.widget.Toast.makeText(context,
            if (ok) "已重置为全局默认" else "已重置（未连接，重连后自动生效）",
            android.widget.Toast.LENGTH_SHORT).show()
    }

    /** 复制全局到本应用：把全局全量固化到该 App（以后改全局不影响它） */
    fun copyGlobalToApp() {
        val m = HashMap<String, Any>()
        for ((k, _) in OVERRIDABLE_SWITCHES) m[k] = globalBool(k)
        overrideMap = m
        vm.saveAppConfig(target, m)
        val ok = vm.pushConfig(target)
        android.widget.Toast.makeText(context,
            if (ok) "已复制全局到本应用" else "已复制（未连接，重连后自动生效）",
            android.widget.Toast.LENGTH_SHORT).show()
    }

    var dexkitOpen by remember { mutableStateOf(false) }
    var aboutOpen by remember { mutableStateOf(false) }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp)
    ) {
        // v1.23: 模式切换（全局默认 / 当前App）
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("配置", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold,
                modifier = Modifier.weight(1f).padding(top = 10.dp, bottom = 6.dp))
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            FilterChip(
                selected = mode == 0,
                onClick = { mode = 0 },
                label = { Text("全局默认") }
            )
            Spacer(Modifier.width(8.dp))
            FilterChip(
                selected = mode == 1,
                onClick = { mode = 1 },
                label = { Text(if (target.isEmpty()) "当前App（未选）" else "当前App：$target") }
            )
        }

        if (mode == 1 && target.isEmpty()) {
            Spacer(Modifier.height(6.dp))
            Text("请先在抓包页选择目标 App", style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error)
        }

        if (mode == 1) {
            // v1.23: 当前App覆盖概览 + 一键操作
            val ovCount = overrideMap.count { (k, v) -> k != "bodyLimit" && k != "logLimit" && k != "debug" }
            Spacer(Modifier.height(6.dp))
            Text("继承全局: ${OVERRIDABLE_SWITCHES.size - ovCount} 项 · 已覆盖: $ovCount 项",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            Row {
                OutlinedButton(onClick = { resetApp() }, modifier = Modifier.weight(1f)) {
                    Text("重置为全局", style = MaterialTheme.typography.labelSmall)
                }
                Spacer(Modifier.width(8.dp))
                OutlinedButton(onClick = { copyGlobalToApp() }, modifier = Modifier.weight(1f)) {
                    Text("复制全局到本应用", style = MaterialTheme.typography.labelSmall)
                }
            }
        }

        Spacer(Modifier.height(8.dp))

        // ===== 模块参数（只放全局）=====
        if (mode == 0) {
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerHigh),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
                    Text("模块参数（全局，不参与分应用覆盖）",
                        style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                    OutlinedTextField(
                        value = gBodyLimit,
                        onValueChange = { gBodyLimit = it },
                        label = { Text("响应体记录上限(字节)，0=不记录body") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = gLogLimit,
                        onValueChange = { gLogLimit = it },
                        label = { Text("日志环形缓冲上限(条)，默认 4096") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    SettingCheck("函数探测详细模式（参数/字段/调用栈）", globalBool("detailMode")) {
                        gSwitches = gSwitches + ("detailMode" to it)
                    }
                    SettingCheck("调试日志（日志页输出 [DBG] 模块运行状态，排查用）", gDebug) { gDebug = it }
                    Text("修改后点「保存并下发」生效", style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            Spacer(Modifier.height(10.dp))
        }

        // ===== 记录开关 =====
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerHigh),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
                Text("记录开关", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(top = 6.dp))
                if (mode == 0) {
                    // 全局模式：直接编辑全局
                    for ((k, label) in OVERRIDABLE_SWITCHES) {
                        SettingCheck(label, globalBool(k)) {
                            gSwitches = gSwitches + (k to it)
                        }
                    }
                } else {
                    // 当前App模式：继承/覆盖可视化
                    for ((k, label) in OVERRIDABLE_SWITCHES) {
                        SettingCheckInherit(
                            label = label,
                            checked = effBool(k),
                            overridden = isOverridden(k),
                            inherited = globalBool(k)
                        ) { v -> toggleOverride(k, v) }
                    }
                }
            }
        }

        Spacer(Modifier.height(10.dp))

        // ===== 反检测（v1.13，防目标 App 检测 hook 环境）=====
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerHigh),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
                Text("反检测（v1.13，防目标 App 检测 hook 环境）",
                    style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                if (mode == 0) {
                    SettingCheck("隐藏 root：File.exists(su)/Runtime.exec/SystemProperties 过滤", globalBool("antiRoot")) {
                        gSwitches = gSwitches + ("antiRoot" to it)
                    }
                    SettingCheck("隐藏 Xposed：loadClass/StackTrace/DexPathList/Modifier 净化", globalBool("antiXposed")) {
                        gSwitches = gSwitches + ("antiXposed" to it)
                    }
                } else {
                    SettingCheckInherit("隐藏 root：File.exists(su)/Runtime.exec/SystemProperties 过滤",
                        effBool("antiRoot"), isOverridden("antiRoot"), globalBool("antiRoot")) { v -> toggleOverride("antiRoot", v) }
                    SettingCheckInherit("隐藏 Xposed：loadClass/StackTrace/DexPathList/Modifier 净化",
                        effBool("antiXposed"), isOverridden("antiXposed"), globalBool("antiXposed")) { v -> toggleOverride("antiXposed", v) }
                }
                Text("与「探测」页的环境检测互为镜像：开反检测后可用 EnvProbe 验证目标 App 还检测到啥",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)

                // v1.23: 保存/同步按钮（全局模式保存全局；当前App模式手动同步）
                if (mode == 0) {
                    Button(onClick = { saveGlobalAndPush() }, modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
                        Text("保存并下发")
                    }
                } else {
                    Button(onClick = { pushNow() }, modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
                        Text("同步到目标 App")
                    }
                }
            }
        }

        Spacer(Modifier.height(10.dp))

        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerHigh),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
                Text("DexKit 反编译", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(bottom = 4.dp))
                Text("导出全部 dex（jadx 打开）+ 字符串反查方法（找校验/密钥/接口逻辑）",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Button(onClick = { dexkitOpen = true }, modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
                    Text("打开 DexKit 工具")
                }
            }
        }

        Spacer(Modifier.height(10.dp))

        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerHigh),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
                Text("关于", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                Text(
                    "SpyProbe v${BuildConfig.VERSION_NAME}（code ${BuildConfig.VERSION_CODE}）\n" +
                        "通用 Xposed 逆向探测模块：抓包 / 函数探测 / 返回值劫持 / DexKit 反编译 / native 层抓包\n" +
                        "GitHub: github.com/kiminbaek/SpyProbe\n" +
                        "许可证：不可商用，二次开发需注明原作者版权",
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(vertical = 4.dp)
                )
                Button(onClick = { aboutOpen = true }, modifier = Modifier.fillMaxWidth()) {
                    Text("完整说明")
                }
            }
        }
        Spacer(Modifier.height(24.dp))
    }

    if (dexkitOpen) {
        DexKitDialog(vm, onDismiss = { dexkitOpen = false })
    }
    if (aboutOpen) {
        AboutDialog(onDismiss = { aboutOpen = false })
    }
}

@Composable
private fun SettingCheck(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    // v1.16 P1-8: Checkbox → M3 Switch（语义是开关）
    Row(verticalAlignment = Alignment.CenterVertically) {
        Switch(checked = checked, onCheckedChange = { onChange(it) })
        Text(label, style = MaterialTheme.typography.bodySmall)
    }
}

/** v1.23: 当前App覆盖模式开关行（紫色=已覆盖本App，灰色小字=继承全局值） */
@Composable
private fun SettingCheckInherit(
    label: String,
    checked: Boolean,
    overridden: Boolean,
    inherited: Boolean,
    onChange: (Boolean) -> Unit
) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Switch(checked = checked, onCheckedChange = { onChange(it) })
        Column {
            Text(label, style = MaterialTheme.typography.bodySmall,
                color = if (overridden) Color(0xFFCE93D8) else MaterialTheme.colorScheme.onSurface)
            Text(if (overridden) "已覆盖（独立于全局）" else "继承全局: ${if (inherited) "开" else "关"}",
                style = MaterialTheme.typography.bodySmall,
                fontSize = 10.sp,
                color = if (overridden) Color(0xFFCE93D8) else MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

// ---------- DexKit 工具 ----------
@Composable
private fun DexKitDialog(vm: SpyViewModel, onDismiss: () -> Unit) {
    var str by remember { mutableStateOf("") }
    var result by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("DexKit 反编译") },
        text = {
            Column {
                Text("导出 dex 到 Download/SpyProbeDump/；字符串反查引用它的方法",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)

                Button(onClick = {
                    android.widget.Toast.makeText(context, "导出中…", android.widget.Toast.LENGTH_SHORT).show()
                    scope.launch {
                        val r = withContext(Dispatchers.IO) { vm.api.dexdump() }
                        android.widget.Toast.makeText(context, "导出结果: ${r ?: "未连接"}", android.widget.Toast.LENGTH_LONG).show()
                    }
                }, modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
                    Icon(Icons.Filled.Share, contentDescription = null)
                    Spacer(Modifier.width(6.dp))
                    Text("导出 dex 到 Download/SpyProbeDump/")
                }

                OutlinedTextField(
                    value = str,
                    onValueChange = { str = it },
                    placeholder = { Text("输入字符串，反查引用它的方法") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                Button(onClick = {
                    val s = str.trim()
                    if (s.isEmpty()) {
                        android.widget.Toast.makeText(context, "请输入字符串", android.widget.Toast.LENGTH_SHORT).show()
                        return@Button
                    }
                    android.widget.Toast.makeText(context, "反查中…", android.widget.Toast.LENGTH_SHORT).show()
                    scope.launch {
                        val r = withContext(Dispatchers.IO) { vm.api.stringFind(s) }
                        if (r == null) {
                            result = "未连接或失败"
                        } else {
                            result = try {
                                val o = org.json.JSONObject(r)
                                if (!o.optBoolean("ok", false)) {
                                    "反查失败: ${o.optString("error")}"
                                } else {
                                    val total = o.optInt("total", 0)
                                    val shown = o.optInt("shown", 0)
                                    val arr = o.optJSONArray("methods")
                                    val sb = StringBuilder("共 $total 个方法引用 \"$s\"\n\n")
                                    if (arr != null) {
                                        for (i in 0 until arr.length()) {
                                            val m = arr.getJSONObject(i)
                                            sb.append(m.optString("class")).append(".")
                                              .append(m.optString("method")).append("(")
                                              .append(m.optString("params")).append(")\n")
                                        }
                                    }
                                    if (shown < total) sb.append("\n…仅显示前 $shown 个")
                                    sb.toString()
                                }
                            } catch (t: Throwable) { "解析失败: $t" }
                        }
                    }
                }, modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
                    Icon(Icons.Filled.Search, contentDescription = null)
                    Spacer(Modifier.width(6.dp))
                    Text("字符串反查")
                }

                // v1.16 P2-14: 反查结果 200 方法可能溢出 → 垂直滚动 + 限高
                result?.let {
                    Text(it, style = MaterialTheme.typography.bodySmall,
                        fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace, fontSize = 10.sp,
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(max = 240.dp)
                            .verticalScroll(rememberScrollState()))
                }

                Button(onClick = {
                    scope.launch { withContext(Dispatchers.IO) { vm.api.dexclose() } }
                    android.widget.Toast.makeText(context, "已释放", android.widget.Toast.LENGTH_SHORT).show()
                }, modifier = Modifier.fillMaxWidth()) {
                    Icon(Icons.Filled.Close, contentDescription = null)
                    Spacer(Modifier.width(6.dp))
                    Text("释放 DexKit（省内存）")
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text("关闭") }
        }
    )
}

@Composable
private fun AboutDialog(onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("关于 SpyProbe") },
        text = {
            Text(
                "SpyProbe v${BuildConfig.VERSION_NAME}（code ${BuildConfig.VERSION_CODE}）\n\n" +
                    "通用 Xposed 逆向探测模块（LSPosed 作用域勾选目标 App 后生效）：\n" +
                    "• 网络抓包：OkHttp / HttpURLConnection / DNS / TCP / WebView / TLS 明文 / 连接点 / Cronet / native 层（libc+SSL）\n" +
                    "• 函数探测：扫描类成员、一键 hook、参数记录\n" +
                    "• 返回值劫持：强制返回 true/false/数字/文本\n" +
                    "• 类加载记录、URL 构造、Log 拦截、加密算法、Activity 生命周期、JSON 结构\n" +
                    "• DexKit：导出 dex + 字符串反查\n\n" +
                    "许可证：不可商用，二次开发需注明原作者版权",
                style = MaterialTheme.typography.bodySmall
            )
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text("OK") } }
    )
}
