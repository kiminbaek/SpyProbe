package com.dustinky.spyprobe.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
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
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.dustinky.spyprobe.BuildConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

// v1.11: 设置页 —— 高级配置（bodyLimit/webView/prefs/sqlite/urlBuild/logcat/crypto/activity/json/detailMode/env/tls/connect/cronet）+ DexKit + 关于

@Composable
fun SettingsScreen(vm: SpyViewModel, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    // 配置状态（默认值 = 后端 Config 默认）
    var bodyLimit by remember { mutableStateOf("2048") }
    var webView by remember { mutableStateOf(true) }
    var prefs by remember { mutableStateOf(false) }
    var sqlite by remember { mutableStateOf(true) }
    var urlBuild by remember { mutableStateOf(true) }
    var logcat by remember { mutableStateOf(true) }
    var crypto by remember { mutableStateOf(false) }
    var activity by remember { mutableStateOf(false) }
    var json by remember { mutableStateOf(false) }
    var detailMode by remember { mutableStateOf(true) }
    var env by remember { mutableStateOf(true) }
    var tls by remember { mutableStateOf(true) }
    var connect by remember { mutableStateOf(true) }
    var cronet by remember { mutableStateOf(false) }

    var dexkitOpen by remember { mutableStateOf(false) }
    var aboutOpen by remember { mutableStateOf(false) }

    fun sendAll() {
        val limit = bodyLimit.trim().toIntOrNull() ?: 2048
        vm.sendConfig(mapOf(
            "bodyLimit" to limit,
            "webView" to webView,
            "prefs" to prefs,
            "sqlite" to sqlite,
            "urlBuild" to urlBuild,
            "logcat" to logcat,
            "crypto" to crypto,
            "activity" to activity,
            "json" to json,
            "detailMode" to detailMode,
            "env" to env,
            "tls" to tls,
            "connect" to connect,
            "cronet" to cronet
        ))
        android.widget.Toast.makeText(context, "配置已下发", android.widget.Toast.LENGTH_SHORT).show()
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp)
    ) {
        Text("高级设置", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(top = 10.dp, bottom = 6.dp))

        OutlinedTextField(
            value = bodyLimit,
            onValueChange = { bodyLimit = it },
            label = { Text("响应体记录上限(字节)，0=不记录body") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )

        SettingCheck("记录 WebView.loadUrl", webView) { webView = it }
        SettingCheck("记录 SharedPreferences key（读取高频，建议按需开）", prefs) { prefs = it }
        SettingCheck("记录 SQLite 增删改查", sqlite) { sqlite = it }
        SettingCheck("记录 URL 构造（找接口地址/CDN 域名）", urlBuild) { urlBuild = it }
        SettingCheck("拦截 App 自身 Log 输出（信息量大）", logcat) { logcat = it }
        SettingCheck("记录加密算法/密钥/IV（Cipher，默认关防刷屏）", crypto) { crypto = it }
        SettingCheck("记录 Activity 生命周期 + Intent 跳转", activity) { activity = it }
        SettingCheck("记录 JSON/Gson 序列化结构", json) { json = it }
        SettingCheck("函数探测详细模式（参数/字段/调用栈）", detailMode) { detailMode = it }
        SettingCheck("记录环境检测（root/vpn/传感器/防截屏/设备指纹）", env) { env = it }
        SettingCheck("TLS 明文抓包（ConscryptEngine，HTTPS 明文头）", tls) { tls = it }
        SettingCheck("万能连接点记录（BlockGuardOs.connect，QUIC/自建TCP）", connect) { connect = it }
        SettingCheck("Cronet 网络栈记录（字节系 app，默认关防重复）", cronet) { cronet = it }

        Button(onClick = { sendAll() }, modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
            Text("下发配置")
        }

        HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

        Text("DexKit 反编译", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(bottom = 4.dp))
        Text("导出全部 dex（jadx 打开）+ 字符串反查方法（找校验/密钥/接口逻辑）",
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Button(onClick = { dexkitOpen = true }, modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
            Text("打开 DexKit 工具")
        }

        HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

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
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = checked, onCheckedChange = { onChange(it) })
        Text(label, style = MaterialTheme.typography.bodySmall)
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

                result?.let {
                    Text(it, style = MaterialTheme.typography.bodySmall,
                        fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace, fontSize = 10.sp)
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
