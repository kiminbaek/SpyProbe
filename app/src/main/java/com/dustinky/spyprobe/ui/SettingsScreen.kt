package com.dustinky.spyprobe.ui

import com.dustinky.spyprobe.BuildConfig
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
    val rootMode by vm.rootMode.collectAsState()

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
            loading = false
            // v1.31.1 P3-14: loading 结束后按「当前」cfgLevel/targetPkg 加载 displayCfg
            //   （此前 loading 期间切 Tab，LaunchedEffect 被跳过，displayCfg 短暂显示全局配置）
            displayCfg = if (cfgLevel == 0) g
            else withContext(Dispatchers.IO) { vm.loadAppConfig(targetPkg) }
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

        // ===== v1.31: 工作模式（普通 / Root）=====
        // Root 模式：本地无历史时兜底直读目标 App 沙箱落盘文件（目标 App 可不在线）
        // 授权模型：本 App 不主动触发 su 授权弹窗（Magisk 默认策略不弹窗），
        //   用户需主动授权；无权限时自动提示并回退普通模式。
        // v1.36 P1-3: v1.32 起日志已搬回 SpyProbe 自己家（HomeLogReader 免 root 直读），
        //   Root 模式仅作"本地无历史时"的兜底，文案同步降级避免误导。
        SettingsGroup(
            title = "工作模式",
            subtitle = "本地优先，Root 兜底",
            expanded = expanded.contains("mode"),
            onToggle = { toggle("mode") }
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("Root 兜底", style = MaterialTheme.typography.bodySmall, fontSize = 12.sp)
                    Text(
                        if (rootMode) "本地无历史时直读目标沙箱（目标 App 可不在线）" else "普通模式：仅读本地日志（v1.32 起免 root）",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        fontSize = 10.sp
                    )
                }
                Switch(
                    checked = rootMode,
                    onCheckedChange = { on ->
                        scope.launch {
                            if (on) {
                                // 切 Root 前检测权限（不弹窗）；无权限提示并保持普通模式
                                val hasRoot = withContext(Dispatchers.IO) {
                                    com.dustinky.spyprobe.util.RootLogReader.checkRoot()
                                }
                                com.dustinky.spyprobe.util.UiLog.log("Settings: 切 Root 模式 checkRoot=$hasRoot")
                                if (hasRoot) {
                                    vm.setRootMode(true)
                                    android.widget.Toast.makeText(context, "Root 兜底已开启（本地无历史时直读文件）", android.widget.Toast.LENGTH_SHORT).show()
                                } else {
                                    android.widget.Toast.makeText(context, "未检测到 root 权限：请先完成授权（Magisk/KernelSU）", android.widget.Toast.LENGTH_LONG).show()
                                }
                            } else {
                                vm.setRootMode(false)
                                android.widget.Toast.makeText(context, "已切回普通模式", android.widget.Toast.LENGTH_SHORT).show()
                            }
                        }
                    }
                )
            }
        }

        Spacer(Modifier.height(8.dp))

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
            // v1.38 (hooker 借鉴): 3 个新开关
            Divider()
            BoolSetting(effective, "keystore", "证书 Dump (mTLS)", false,
                inherited = inh("keystore"),
                onSet = { setCfg("keystore", it) })
            Divider()
            BoolSetting(effective, "keylog", "SSL KeyLog", false,
                inherited = inh("keylog"),
                onSet = { setCfg("keylog", it) })
            Divider()
            BoolSetting(effective, "webViewDebug", "WebView 调试", false,
                inherited = inh("webViewDebug"),
                onSet = { setCfg("webViewDebug", it) })
            // v1.39 P0 (r0capture 借鉴): pcap 导出开关（native TLS 明文 → 标准 pcap，Wireshark 直开）
            Divider()
            BoolSetting(effective, "pcap", "pcap 导出 (Wireshark)", false,
                inherited = inh("pcap"),
                onSet = { setCfg("pcap", it) })
            // v1.39.1: 导出 pcap 按钮放开关正下方（与调试日志分开——pcap=抓包明文，调试日志=排障内部日志）
            var pcapStatus by remember { mutableStateOf("") }
            Button(
                onClick = {
                    com.dustinky.spyprobe.util.UiLog.log("Settings: 点击「导出 pcap」")
                    scope.launch {
                        pcapStatus = withContext(Dispatchers.IO) {
                            try {
                                // 先让目标进程把活跃会话 flush 到主进程（在线时）
                                vm.api.httpPost("/api/flush_pcap", "{}")
                            } catch (t: Throwable) { }
                            val bytes = com.dustinky.spyprobe.PcapStore.get().exportAllBytes()
                            if (bytes == null || bytes.size <= 24) {
                                "暂无 pcap 数据（需先开 pcap 开关并抓包，TLS 连接关闭后落盘）"
                            } else {
                                val uri = com.dustinky.spyprobe.util.ShareLogUtil.writePcapFile(context, bytes)
                                if (uri == null) {
                                    "pcap 写文件失败（详见 UiLog）"
                                } else {
                                    val err = com.dustinky.spyprobe.util.ShareLogUtil.shareUri(
                                        context,
                                        "SpyProbe pcap ${bytes.size / 1024}KB",
                                        uri
                                    )
                                    if (err != null) "分享失败：$err" else "已导出 pcap（${bytes.size / 1024}KB），可在 Download/SpyProbe/ 找到"
                                }
                            }
                        }
                        android.widget.Toast.makeText(context, pcapStatus, android.widget.Toast.LENGTH_LONG).show()
                    }
                },
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp)
            ) {
                Text("导出 pcap（Wireshark 直开 TLS 明文）")
            }
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
        // v1.36 P1-5: 删除 autoProbe 开关（双入口冗余）——完整入口（开关+过滤器+说明）在
        //   「探测」页「全自动」Tab，设置页改为提示跳转，避免两处状态不同步/用户困惑。
        SettingsGroup(
            title = "Hook 引擎",
            subtitle = "全自动探测",
            expanded = expanded.contains("hook"),
            onToggle = { toggle("hook") }
        ) {
            Text(
                "全自动探测开关与过滤关键字在「探测」页「全自动」Tab 中设置",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontSize = 12.sp,
                modifier = Modifier.padding(vertical = 6.dp)
            )
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

            // v1.38 P2-8: 类名模糊搜索 → 自动生成 hook 清单（hooker gs 命令借鉴）
            Divider()
            var findClassStr by remember { mutableStateOf("") }
            var classResult by remember { mutableStateOf("") }
            OutlinedTextField(
                value = findClassStr,
                onValueChange = { findClassStr = it },
                label = { Text("类名搜索 (生成 hook 清单)", fontSize = 12.sp) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(6.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = {
                    scope.launch {
                        classResult = withContext(Dispatchers.IO) { vm.api.classFind(findClassStr) }
                            ?: "失败"
                    }
                }, enabled = findClassStr.isNotEmpty()) {
                    Text("搜索", fontSize = 12.sp)
                }
            }
            if (classResult.isNotEmpty()) {
                Text(
                    classResult.take(800),
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
            AboutRow("版本", "v${BuildConfig.VERSION_NAME}")
            Divider()
            AboutRow("作者", "SpyProbe Team")
            Divider()
            AboutRow("许可证", "自定义 (非商用)")
            Divider()

            // ===== v1.37 P0-4: 检查更新 =====
            var updateStatus by remember { mutableStateOf("") }
            var updateInfo by remember { mutableStateOf<com.dustinky.spyprobe.Updater.UpdateInfo?>(null) }
            var downloading by remember { mutableStateOf(false) }
            var downloadPct by remember { mutableStateOf(0) }
            Button(
                onClick = {
                    com.dustinky.spyprobe.util.UiLog.log("Settings: 点击「检查更新」")
                    updateStatus = "检查中…"
                    updateInfo = null
                    scope.launch {
                        updateStatus = withContext(Dispatchers.IO) {
                            when (val r = com.dustinky.spyprobe.Updater.checkUpdate()) {
                                is com.dustinky.spyprobe.Updater.CheckResult.Latest ->
                                    "已是最新版本 (v${BuildConfig.VERSION_NAME})"
                                is com.dustinky.spyprobe.Updater.CheckResult.Fail ->
                                    "检查失败：${r.reason}"
                                is com.dustinky.spyprobe.Updater.CheckResult.Update -> {
                                    updateInfo = r.info
                                    "发现新版本 v${r.info.latestVersion}"
                                }
                            }
                        }
                    }
                },
                enabled = !downloading,
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp)
            ) {
                Text(if (downloading) "下载中… $downloadPct%" else "检查更新")
            }
            if (updateStatus.isNotEmpty()) {
                Text(updateStatus, style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 4.dp), fontSize = 11.sp)
            }
            val upInfo = updateInfo
            if (upInfo != null && !downloading) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(top = 6.dp)) {
                    Button(onClick = {
                        scope.launch {
                            downloading = true
                            downloadPct = 0
                            com.dustinky.spyprobe.util.UiLog.log("Settings: 开始下载更新 v${upInfo.latestVersion}")
                            val dest = java.io.File(context.filesDir, "update.apk")
                            val ok = withContext(Dispatchers.IO) {
                                com.dustinky.spyprobe.Updater.download(upInfo.downloadUrl, dest) { pct ->
                                    downloadPct = pct
                                }
                            }
                            if (!ok) {
                                updateStatus = "下载失败（网络/镜像不可用）"
                                downloading = false
                            } else {
                                updateStatus = "下载完成，校验中…"
                                val err = withContext(Dispatchers.IO) {
                                    com.dustinky.spyprobe.Updater.verify(context, dest, upInfo.sha256)
                                }
                                if (err != null) {
                                    updateStatus = "校验失败：$err"
                                    downloading = false
                                } else {
                                    updateStatus = "校验通过，安装中…"
                                    val installed = withContext(Dispatchers.IO) {
                                        com.dustinky.spyprobe.Updater.installRoot(dest)
                                    }
                                    if (installed) {
                                        updateStatus = "已静默安装，重启 SpyProbe 生效"
                                        downloading = false
                                    } else {
                                        // root 失败 → 系统安装器
                                        updateStatus = "静默安装失败，改用系统安装器"
                                        val started = withContext(Dispatchers.IO) {
                                            com.dustinky.spyprobe.Updater.installSystem(context, dest)
                                        }
                                        updateStatus = if (started) "已打开系统安装器" else "系统安装器启动失败"
                                        downloading = false
                                    }
                                }
                            }
                        }
                    }) { Text("下载并更新", fontSize = 12.sp) }
                    TextButton(onClick = { updateInfo = null; updateStatus = "" }) {
                        Text("忽略", fontSize = 12.sp)
                    }
                }
                if (upInfo.body.isNotBlank()) {
                    Text(upInfo.body.take(200), style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 4.dp), fontSize = 10.sp, maxLines = 3)
                }
            }
            Divider()
            // v1.29: 独立调试日志 —— 排查"历史无记录/导出失败/重启丢日志"一键分享
            // v1.30.1: 合并目标进程 DebugLog + UI 进程 UiLog（导出失败原因在 UiLog 里）
            var debugMsg by remember { mutableStateOf("") }
            Button(
                onClick = {
                    // v1.30.2: 点击本身留痕（用户说"每一步都要日志"）
                    com.dustinky.spyprobe.util.UiLog.log("Settings: 点击「发送调试日志」")
                    scope.launch {
                        debugMsg = withContext(Dispatchers.IO) {
                            val info = vm.api.debugLog()
                            val target = if (info == null) {
                                "未连接目标进程（${vm.api.lastHttpError.ifEmpty { "HTTP 无响应" }}）"
                            } else {
                                "persist init: ${info.init}\ndir: ${info.dir}\n====================\n${info.text}"
                            }
                            buildString {
                                append("SpyProbe v${BuildConfig.VERSION_NAME} 调试日志\n")
                                append("===== 目标进程 DebugLog =====\n")
                                append(target)
                                append("\n\n===== UI 进程 UiLog =====\n")
                                val ui = com.dustinky.spyprobe.util.UiLog.dump()
                                append(if (ui.isEmpty()) "（无记录）" else ui)
                            }
                        }
                        // v1.30: 写 txt 文件分享（替代 ACTION_SEND 纯文本，长日志不截断、可保存）
                        // v1.30.3: 写文件在 IO 线程，startActivity 主线程
                        val uri = withContext(Dispatchers.IO) {
                            com.dustinky.spyprobe.util.ShareLogUtil.writeLogTxtFile(
                                context,
                                "spyprobe_debuglog",
                                debugMsg
                            )
                        }
                        if (uri == null) {
                            com.dustinky.spyprobe.util.UiLog.log("Settings: 调试日志写文件失败 len=${debugMsg.length}")
                            android.widget.Toast.makeText(context, "导出失败：无法写入 txt 文件（详见 UiLog）", android.widget.Toast.LENGTH_LONG).show()
                        } else {
                            val err = com.dustinky.spyprobe.util.ShareLogUtil.shareUri(
                                context,
                                "SpyProbe 调试日志 v${BuildConfig.VERSION_NAME}",
                                uri
                            )
                            if (err != null) {
                                com.dustinky.spyprobe.util.UiLog.log("Settings: 调试日志分享失败 $err")
                                android.widget.Toast.makeText(context, "导出失败：$err", android.widget.Toast.LENGTH_LONG).show()
                            } else {
                                com.dustinky.spyprobe.util.UiLog.log("Settings: 调试日志导出成功 len=${debugMsg.length}")
                            }
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp)
            ) {
                Text("发送调试日志（含 UI 侧，排查导出失败）")
            // v1.39 P0: 导出 pcap 按钮已移至「通用」区块（pcap 开关正下方），
            // 与调试日志分开 —— 调试日志=排障内部日志，pcap=抓包明文数据，语义不同
        }
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
