package com.dustinky.spyprobe.ui

import android.app.Application
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ResolveInfo
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.util.regex.Pattern

// v1.11: 状态管理 + 轮询（原 MainActivity 逻辑 Kotlin 化，保留端口扫描/应用列表）

data class AppInfo(val label: String, val pkg: String)

class SpyViewModel(app: Application) : AndroidViewModel(app) {

    private val prefs = app.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private val _targetPkg = MutableStateFlow(prefs.getString(KEY_TARGET, "") ?: "")
    val targetPkg: StateFlow<String> = _targetPkg.asStateFlow()

    private val _port = MutableStateFlow(prefs.getInt(KEY_PORT, 9901))
    val port: StateFlow<Int> = _port.asStateFlow()

    // v1.31: 工作模式（普通 / Root）——Root 模式历史日志直读目标沙箱文件，目标 App 可不在线
    private val _rootMode = MutableStateFlow(prefs.getBoolean(KEY_ROOT_MODE, false))
    val rootMode: StateFlow<Boolean> = _rootMode.asStateFlow()

    fun setRootMode(on: Boolean) {
        _rootMode.value = on
        prefs.edit().putBoolean(KEY_ROOT_MODE, on).apply()
        com.dustinky.spyprobe.util.UiLog.log("setRootMode: $on")
    }

    val api = SpyApi(_port.value)

    // 日志（v1.16 P0-2: Pair<seq, 行文本>，seq 自增唯一，LazyColumn key 用它防重复行崩溃）
    private val _logLines = MutableStateFlow<List<Pair<Long, String>>>(emptyList())
    val logLines: StateFlow<List<Pair<Long, String>>> = _logLines.asStateFlow()

    // v1.18: 日志条数（抓包页角标用，避免 collect 全量日志）
    val logCount: StateFlow<Int> = _logLines.map { it.size }.stateIn(
        viewModelScope, SharingStarted.Eagerly, 0
    )

    private var logSeq = 0L

    private val _filter = MutableStateFlow("")
    val filter: StateFlow<String> = _filter.asStateFlow()

    // v1.19 P2-2: 暂停状态提升到 ViewModel（此前在 LogsScreen 局部 remember，
    //   页面销毁重建时状态丢失 → 轮询被 stopPolling 但 UI 还显示"暂停"）
    private val _paused = MutableStateFlow(false)
    val paused: StateFlow<Boolean> = _paused.asStateFlow()

    // ---------- v1.27: 历史日志（落盘文件） ----------
    // v1.31: 数据源双模式——Root 模式直读目标沙箱文件（目标 App 可不在线）；
    //   普通模式走 HTTP（目标 App 需在线）。UI 层通过 rootMode 自动选择。
    // v1.33: 卡片从"天"升级为"会话"（目标进程每启动一次 = 一个会话，天然分开）
    private val _historySessions = MutableStateFlow<List<com.dustinky.spyprobe.util.HomeLogReader.SessionInfo>>(emptyList())
    val historySessions: StateFlow<List<com.dustinky.spyprobe.util.HomeLogReader.SessionInfo>> = _historySessions.asStateFlow()

    private val _historyLogs = MutableStateFlow<List<Pair<Long, String>>>(emptyList())
    val historyLogs: StateFlow<List<Pair<Long, String>>> = _historyLogs.asStateFlow()

    private val _historyLoading = MutableStateFlow(false)
    val historyLoading: StateFlow<Boolean> = _historyLoading.asStateFlow()

    // v1.31: 历史读取来源说明（UI 显示数据源 + 错误原因）
    private val _historySource = MutableStateFlow("")
    val historySource: StateFlow<String> = _historySource.asStateFlow()

    // v1.33: 当前选中会话（date + session）
    private val _selectedHistorySession = MutableStateFlow<com.dustinky.spyprobe.util.HomeLogReader.SessionInfo?>(null)
    val selectedHistorySession: StateFlow<com.dustinky.spyprobe.util.HomeLogReader.SessionInfo?> = _selectedHistorySession.asStateFlow()

    // 状态栏
    private val _status = MutableStateFlow("未连接（目标 App 需在运行）")
    val status: StateFlow<String> = _status.asStateFlow()

    private val _connected = MutableStateFlow(false)
    val connected: StateFlow<Boolean> = _connected.asStateFlow()

    private var since = 0L
    private var pollingJob: Job? = null

    // v1.18.1 修复: 轮询常驻 ViewModel（此前由页面 LaunchedEffect 控制，切到日志页时抓包页销毁触发
    // stopPolling 导致日志冻结）——现在任何页面都实时更新，暂停按钮才真正控制轮询
    init {
        startPolling()
    }

    companion object {
        const val PREFS = "spyprobe"
        const val KEY_TARGET = "target"
        const val KEY_PORT = "port"
        const val KEY_ROOT_MODE = "root_mode"
        const val KEY_FAV_DAYS = "fav_days"
        const val MAX_LOG_LINES = 3000
        // v1.23: 配置库 key（UI 本地为权威：全局默认 + 分应用覆盖）
        const val KEY_GLOBAL_CFG = "global_cfg"
        const val KEY_APP_CFG_PREFIX = "app_cfg_"
    }

    // ===== v1.23: 配置库（全局默认 + 分应用覆盖，UI 本地为权威）=====
    // 架构：开关真相存 UI 本地 prefs；目标进程只是执行端（内存 Config + data 缓存镜像）。
    //   全局默认: 全量项，适用于所有未覆盖的 App
    //   分应用覆盖: 只存"不一样"的项（key = app_cfg_<pkg>），未覆盖的项继承全局
    //   生效值 effective(pkg) = 全局 + 该 App 覆盖项
    //   保存永远在本地（不依赖连接）；连接后自动推送 effective 到目标进程

    /** 内置默认（与后端 Config 默认一致）
     *  v1.25 P1-1: 补 8 个缺失 key（sslBypass/okhttp/url/dns/tcp/classes/classFilter/classLogAll）——
     *  此前缺 key 导致「当前 App」Tab 里这些项读不到 effective 值、设置页继承逻辑失真 */
    fun defaultConfig(): Map<String, Any> = mapOf(
        "webView" to true,
        "prefs" to false,
        "sqlite" to true,
        "urlBuild" to true,
        "logcat" to true,
        "crypto" to false,
        "activity" to false,
        "json" to false,
        "detailMode" to true,
        "env" to true,
        "tls" to true,
        "connect" to true,
        "cronet" to false,
        "antiRoot" to false,
        "antiXposed" to false,
        "native" to true,
        "autoProbe" to false,
        "autoProbeFilter" to "",
        "sslBypass" to true,
        "okhttp" to true,
        "url" to true,
        "dns" to true,
        "tcp" to true,
        "classes" to true,
        "classFilter" to "",
        "classLogAll" to false,
        "bodyLimit" to 2, // v1.25 P1-2: 单位统一 KB（此前 2048=字节，与 UI KB 语义不一致）
        "logLimit" to 4096,
        "debug" to false
    )

    private fun parseCfgJson(s: String): Map<String, Any> {
        if (s.isEmpty()) return emptyMap()
        return try {
            val o = JSONObject(s)
            val m = HashMap<String, Any>()
            val it = o.keys()
            while (it.hasNext()) { val k = it.next(); o.opt(k)?.let { v -> m[k] = v } }
            m
        } catch (t: Throwable) { emptyMap() }
    }

    /** 全局默认配置（默认值 + 已保存覆盖） */
    fun loadGlobalConfig(): Map<String, Any> =
        defaultConfig() + parseCfgJson(prefs.getString(KEY_GLOBAL_CFG, "") ?: "")

    /** 保存全局默认配置 */
    fun saveGlobalConfig(map: Map<String, Any>) {
        prefs.edit().putString(KEY_GLOBAL_CFG, JSONObject(map as Map<*, *>).toString()).apply()
    }

    /** 某 App 的覆盖项（只存"不一样"的） */
    fun loadAppConfig(pkg: String): Map<String, Any> =
        parseCfgJson(prefs.getString(KEY_APP_CFG_PREFIX + pkg, "") ?: "")

    /** 保存某 App 覆盖项（空 map = 清空覆盖，完全跟随全局） */
    fun saveAppConfig(pkg: String, map: Map<String, Any>) {
        val e = prefs.edit()
        if (map.isEmpty()) e.remove(KEY_APP_CFG_PREFIX + pkg)
        else e.putString(KEY_APP_CFG_PREFIX + pkg, JSONObject(map as Map<*, *>).toString())
        e.apply()
    }

    /** 某 App 生效配置 = 全局 + 该 App 覆盖 */
    fun effectiveConfig(pkg: String): Map<String, Any> = loadGlobalConfig() + loadAppConfig(pkg)

    /** 推送 effective 配置到目标进程（同步，返回是否成功下发） */
    fun pushConfig(pkg: String): Boolean {
        if (pkg.isEmpty()) return false
        return try {
            sendConfig(effectiveConfig(pkg))
        } catch (t: Throwable) { false }
    }

    /**
     * v1.25 P0-2: 统一配置修改入口——抓包页/探测页/设置页当前 App Tab 都走这里。
     * 语义（UI 本地为权威）：把 key 设为 value → 保存到当前目标 App 的覆盖层（只存与全局不同的差异项）
     * → 推送 effective 到目标进程。
     * 返回是否成功下发：成功=true；未连接/false（配置已保存本地，连接后自动补发）。
     */
    fun setEffectiveSwitch(key: String, value: Any): Boolean {
        val pkg = _targetPkg.value
        if (pkg.isEmpty()) {
            com.dustinky.spyprobe.util.UiLog.log("setEffectiveSwitch: $key=$value 但 target 为空，跳过")
            return false
        }
        val global = loadGlobalConfig()
        val effective = global + loadAppConfig(pkg) + (key to value)
        // 只存差异项（与全局相同的不占位，避免覆盖项冗余）
        val overrides = HashMap<String, Any>()
        effective.forEach { (k, v) -> if (global[k] != v) overrides[k] = v }
        saveAppConfig(pkg, overrides)
        // v1.32: 权威配置同步到 SpyProbe 自己家（files/spyprobe_cfg.json）——
        // 目标进程下次启动从 :9900 拉这份，UI 改的开关（含 native）重启后依然生效
        try {
            com.dustinky.spyprobe.Config.get().applyJson(JSONObject(effective as Map<*, *>).toString())
            com.dustinky.spyprobe.Config.get().saveConfig(com.dustinky.spyprobe.Config.get().homeCfgFile())
        } catch (t: Throwable) {
            com.dustinky.spyprobe.util.UiLog.log("setEffectiveSwitch: save home cfg FAIL: $t")
        }
        val pushed = pushConfig(pkg)
        com.dustinky.spyprobe.util.UiLog.log("setEffectiveSwitch: $key=$value pushed=$pushed")
        return pushed
    }

    // ---------- 目标/端口 ----------
    fun setTarget(pkg: String) {
        _targetPkg.value = pkg
        prefs.edit().putString(KEY_TARGET, pkg).apply()
        // v1.36 P1-2: 切换目标后旧 since 失效（新 App 进程 seq 从 1 开始）→ 重置 + 清空旧日志，
        //   避免新 App 日志前段被旧 since 跳过
        since = 0
        _logLines.value = emptyList()
        com.dustinky.spyprobe.util.UiLog.log("setTarget: $pkg since 重置 0")
        refreshStatus()
    }

    fun setPort(p: Int) {
        _port.value = p
        api.setPort(p)
        prefs.edit().putInt(KEY_PORT, p).apply()
        com.dustinky.spyprobe.util.UiLog.log("setPort: $p")
    }

    // ---------- 轮询 ----------
    fun startPolling() {
        if (pollingJob != null && pollingJob!!.isActive) return
        pollingJob = viewModelScope.launch {
            // v1.23: 连接状态跟踪（断开→恢复时自动补发当前目标配置）
            var wasConnected = false
            while (isActive) {
                val resp = withContext(Dispatchers.IO) { api.fetchLogs(since) }
                if (resp != null) {
                    if (!wasConnected) {
                        wasConnected = true
                        // v1.36 P1-2: 连接恢复重置 since —— 目标进程重启后新进程 seq 从 1 开始，
                        //   旧 since（如 1234）轮询返回空且被更新为小值 → seq < since 的新日志永久跳过；
                        //   重置后全量重拉 + 清空旧列表（旧进程日志已无意义）
                        since = 0
                        _logLines.value = emptyList()
                        com.dustinky.spyprobe.util.UiLog.log("轮询: 连接恢复 target=${_targetPkg.value} port=${api.baseUrl()} since 重置 0")
                        // v1.23: 目标进程连接恢复 → 自动补发该 App 生效配置（本地权威推送到执行端）
                        val pkg = _targetPkg.value
                        if (pkg.isNotEmpty()) {
                            withContext(Dispatchers.IO) { api.sendConfig(effectiveConfig(pkg)) }
                        }
                        refreshStatus()
                        // v1.36 P1-2: 本轮 resp 是旧 since 拉的结果，跳过本轮追加，
                        //   下一轮 with since=0 全量重拉（不重复显示）
                        continue
                    }
                    val (newLogs, next) = resp
                    since = next
                    if (newLogs.isNotEmpty()) {
                        // v1.16 P0-2: 每行分配唯一自增 seq
                        val newLines = newLogs.flatMap { it.display().split("\n") }.map { Pair(++logSeq, it) }
                        val all = (_logLines.value + newLines)
                        _logLines.value = if (all.size > MAX_LOG_LINES) {
                            all.subList(all.size - MAX_LOG_LINES, all.size)
                        } else all
                    }
                } else {
                    wasConnected = false
                }
                delay(800)
            }
        }
    }

    fun stopPolling() {
        pollingJob?.cancel()
        pollingJob = null
    }

    // v1.19 P2-2: 暂停/继续轮询（状态提升，防页面重建状态错位）
    fun togglePaused() {
        if (_paused.value) {
            _paused.value = false
            startPolling()
        } else {
            _paused.value = true
            stopPolling()
        }
    }

    fun setFilter(f: String) {
        _filter.value = f
    }

    fun clearLogs() {
        viewModelScope.launch {
            com.dustinky.spyprobe.util.UiLog.log("clearLogs: 清空内存日志")
            val resp = withContext(Dispatchers.IO) { api.clear() }
            _logLines.value = emptyList()
            since = 0
            _status.value = if (resp == null) "未连接" else "已清空"
        }
    }

    // ---------- v1.27: 历史日志 ----------
    // v1.31: Root 模式直读目标沙箱落盘文件（目标 App 可不在线）
    // v1.33: 卡片 = 会话（目标进程每启动一次 = 一个会话）；主进程自己家优先（免 root 免目标在线）
    fun loadHistoryDays() {
        viewModelScope.launch {
            val sessions = withContext(Dispatchers.IO) {
                // v1.32: 第一优先 = SpyProbe 自己家（本地文件，免 root 免目标 App 在线）
                val homeSessions = com.dustinky.spyprobe.util.HomeLogReader.sessions(getApplication<Application>().filesDir)
                if (homeSessions.isNotEmpty()) {
                    _historySource.value = "本地：SpyProbe 自己家（免 root）"
                    homeSessions
                } else if (_rootMode.value) {
                    val pkg = _targetPkg.value
                    if (pkg.isEmpty()) {
                        _historySource.value = "Root 模式：请先在抓包页选择目标 App"
                        emptyList()
                    } else if (!com.dustinky.spyprobe.util.RootLogReader.checkRoot()) {
                        _historySource.value = "Root 模式：未检测到 root 权限，请确认已主动授权（或改回普通模式）"
                        emptyList()
                    } else {
                        _historySource.value = "Root 兜底：直读 ${pkg} 落盘文件（本地无历史时）"
                        // 旧版按天文件 → 包装成"会话 0"兼容展示
                        com.dustinky.spyprobe.util.RootLogReader.days(pkg).map { day ->
                            com.dustinky.spyprobe.util.HomeLogReader.SessionInfo(day, 0, 0, 0, "", "")
                        }
                    }
                } else {
                    _historySource.value = "普通模式：HTTP 读取（目标 App 需在线）"
                    (api.historyDays() ?: emptyList()).map { day ->
                        com.dustinky.spyprobe.util.HomeLogReader.SessionInfo(day, 0, 0, 0, "", "")
                    }
                }
            }
            _historySessions.value = sessions
            com.dustinky.spyprobe.util.UiLog.log("loadHistoryDays: sessions=${sessions.size} src=${_historySource.value}")
        }
    }

    // v1.31.1 P2-4: loadHistory 并发竞态——记录最近一次请求的 (day,session)，完成时丢弃过期结果
    //   （连续点击两个日期卡片时，旧请求后完成会覆盖新请求的数据 → 界面显示与 selectedDay 不匹配）
    @Volatile
    private var latestHistoryKey: String? = null

    fun loadHistory(session: com.dustinky.spyprobe.util.HomeLogReader.SessionInfo) {
        val key = "${session.date}#${session.session}"
        latestHistoryKey = key
        viewModelScope.launch {
            _historyLoading.value = true
            com.dustinky.spyprobe.util.UiLog.log("loadHistory: session=$key mode=${if (_rootMode.value) "root" else "http"}")
            val logs = withContext(Dispatchers.IO) {
                // v1.32: 第一优先 = SpyProbe 自己家（本地文件，免 root）
                val homeLogs = com.dustinky.spyprobe.util.HomeLogReader.readSession(getApplication<Application>().filesDir, session.date, session.session, 10000)
                if (homeLogs.isNotEmpty()) {
                    _historySource.value = "本地：SpyProbe 自己家（免 root）"
                    homeLogs.map { com.dustinky.spyprobe.ui.LogEntry(it.time, it.tag, it.msg) }
                } else if (_rootMode.value) {
                    val pkg = _targetPkg.value
                    if (pkg.isEmpty()) null
                    else com.dustinky.spyprobe.util.RootLogReader.readDay(pkg, session.date, 10000)
                        .map { com.dustinky.spyprobe.ui.LogEntry(it.time, it.tag, it.msg) }
                } else {
                    api.history(session.date, 10000)
                }
            }
            // 过期请求丢弃（期间用户又点了别的会话）
            if (latestHistoryKey != key) {
                com.dustinky.spyprobe.util.UiLog.log("loadHistory: session=$key 过期结果丢弃（当前 key=$latestHistoryKey）")
                return@launch
            }
            _historyLogs.value = logs?.mapIndexed { i, it -> Pair(i.toLong() + 1, it.display()) }
                ?: emptyList()
            com.dustinky.spyprobe.util.UiLog.log("loadHistory: session=$key entries=${logs?.size}")
            _historyLoading.value = false
        }
    }

    /** 清空历史：day=null 清全部（Root 模式直接删目标沙箱文件；普通模式走 HTTP） */
    fun clearHistory(day: String?, onDone: (Boolean) -> Unit = {}) {
        viewModelScope.launch {
            com.dustinky.spyprobe.util.UiLog.log("clearHistory: day=${day ?: "(全部)"} mode=${if (_rootMode.value) "root" else "http"}")
            val ok = withContext(Dispatchers.IO) {
                // v1.32: 第一优先清自己家（本地文件，免 root）；本地无文件再走 Root/HTTP
                val homeCleared = com.dustinky.spyprobe.util.HomeLogReader.clear(getApplication<Application>().filesDir, day)
                if (homeCleared) true
                else if (_rootMode.value) {
                    val pkg = _targetPkg.value
                    if (pkg.isEmpty()) false
                    else com.dustinky.spyprobe.util.RootLogReader.clear(pkg, day)
                } else {
                    api.clearHistory(day)
                }
            }
            if (ok) {
                loadHistoryDays()
                // v1.28 P1: day==null 清全部时也要清空展示列表（之前只清单天，界面残留旧数据）
                _historyLogs.value = emptyList()
            }
            com.dustinky.spyprobe.util.UiLog.log("clearHistory: ok=$ok")
            onDone(ok)
        }
    }

    /** v1.33: 清空单个会话（session=null 清全部）。本地优先（自己家文件）；旧按天文件按天清兜底 */
    fun clearHistorySession(session: com.dustinky.spyprobe.util.HomeLogReader.SessionInfo?, onDone: (Boolean) -> Unit = {}) {
        viewModelScope.launch {
            com.dustinky.spyprobe.util.UiLog.log("clearHistorySession: ${session?.let { "${it.date}#${it.session}" } ?: "(全部)"}")
            val ok = withContext(Dispatchers.IO) {
                if (session == null) {
                    com.dustinky.spyprobe.util.HomeLogReader.clear(getApplication<Application>().filesDir, null)
                } else {
                    // 先清精确会话（会话级文件）；若命中不到（旧按天文件）则清该天全部
                    val any = com.dustinky.spyprobe.util.HomeLogReader.clearSession(getApplication<Application>().filesDir, session.date, session.session)
                    if (any) true
                    else com.dustinky.spyprobe.util.HomeLogReader.clear(getApplication<Application>().filesDir, session.date)
                }
            }
            if (ok) {
                loadHistoryDays()
                _historyLogs.value = emptyList()
            }
            com.dustinky.spyprobe.util.UiLog.log("clearHistorySession: ok=$ok")
            onDone(ok)
        }
    }

    // v1.31: 收藏日期（SharedPreferences 字符串集合，本地持久化，不依赖连接）
    fun favoriteDays(): Set<String> =
        prefs.getStringSet(KEY_FAV_DAYS, emptySet()) ?: emptySet()

    fun isFavoriteDay(day: String): Boolean = favoriteDays().contains(day)

    fun toggleFavoriteDay(day: String) {
        val cur = HashSet(prefs.getStringSet(KEY_FAV_DAYS, emptySet()) ?: emptySet())
        if (!cur.add(day)) cur.remove(day)
        prefs.edit().putStringSet(KEY_FAV_DAYS, cur).apply()
        com.dustinky.spyprobe.util.UiLog.log("toggleFavoriteDay: $day fav=${cur.contains(day)}")
    }

    // ---------- 状态刷新（含端口自动发现） ----------
    fun refreshStatus() {
        viewModelScope.launch {
            val info = withContext(Dispatchers.IO) {
                var r = api.ping()
                if (r == null) {
                    val found = api.scanPorts()
                    if (found > 0) {
                        com.dustinky.spyprobe.util.UiLog.log("refreshStatus: 9901 不通，扫描发现端口 $found")
                        api.setPort(found)
                        _port.value = found
                        prefs.edit().putInt(KEY_PORT, found).apply()
                        r = api.ping()
                    }
                }
                r
            }
            if (info != null) {
                val sb = StringBuilder("● 已连接 ").append(info.pkg)
                if (info.versionName.isNotEmpty()) sb.append(" v").append(info.versionName)
                sb.append("  (日志 ").append(info.logCount).append(" 条 / 类 ").append(info.classCount).append(" 个)")
                _status.value = sb.toString()
                _connected.value = true
            } else {
                _status.value = "○ 未连接：请先打开目标 App（${api.baseUrl()}）"
                _connected.value = false
            }
        }
    }

    // ---------- 配置开关 ----------
    // v1.19 P2-1: 返回是否成功下发（成功=true；未连接/失败=false，UI 据此决定是否更新本地快照）
    //   runBlocking 同步等待：本地回环 HTTP 延迟 <10ms，开关点击场景可接受；保证 UI 能拿到真实结果
    fun sendConfig(map: Map<String, Any>): Boolean {
        return try {
            kotlinx.coroutines.runBlocking {
                withContext(Dispatchers.IO) { api.sendConfig(map) }
            }
        } catch (t: Throwable) { false }
    }

    // ---------- 应用列表 ----------
    fun loadApps(): List<AppInfo> = runCatching {
        val pm = getApplication<Application>().packageManager
        val launcher = Intent(Intent.ACTION_MAIN).apply { addCategory(Intent.CATEGORY_LAUNCHER) }
        val seen = HashSet<String>()
        val apps = ArrayList<AppInfo>()
        val ris: List<ResolveInfo> = pm.queryIntentActivities(launcher, 0)
        for (ri in ris) {
            val a = ri.activityInfo ?: continue
            val pkgName = a.packageName ?: continue
            if (pkgName == getApplication<Application>().packageName) continue
            if (!seen.add(pkgName)) continue
            val label = try { ri.loadLabel(pm).toString() } catch (t: Throwable) { pkgName }
            apps.add(AppInfo(label, pkgName))
        }
        apps.sortBy { it.label.lowercase() }
        apps
    }.getOrDefault(emptyList())
}
