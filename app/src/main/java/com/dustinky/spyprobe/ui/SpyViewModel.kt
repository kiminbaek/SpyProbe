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
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.regex.Pattern

// v1.11: 状态管理 + 轮询（原 MainActivity 逻辑 Kotlin 化，保留端口扫描/应用列表）

data class AppInfo(val label: String, val pkg: String)

class SpyViewModel(app: Application) : AndroidViewModel(app) {

    private val prefs = app.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private val _targetPkg = MutableStateFlow(prefs.getString(KEY_TARGET, "") ?: "")
    val targetPkg: StateFlow<String> = _targetPkg.asStateFlow()

    private val _port = MutableStateFlow(prefs.getInt(KEY_PORT, 9901))
    val port: StateFlow<Int> = _port.asStateFlow()

    val api = SpyApi(_port.value)

    // 日志（v1.16 P0-2: Pair<seq, 行文本>，seq 自增唯一，LazyColumn key 用它防重复行崩溃）
    private val _logLines = MutableStateFlow<List<Pair<Long, String>>>(emptyList())
    val logLines: StateFlow<List<Pair<Long, String>>> = _logLines.asStateFlow()

    private var logSeq = 0L

    private val _filter = MutableStateFlow("")
    val filter: StateFlow<String> = _filter.asStateFlow()

    // 状态栏
    private val _status = MutableStateFlow("未连接（目标 App 需在运行）")
    val status: StateFlow<String> = _status.asStateFlow()

    private val _connected = MutableStateFlow(false)
    val connected: StateFlow<Boolean> = _connected.asStateFlow()

    private var since = 0L
    private var pollingJob: Job? = null

    companion object {
        const val PREFS = "spyprobe"
        const val KEY_TARGET = "target"
        const val KEY_PORT = "port"
        const val MAX_LOG_LINES = 3000
    }

    // ---------- 目标/端口 ----------
    fun setTarget(pkg: String) {
        _targetPkg.value = pkg
        prefs.edit().putString(KEY_TARGET, pkg).apply()
        refreshStatus()
    }

    fun setPort(p: Int) {
        _port.value = p
        api.setPort(p)
        prefs.edit().putInt(KEY_PORT, p).apply()
    }

    // ---------- 轮询 ----------
    fun startPolling() {
        if (pollingJob != null && pollingJob!!.isActive) return
        pollingJob = viewModelScope.launch {
            while (isActive) {
                val resp = withContext(Dispatchers.IO) { api.fetchLogs(since) }
                if (resp != null) {
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
                }
                delay(800)
            }
        }
    }

    fun stopPolling() {
        pollingJob?.cancel()
        pollingJob = null
    }

    fun setFilter(f: String) {
        _filter.value = f
    }

    fun clearLogs() {
        viewModelScope.launch {
            val resp = withContext(Dispatchers.IO) { api.clear() }
            _logLines.value = emptyList()
            since = 0
            _status.value = if (resp == null) "未连接" else "已清空"
        }
    }

    // ---------- 状态刷新（含端口自动发现） ----------
    fun refreshStatus() {
        viewModelScope.launch {
            val info = withContext(Dispatchers.IO) {
                var r = api.ping()
                if (r == null) {
                    val found = api.scanPorts()
                    if (found > 0) {
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
    fun sendConfig(map: Map<String, Any>) {
        viewModelScope.launch {
            withContext(Dispatchers.IO) { api.sendConfig(map) }
        }
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
