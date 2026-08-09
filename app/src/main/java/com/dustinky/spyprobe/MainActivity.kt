package com.dustinky.spyprobe

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import com.dustinky.spyprobe.ui.MainScreen
import com.dustinky.spyprobe.ui.theme.SpyProbeTheme

// v1.11: Compose UI 重构 —— 替换原 1408 行纯代码 UI（MainActivity.java）
// 后端（ModuleMain/SpyServer/NetProbe/Config/LogStore/native）零改动
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // v1.30.1: UI 进程自己的调试日志（导出失败原因定位）
        com.dustinky.spyprobe.util.UiLog.init(applicationContext)
        com.dustinky.spyprobe.util.UiLog.log("MainActivity onCreate, v=${BuildConfig.VERSION_NAME}")
        // v1.32: 数据面初始化 —— 日志/配置全部放 SpyProbe 自己家（不再依赖目标 App data）
        // ① 日志落盘自己家：files/spyprobe_logs/（目标进程推回来的日志写这里，历史免 root）
        try {
            com.dustinky.spyprobe.LogPersister.get().init(applicationContext.filesDir)
        } catch (t: Throwable) {
            com.dustinky.spyprobe.util.UiLog.log("Home init LogPersister FAIL: $t")
        }
        // ② 权威配置自己家：files/spyprobe_cfg.json（目标进程启动时从 :9900 拉）
        try {
            com.dustinky.spyprobe.Config.get().loadConfig(
                java.io.File(applicationContext.filesDir, "spyprobe_cfg.json"))
        } catch (t: Throwable) {
            com.dustinky.spyprobe.util.UiLog.log("Home init Config FAIL: $t")
        }
        // ③ 数据面 server（目标进程日志推送 / 配置拉取的接收端）
        try {
            com.dustinky.spyprobe.SpyHomeServer.get().start()
        } catch (t: Throwable) {
            com.dustinky.spyprobe.util.UiLog.log("Home server start FAIL: $t")
        }
        enableEdgeToEdge()
        setContent {
            SpyProbeTheme {
                MainScreen()
            }
        }
    }

    // v1.30.2: 生命周期每步留痕（用户要"每一步都写日志"；后台恢复/锁屏重连问题能定位）
    override fun onStart() {
        super.onStart()
        com.dustinky.spyprobe.util.UiLog.log("MainActivity onStart")
    }

    override fun onResume() {
        super.onResume()
        com.dustinky.spyprobe.util.UiLog.log("MainActivity onResume")
    }

    override fun onPause() {
        super.onPause()
        com.dustinky.spyprobe.util.UiLog.log("MainActivity onPause")
    }

    override fun onStop() {
        super.onStop()
        com.dustinky.spyprobe.util.UiLog.log("MainActivity onStop")
    }

    override fun onDestroy() {
        super.onDestroy()
        com.dustinky.spyprobe.util.UiLog.log("MainActivity onDestroy")
    }
}
