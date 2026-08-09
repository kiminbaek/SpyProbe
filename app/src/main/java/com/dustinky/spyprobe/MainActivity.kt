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
