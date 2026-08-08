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
        enableEdgeToEdge()
        setContent {
            SpyProbeTheme {
                MainScreen()
            }
        }
    }
}
