package com.dustinky.spyprobe.ui

import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel

// v1.24: 主框架优化 —— 终端风格顶栏 + 语义化图标 + 统一间距
// v1.18: Compose 主界面 —— 5 Tab 底部导航（日志页独立）

private data class TabItem(val title: String, val icon: ImageVector)

private val tabs = listOf(
    TabItem("抓包", Icons.Filled.Build),   // 用 Build 代表"分析/抓包工具"
    TabItem("探测", Icons.Filled.Lock),    // 用 Lock 代表"探测/反编译"
    TabItem("Hook", Icons.Filled.Lock),    // 锁 = Hook/劫持
    TabItem("日志", Icons.Filled.Build),   // Build = 日志/工具列表
    TabItem("设置", Icons.Filled.Settings)
)

// v1.24: 终端黑客风格顶栏 —— 深色底 + 荧光绿标题 + 小圆角分割
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(vm: SpyViewModel = viewModel()) {
    var selected by rememberSaveable { mutableIntStateOf(0) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        "SpyProbe · ${tabs[selected].title}",
                        fontWeight = FontWeight.Bold,
                        fontSize = 18.sp,
                        color = MaterialTheme.colorScheme.primary
                    )
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = MaterialTheme.colorScheme.primary,
                    scrolledContainerColor = MaterialTheme.colorScheme.surface
                )
            )
        },
        bottomBar = {
            NavigationBar(
                containerColor = MaterialTheme.colorScheme.surface,
                contentColor = MaterialTheme.colorScheme.onSurface
            ) {
                tabs.forEachIndexed { i, tab ->
                    NavigationBarItem(
                        selected = selected == i,
                        onClick = { selected = i },
                        icon = {
                            Icon(
                                tab.icon,
                                contentDescription = tab.title,
                                modifier = Modifier.size(22.dp)
                            )
                        },
                        label = {
                            Text(
                                tab.title,
                                fontSize = 11.sp,
                                fontWeight = if (selected == i) FontWeight.SemiBold else FontWeight.Normal
                            )
                        }
                    )
                }
            }
        },
        containerColor = MaterialTheme.colorScheme.background
    ) { padding ->
        when (selected) {
            0 -> CaptureScreen(vm, onOpenLogs = { selected = 3 }, Modifier.padding(padding))
            1 -> ProbeScreen(vm, Modifier.padding(padding))
            2 -> HooksScreen(vm, Modifier.padding(padding))
            3 -> LogsScreen(vm, Modifier.padding(padding))
            else -> SettingsScreen(vm, Modifier.padding(padding))
        }
    }
}
