package com.dustinky.spyprobe.ui

import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Call
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
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.lifecycle.viewmodel.compose.viewModel

// v1.11: Compose 主界面 —— 4 Tab 底部导航

private data class TabItem(val title: String, val icon: ImageVector)

private val tabs = listOf(
    TabItem("抓包", Icons.Filled.Call),
    TabItem("探测", Icons.Filled.Build),
    TabItem("Hook", Icons.Filled.Lock),
    TabItem("设置", Icons.Filled.Settings)
)

// v1.16 P2-16: TopAppBar 标题栏统一（此前各页用普通 Text 标题，无一致性）
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(vm: SpyViewModel = viewModel()) {
    var selected by rememberSaveable { mutableIntStateOf(0) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(tabs[selected].title, fontWeight = androidx.compose.ui.text.font.FontWeight.Bold) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                    titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer
                )
            )
        },
        bottomBar = {
            NavigationBar {
                tabs.forEachIndexed { i, tab ->
                    NavigationBarItem(
                        selected = selected == i,
                        onClick = { selected = i },
                        icon = { Icon(tab.icon, contentDescription = tab.title) },
                        label = { Text(tab.title) }
                    )
                }
            }
        }
    ) { padding ->
        when (selected) {
            0 -> CaptureScreen(vm, Modifier.padding(padding))
            1 -> ProbeScreen(vm, Modifier.padding(padding))
            2 -> HooksScreen(vm, Modifier.padding(padding))
            else -> SettingsScreen(vm, Modifier.padding(padding))
        }
    }
}
