package com.dustinky.spyprobe.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// v1.17: 主题现代化 —— 深色深蓝黑基调 + 卡片分层 + 统一圆角
// 主色保持绿色系（逆向/终端感），但整体从 #111111 平铺升级为卡片分层

private val DarkColors = darkColorScheme(
    primary = Color(0xFF66BB6A),
    onPrimary = Color(0xFF0A1F0D),
    primaryContainer = Color(0xFF1B3A22),
    onPrimaryContainer = Color(0xFFC8E6C9),
    secondary = Color(0xFF4FC3F7),
    onSecondary = Color(0xFF04222E),
    secondaryContainer = Color(0xFF123D4F),
    onSecondaryContainer = Color(0xFFB3E5FC),
    tertiary = Color(0xFFFFA726),
    onTertiary = Color(0xFF2A1604),
    background = Color(0xFF0F1218),
    onBackground = Color(0xFFE3E5E8),
    surface = Color(0xFF171B24),
    onSurface = Color(0xFFE3E5E8),
    surfaceVariant = Color(0xFF232936),
    onSurfaceVariant = Color(0xFFA6ADBB),
    outline = Color(0xFF3A4150),
    outlineVariant = Color(0xFF2A3140),
    error = Color(0xFFEF5350),
    onError = Color(0xFFFFFFFF),
    surfaceContainerLowest = Color(0xFF0F1218),
    surfaceContainerLow = Color(0xFF151922),
    surfaceContainer = Color(0xFF171B24),
    surfaceContainerHigh = Color(0xFF1D2230),
    surfaceContainerHighest = Color(0xFF232936)
)

private val LightColors = lightColorScheme(
    primary = Color(0xFF2E7D32),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFC8E6C9),
    onPrimaryContainer = Color(0xFF0A1F0D),
    secondary = Color(0xFF0277BD),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFB3E5FC),
    onSecondaryContainer = Color(0xFF04222E),
    tertiary = Color(0xFFE65100),
    onTertiary = Color(0xFFFFFFFF),
    background = Color(0xFFF7F8FA),
    onBackground = Color(0xFF1A1D24),
    surface = Color(0xFFFFFFFF),
    onSurface = Color(0xFF1A1D24),
    surfaceVariant = Color(0xFFEDEFF3),
    onSurfaceVariant = Color(0xFF4A5160),
    outline = Color(0xFF9AA1AF),
    outlineVariant = Color(0xFFDFE2E8),
    error = Color(0xFFC62828),
    onError = Color(0xFFFFFFFF),
    surfaceContainerLowest = Color(0xFFFFFFFF),
    surfaceContainerLow = Color(0xFFF7F8FA),
    surfaceContainer = Color(0xFFF2F3F6),
    surfaceContainerHigh = Color(0xFFECEEF2),
    surfaceContainerHighest = Color(0xFFE6E8ED)
)

@Composable
fun SpyProbeTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = if (darkTheme) DarkColors else LightColors,
        content = content
    )
}
