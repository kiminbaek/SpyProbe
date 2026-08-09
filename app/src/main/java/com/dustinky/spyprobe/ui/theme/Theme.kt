package com.dustinky.spyprobe.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

// v1.24: 视觉系统重做 —— 终端/黑客风格（深蓝黑底 + 荧光绿强调）
// 三档 surface 分层 + 微光边框 + 统一字体层级
// v1.17: 主题现代化 —— 深色深蓝黑基调 + 卡片分层 + 统一圆角

private val DarkColors = darkColorScheme(
    primary = Color(0xFF00E676),          // 荧光绿（强调/选中/状态）
    onPrimary = Color(0xFF0A0E14),
    primaryContainer = Color(0xFF0D2818), // 深绿容器
    onPrimaryContainer = Color(0xFF69F0AE),
    secondary = Color(0xFF00E5FF),        // 青蓝（辅助信息）
    onSecondary = Color(0xFF002023),
    secondaryContainer = Color(0xFF003B42),
    onSecondaryContainer = Color(0xFF84FFFF),
    tertiary = Color(0xFFFFB300),         // 琥珀（警告/特殊）
    onTertiary = Color(0xFF2A1C00),
    tertiaryContainer = Color(0xFF4A3400),
    onTertiaryContainer = Color(0xFFFFD97A),
    error = Color(0xFFFF5252),             // 红（错误/断开）
    onError = Color(0xFF2D0000),
    errorContainer = Color(0xFF8C0000),
    onErrorContainer = Color(0xFFFFDAD6),
    background = Color(0xFF0A0E14),       // 全局底色
    onBackground = Color(0xFFE0E6ED),
    surface = Color(0xFF0F1419),          // surface 最低档
    onSurface = Color(0xFFE0E6ED),
    surfaceVariant = Color(0xFF1A212B),
    onSurfaceVariant = Color(0xFF8B96A8),
    outline = Color(0xFF2A3441),          // 边框
    outlineVariant = Color(0xFF1E2631),
    surfaceContainerLowest = Color(0xFF0A0E14),
    surfaceContainerLow = Color(0xFF0F1419),
    surfaceContainer = Color(0xFF141A22),
    surfaceContainerHigh = Color(0xFF1A212B),
    surfaceContainerHighest = Color(0xFF222B37),
    inverseSurface = Color(0xFFE0E6ED),
    inverseOnSurface = Color(0xFF0F1419),
    scrim = Color(0x88000000)
)

private val LightColors = lightColorScheme(
    primary = Color(0xFF00C853),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFC8FFD4),
    onPrimaryContainer = Color(0xFF00210B),
    secondary = Color(0xFF00B8D4),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFB2EBF2),
    onSecondaryContainer = Color(0xFF002023),
    tertiary = Color(0xFFFF8F00),
    onTertiary = Color(0xFFFFFFFF),
    tertiaryContainer = Color(0xFFFFE0B2),
    onTertiaryContainer = Color(0xFF2A1C00),
    error = Color(0xFFD32F2F),
    onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFFFCDD2),
    onErrorContainer = Color(0xFF8C0000),
    background = Color(0xFFF5F7FA),
    onBackground = Color(0xFF1A2028),
    surface = Color(0xFFFFFFFF),
    onSurface = Color(0xFF1A2028),
    surfaceVariant = Color(0xFFE8ECF0),
    onSurfaceVariant = Color(0xFF5A6574),
    outline = Color(0xFFB0BAC8),
    outlineVariant = Color(0xFFD0D7DF),
    surfaceContainerLowest = Color(0xFFFFFFFF),
    surfaceContainerLow = Color(0xFFF5F7FA),
    surfaceContainer = Color(0xFFEEF1F5),
    surfaceContainerHigh = Color(0xFFE3E8ED),
    surfaceContainerHighest = Color(0xFFD6DCE3)
)

// v1.24: 统一字体层级
private val SpyTypography = Typography(
    displayLarge = TextStyle(fontSize = 32.sp, fontWeight = FontWeight.Bold),
    headlineLarge = TextStyle(fontSize = 24.sp, fontWeight = FontWeight.Bold),
    headlineMedium = TextStyle(fontSize = 20.sp, fontWeight = FontWeight.Bold),
    headlineSmall = TextStyle(fontSize = 18.sp, fontWeight = FontWeight.SemiBold),
    titleLarge = TextStyle(fontSize = 16.sp, fontWeight = FontWeight.Bold),
    titleMedium = TextStyle(fontSize = 14.sp, fontWeight = FontWeight.SemiBold),
    titleSmall = TextStyle(fontSize = 13.sp, fontWeight = FontWeight.Medium),
    bodyLarge = TextStyle(fontSize = 15.sp, fontWeight = FontWeight.Normal),
    bodyMedium = TextStyle(fontSize = 14.sp, fontWeight = FontWeight.Normal),
    bodySmall = TextStyle(fontSize = 12.sp, fontWeight = FontWeight.Normal),
    labelLarge = TextStyle(fontSize = 13.sp, fontWeight = FontWeight.Medium),
    labelMedium = TextStyle(fontSize = 12.sp, fontWeight = FontWeight.Medium),
    labelSmall = TextStyle(fontSize = 10.sp, fontWeight = FontWeight.Medium, letterSpacing = 0.3.sp)
)

/** 代码字体样式（v1.24 统一） */
val codeStyle: TextStyle
    @Composable get() = MaterialTheme.typography.bodySmall.copy(
        fontFamily = FontFamily.Monospace,
        fontSize = 11.sp,
        lineHeight = 14.sp
    )

@Composable
fun SpyProbeTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = if (darkTheme) DarkColors else LightColors,
        typography = SpyTypography,
        content = content
    )
}
