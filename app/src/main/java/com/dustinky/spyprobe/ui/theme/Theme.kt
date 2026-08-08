package com.dustinky.spyprobe.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// v1.11: Material3 主题 —— 深色为主（沿用原 #111111 黑客风格），浅色也支持

private val DarkColors = darkColorScheme(
    primary = Color(0xFF81C784),
    onPrimary = Color(0xFF0A1F0D),
    primaryContainer = Color(0xFF1B3A22),
    onPrimaryContainer = Color(0xFFB9F6CA),
    secondary = Color(0xFF80CBC4),
    onSecondary = Color(0xFF0A1F1D),
    secondaryContainer = Color(0xFF1B3A36),
    onSecondaryContainer = Color(0xFFB2DFDB),
    tertiary = Color(0xFFF4A259),
    onTertiary = Color(0xFF2A1604),
    background = Color(0xFF111111),
    onBackground = Color(0xFFE0E0E0),
    surface = Color(0xFF1A1A1A),
    onSurface = Color(0xFFE0E0E0),
    surfaceVariant = Color(0xFF262626),
    onSurfaceVariant = Color(0xFFB0B0B0),
    outline = Color(0xFF555555),
    error = Color(0xFFEF5350),
    onError = Color(0xFFFFFFFF)
)

private val LightColors = lightColorScheme(
    primary = Color(0xFF2E7D32),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFB9F6CA),
    onPrimaryContainer = Color(0xFF0A1F0D),
    secondary = Color(0xFF00897B),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFB2DFDB),
    onSecondaryContainer = Color(0xFF0A1F1D),
    tertiary = Color(0xFFE65100),
    onTertiary = Color(0xFFFFFFFF),
    background = Color(0xFFFAFAFA),
    onBackground = Color(0xFF1A1A1A),
    surface = Color(0xFFFFFFFF),
    onSurface = Color(0xFF1A1A1A),
    surfaceVariant = Color(0xFFEEEEEE),
    onSurfaceVariant = Color(0xFF555555),
    outline = Color(0xFF999999),
    error = Color(0xFFC62828),
    onError = Color(0xFFFFFFFF)
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
