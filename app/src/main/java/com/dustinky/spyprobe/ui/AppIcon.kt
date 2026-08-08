package com.dustinky.spyprobe.ui

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import android.util.LruCache

/**
 * v1.12: 应用图标懒加载 + 8MiB LRU 缓存（借鉴 Guise Reborn 的 AppIcon 设计）
 *
 * 只在列表项真正组合时才触发加载（LazyColumn 懒加载 = Guise 的"只为屏幕上
 * 组合的项目加载图标"）；缓存按 byteCount 计成本，超 8MiB 自动淘汰最久未用。
 */
object AppIconCache {

    private const val MAX_CACHE_BYTES = 8 * 1024 * 1024 // 8MiB（Guise 同款）

    private val cache = object : LruCache<String, Bitmap>(MAX_CACHE_BYTES) {
        override fun sizeOf(key: String, value: Bitmap): Int = value.byteCount
    }

    /** 同步加载图标（IO 线程调用）；失败返回 null，UI 显示占位块 */
    fun get(context: Context, pkg: String): Bitmap? {
        cache.get(pkg)?.let { return it }
        val bmp = try {
            drawableToBitmap(context.packageManager.getApplicationIcon(pkg))
        } catch (t: Throwable) {
            null
        }
        if (bmp != null) cache.put(pkg, bmp)
        return bmp
    }

    private fun drawableToBitmap(d: Drawable): Bitmap? {
        if (d is BitmapDrawable && d.bitmap != null) return d.bitmap
        return try {
            val w = if (d.intrinsicWidth > 0) d.intrinsicWidth else 64
            val h = if (d.intrinsicHeight > 0) d.intrinsicHeight else 64
            val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
            val canvas = Canvas(bmp)
            d.setBounds(0, 0, canvas.width, canvas.height)
            d.draw(canvas)
            bmp
        } catch (t: Throwable) { null }
    }
}
