package com.dustinky.spyprobe.util

import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import androidx.core.content.FileProvider
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * v1.30: 日志导出统一改为"写 txt 文件 + 分享文件"。
 * 之前用 ACTION_SEND 纯文本（EXTRA_TEXT）——日志一大就被系统分享截断/丢失（用户实测导出失败）。
 * 现在：
 *  - Android 10+（API 29+）：写公共 Download/SpyProbe/ 目录（MediaStore 免权限），用户文件管理器直接可见、可拷出
 *  - Android 9-（API 26-28）：写 app 专属外部目录 logs/，经 FileProvider 分享出去（QQ/微信保存为 txt）
 * v1.30.1: 失败时返回具体错误信息（string）+ UiLog 记录，UI 能显示根因。
 */
object ShareLogUtil {

    /** 生成唯一文件名时间戳 */
    fun timestamp(): String =
        SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())

    /**
     * 把日志内容写成 txt 文件并返回可分享的 Uri（content://）。
     * 失败返回 null。
     */
    fun writeLogTxt(context: Context, prefix: String, content: String): Uri? {
        val filename = "${prefix}_${timestamp()}.txt"
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                writePublicDownload(context, filename, content) ?: writeAppExternal(context, filename, content)
            } else {
                writeAppExternal(context, filename, content)
            }
        } catch (e: Exception) {
            UiLog.log("writeLogTxt failed: ${e.javaClass.simpleName}: ${e.message}")
            null
        }
    }

    /** 公共 Download/SpyProbe/ 目录（Android 10+ 免权限，文件管理器可见） */
    private fun writePublicDownload(context: Context, filename: String, content: String): Uri? {
        return try {
            val values = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, filename)
                put(MediaStore.Downloads.MIME_TYPE, "text/plain")
                put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/SpyProbe")
            }
            val uri = context.contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
            if (uri == null) {
                UiLog.log("writePublicDownload: MediaStore insert null")
                return null
            }
            context.contentResolver.openOutputStream(uri)?.use { out ->
                out.write(content.toByteArray(Charsets.UTF_8))
            } ?: run {
                UiLog.log("writePublicDownload: openOutputStream null")
                return null
            }
            UiLog.log("writePublicDownload OK: $filename len=${content.length}")
            uri
        } catch (e: Exception) {
            UiLog.log("writePublicDownload fail: ${e.javaClass.simpleName}: ${e.message}")
            null
        }
    }

    /** app 专属外部目录（老系统 / 公共目录失败兜底，经 FileProvider 分享） */
    private fun writeAppExternal(context: Context, filename: String, content: String): Uri? {
        return try {
            val dir = File(context.getExternalFilesDir(null), "logs")
            if (!dir.exists()) dir.mkdirs()
            val file = File(dir, filename)
            file.writeText(content, Charsets.UTF_8)
            UiLog.log("writeAppExternal OK: $filename len=${content.length}")
            FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
        } catch (e: Exception) {
            UiLog.log("writeAppExternal fail: ${e.javaClass.simpleName}: ${e.message}")
            null
        }
    }

    /**
     * 分享 txt 文件（EXTRA_STREAM 文件流，非纯文本）。
     * @return null=成功；非 null=失败原因（供 UI Toast 显示）
     */
    fun shareTxtFile(context: Context, title: String, prefix: String, content: String): String? {
        val uri = writeLogTxt(context, prefix, content)
        if (uri == null) return "无法写入 txt 文件（详见 UiLog）"
        return try {
            val send = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_SUBJECT, title)
                putExtra(Intent.EXTRA_STREAM, uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            context.startActivity(Intent.createChooser(send, title).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            UiLog.log("shareTxtFile OK: $prefix uri=$uri")
            null
        } catch (e: Exception) {
            UiLog.log("shareTxtFile startActivity fail: ${e.javaClass.simpleName}: ${e.message}")
            "系统分享拉起失败：${e.javaClass.simpleName}"
        }
    }
}
