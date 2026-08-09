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
 * v1.39: 新增 pcap 二进制导出（writePcapFile），同样走公共 Download + FileProvider 兜底。
 */
object ShareLogUtil {

    /** 生成唯一文件名时间戳 */
    fun timestamp(): String =
        SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())

    /**
     * v1.35 P2-1: 统一日志行格式化（导出 txt 用）。
     * 旧格式 "HH:mm:ss.SSS [tag] msg" 各导出点重复拼、tag 长短不一 → 右对齐到固定宽度，
     * 输出 "HH:mm:ss.SSS [      tag] msg"，一眼对齐 tag 列，msg 单行（已在 LogStore 折叠）。
     */
    private const val TAG_WIDTH = 20

    fun formatLine(time: String, tag: String, msg: String): String {
        val t = if (time.isEmpty()) "" else time
        val g = if (tag.isEmpty()) "-" else tag
        val pad = if (g.length >= TAG_WIDTH) g else g.padStart(TAG_WIDTH)
        return "$t [$pad] $msg"
    }

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
     * v1.39 P0: pcap 文件写公共 Download/SpyProbe/（Android 10+ MediaStore 免权限；老系统 FileProvider 兜底）。
     * @return 可分享 Uri；null=失败（UiLog 有原因）
     */
    fun writePcapFile(context: Context, bytes: ByteArray): Uri? {
        val filename = "spyprobe_pcap_${timestamp()}.pcap"
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                writePublicDownloadBytes(context, filename, bytes) ?: writeAppExternalBytes(context, filename, bytes)
            } else {
                writeAppExternalBytes(context, filename, bytes)
            }
        } catch (e: Exception) {
            UiLog.log("writePcapFile failed: ${e.javaClass.simpleName}: ${e.message}")
            null
        }
    }

    /** 公共 Download/SpyProbe/ 写二进制（Android 10+ MediaStore，免权限） */
    private fun writePublicDownloadBytes(context: Context, filename: String, bytes: ByteArray): Uri? {
        return try {
            val values = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, filename)
                put(MediaStore.Downloads.MIME_TYPE, "application/vnd.tcpdump.pcap")
                put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/SpyProbe")
            }
            val uri = context.contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
            if (uri == null) {
                UiLog.log("writePublicDownloadBytes: MediaStore insert null")
                return null
            }
            context.contentResolver.openOutputStream(uri)?.use { out ->
                out.write(bytes)
            } ?: run {
                UiLog.log("writePublicDownloadBytes: openOutputStream null")
                return null
            }
            UiLog.log("writePublicDownloadBytes OK: $filename len=${bytes.size}")
            uri
        } catch (e: Exception) {
            UiLog.log("writePublicDownloadBytes fail: ${e.javaClass.simpleName}: ${e.message}")
            null
        }
    }

    /** app 专属外部目录写二进制（老系统 / 公共目录失败兜底，经 FileProvider 分享） */
    private fun writeAppExternalBytes(context: Context, filename: String, bytes: ByteArray): Uri? {
        return try {
            val dir = File(context.getExternalFilesDir(null), "logs")
            if (!dir.exists()) dir.mkdirs()
            val file = File(dir, filename)
            file.writeBytes(bytes)
            UiLog.log("writeAppExternalBytes OK: $filename len=${bytes.size}")
            FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
        } catch (e: Exception) {
            UiLog.log("writeAppExternalBytes fail: ${e.javaClass.simpleName}: ${e.message}")
            null
        }
    }

    /**
     * v1.30.3: 拆成两步 —— 写文件（IO 线程调用） + shareUri（主线程调用，startActivity 必须在主线程）。
     * 此前 shareTxtFile 一步完成：UI 协程里直接 httpGet（主线程网络 → NetworkOnMainThreadException 导出必失败）。
     *
     * 第一步：写日志 txt 文件（IO 线程调用，MediaStore/FileProvider 写盘）。
     * @return 文件 Uri；null=失败（详情见 UiLog）
     */
    fun writeLogTxtFile(context: Context, prefix: String, content: String): Uri? =
        writeLogTxt(context, prefix, content)

    /**
     * 第二步：拉起系统分享（主线程调用）。
     * @return null=成功；非 null=失败原因（供 UI Toast 显示）
     */
    fun shareUri(context: Context, title: String, uri: Uri): String? {
        return try {
            val send = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_SUBJECT, title)
                putExtra(Intent.EXTRA_STREAM, uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            context.startActivity(Intent.createChooser(send, title).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            UiLog.log("shareUri OK: $title uri=$uri")
            null
        } catch (e: Exception) {
            UiLog.log("shareUri startActivity fail: ${e.javaClass.simpleName}: ${e.message}")
            "系统分享拉起失败：${e.javaClass.simpleName}"
        }
    }
}
