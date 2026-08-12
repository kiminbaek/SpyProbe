package com.dustinky.spyprobe

/*
 * v1.37 P0-4: 内置更新系统（借鉴 Guise AppUpdater 工程思想，自研实现）
 *
 * 【痛点】SpyProbe 几乎每个版本都要"待真机验证"，用户每次手动下载 APK 再装。
 *   内置更新后：打开 App 检测新版本 → 一键下载 → 校验 → root 静默安装（或系统安装器）。
 *
 * 【流程】
 *   1. checkUpdate(): GET GitHub API latest release（多镜像回退）→ tag_name + apk asset URL + body 里 SHA256
 *   2. download(url, dest, progress): HttpURLConnection 流式下载（支持重定向/镜像回退）
 *   3. verify(file): PackageManager.getPackageArchiveInfo 验 packageName==com.dustinky.spyprobe
 *      + versionCode > 当前 + SHA256 比对（release body 解析，防下载损坏/装错版）
 *   4. install: root 静默（cat apk | pm install -S <size> -r 流式喂 pm，绕过 SELinux 禁 /data/local/tmp）
 *      → 失败回退 ACTION_VIEW 系统安装器（FileProvider）
 *
 * 【镜像回退】GitHub 直连慢/被墙时走加速镜像（ghproxy 等），逐个试，什么快用什么。
 *   API 也用镜像（api.github.com 直连不稳）。
 */

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import androidx.core.content.FileProvider
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

object Updater {

    private const val REPO = "kiminbaek/SpyProbe"
    private const val PKG = "com.dustinky.spyprobe"

    /** 版本信息结果 */
    data class UpdateInfo(
        val latestVersion: String,      // 如 "1.37.0"
        val downloadUrl: String,        // 首个可用 apk asset URL
        val sha256: String,             // 可能为空（release body 未附）
        val body: String                // release notes
    )

    /** 检查结果 */
    sealed class CheckResult {
        data class Update(val info: UpdateInfo) : CheckResult()
        object Latest : CheckResult()
        data class Fail(val reason: String) : CheckResult()
    }

    // ===== 1. 检查更新 =====

    /** 检查 GitHub release；currentVersion 用于比对（如 "1.36.0"）。
     *  includePrerelease=true 时拉 /releases 列表取最新（含 pre-release 测试版）；false 只查 /releases/latest 正式版 */
    fun checkUpdate(includePrerelease: Boolean = false): CheckResult {
        try {
            val releaseJson = fetchLatestRelease(includePrerelease) ?: return CheckResult.Fail("无法访问 GitHub API（镜像均失败）")
            val tag = releaseJson.optString("tag_name", "").trim() // 如 "v1.37.0"
            if (tag.isEmpty()) return CheckResult.Fail("release 无 tag_name")
            val latestVersion = tag.removePrefix("v")
            // 比对版本（简单数字分段比较）
            if (compareVersion(latestVersion, BuildConfig.VERSION_NAME) <= 0) {
                return CheckResult.Latest
            }
            // 找 apk asset
            var apkUrl = ""
            val assets = releaseJson.optJSONArray("assets")
            if (assets != null) {
                for (i in 0 until assets.length()) {
                    val a = assets.getJSONObject(i)
                    val name = a.optString("name", "")
                    if (name.endsWith(".apk")) {
                        apkUrl = a.optString("browser_download_url", "")
                        break
                    }
                }
            }
            // 无 assets 时用约定 URL（Release 规范：SpyProbe-vX.Y.Z.apk）
            if (apkUrl.isEmpty()) {
                apkUrl = "https://github.com/$REPO/releases/download/$tag/SpyProbe-$latestVersion.apk"
            }
            // body 里解析 SHA256（发布规范：正文含 "SHA256: <hex>"）
            val body = releaseJson.optString("body", "")
            val sha256 = parseSha256(body)
            return CheckResult.Update(
                UpdateInfo(latestVersion, apkUrl, sha256, body)
            )
        } catch (t: Throwable) {
            return CheckResult.Fail("检查失败: $t")
        }
    }

    /** 多镜像回退拉取 release JSON；逐个试。
     *  includePrerelease=true → /releases?per_page=30 列表，从最新开始找第一个非 draft（含 pre-release 测试版）；
     *  false → /releases/latest（GitHub 语义：仅正式版） */
    private fun fetchLatestRelease(includePrerelease: Boolean): JSONObject? {
        val apiPath = if (includePrerelease) "releases?per_page=30" else "releases/latest"
        val candidates = listOf(
            "https://api.github.com/repos/$REPO/$apiPath",
            "https://ghproxy.com/https://api.github.com/repos/$REPO/$apiPath",
            "https://mirror.ghproxy.com/https://api.github.com/repos/$REPO/$apiPath",
            "https://gh-proxy.com/https://api.github.com/repos/$REPO/$apiPath"
        )
        for (url in candidates) {
            var conn: HttpURLConnection? = null
            try {
                conn = (URL(url).openConnection() as HttpURLConnection).apply {
                    connectTimeout = 8000
                    readTimeout = 8000
                    setRequestProperty("User-Agent", "SpyProbe/${BuildConfig.VERSION_NAME}")
                    setRequestProperty("Accept", "application/vnd.github+json")
                }
                val code = conn.responseCode
                if (code == 200) {
                    val body = conn.inputStream.bufferedReader().use { it.readText() }
                    if (includePrerelease) {
                        // /releases 返回 JSONArray（按发布时间倒序）；跳过 draft，取第一个可用（含 pre-release）
                        val arr = JSONArray(body)
                        for (i in 0 until arr.length()) {
                            val rel = arr.getJSONObject(i)
                            if (rel.optBoolean("draft", false)) continue
                            return rel
                        }
                        return null
                    }
                    return JSONObject(body)
                }
            } catch (t: Throwable) {
                // 试下一个镜像
            } finally {
                // v1.42 P2-15: 异常路径也释放连接（旧实现 200 后正常 disconnect，
                //   inputStream 读取抛异常 / 非 200 时 conn 泄漏，最多 4 连接/检查）
                try { conn?.disconnect() } catch (t2: Throwable) { }
            }
        }
        return null
    }

    /** 从 release body 解析 "SHA256: xxx" / "sha256=xxx" */
    private fun parseSha256(body: String): String {
        val r = Regex("(?i)(sha256\\s*[:=]\\s*)([0-9a-f]{64})").find(body)
        return r?.groupValues?.get(2) ?: ""
    }

    /** 版本比较：a>b 返回 >0；支持 "1.37.0" 与 "1.36" 混合 */
    fun compareVersion(a: String, b: String): Int {
        val pa = a.split('.').mapNotNull { it.toIntOrNull() }
        val pb = b.split('.').mapNotNull { it.toIntOrNull() }
        for (i in 0 until maxOf(pa.size, pb.size)) {
            val x = pa.getOrElse(i) { 0 }
            val y = pb.getOrElse(i) { 0 }
            if (x != y) return x - y
        }
        return 0
    }

    // ===== 2. 下载 =====

    /** 流式下载到 dest，progress 回调 0-100（-1 表示不确定）；返回 true=成功 */
    fun download(url: String, dest: File, progress: (Int) -> Unit): Boolean {
        var current = url
        repeat(4) { attempt -> // 最多试 4 个 URL（原 + 3 镜像）
            var conn: HttpURLConnection? = null
            try {
                conn = (URL(current).openConnection() as HttpURLConnection).apply {
                    connectTimeout = 15000
                    readTimeout = 30000
                    setRequestProperty("User-Agent", "SpyProbe/${BuildConfig.VERSION_NAME}")
                    // 重定向跟随
                    instanceFollowRedirects = true
                }
                val code = conn.responseCode
                if (code != 200) {
                    // 尝试镜像（v1.47 P2-13: 传 attempt 不再 +1——旧实现 attempt=0 失败后
                    //   mirrorOf(url,1) 返回原 URL，导致原 URL 重复试 2 次、最后一个镜像永远试不到）
                    current = mirrorOf(url, attempt) ?: return false
                    return@repeat
                }
                val total = conn.contentLengthLong
                val input = conn.inputStream
                val out = FileOutputStream(dest)
                val buf = ByteArray(64 * 1024)
                var read = 0L
                var lastPct = -1
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    out.write(buf, 0, n)
                    read += n
                    if (total > 0) {
                        val pct = ((read * 100) / total).toInt()
                        if (pct != lastPct) {
                            lastPct = pct
                            progress(pct)
                        }
                    }
                }
                out.flush()
                out.close()
                input.close()
                if (total > 0 && read < total) {
                    dest.delete()
                    return false
                }
                progress(100)
                return true
            } catch (t: Throwable) {
                dest.delete()
                // 网络异常试镜像（v1.47 P2-13: 同上，不再 +1）
                current = mirrorOf(url, attempt) ?: return false
            } finally {
                // v1.42 P2-15: 异常路径也释放连接（下载中断/校验失败时 conn 泄漏）
                try { conn?.disconnect() } catch (t2: Throwable) { }
            }
        }
        return false
    }

    /** 生成镜像 URL：attempt=0 原 URL，1/2/3 各镜像（v1.47 P2-13: 下标修正——旧实现 attempt<=1 返回 original 造成原 URL 试 2 次） */
    private fun mirrorOf(original: String, attempt: Int): String? {
        if (attempt <= 0) return original
        val prefixes = listOf(
            "https://ghproxy.com/",
            "https://mirror.ghproxy.com/",
            "https://gh-proxy.com/"
        )
        val idx = attempt - 1
        if (idx >= prefixes.size) return null
        return prefixes[idx] + original
    }

    // ===== 3. 校验 =====

    /** 校验下载的 APK：packageName + versionCode > 当前 + SHA256（可选） */
    fun verify(context: Context, file: File, expectedSha256: String): String? {
        // null=通过；否则返回错误原因
        try {
            val pm = context.packageManager
            val ai = pm.getPackageArchiveInfo(file.absolutePath, PackageManager.GET_ACTIVITIES)
                ?: return "APK 解析失败（损坏？）"
            if (ai.packageName != PKG) return "包名不符: ${ai.packageName}（不是 SpyProbe）"
            if (ai.versionCode <= BuildConfig.VERSION_CODE) {
                return "版本不高于当前（${BuildConfig.VERSION_NAME}）"
            }
            if (expectedSha256.isNotEmpty()) {
                val actual = sha256(file)
                if (!actual.equals(expectedSha256, ignoreCase = true)) {
                    return "SHA256 校验失败\n期望: $expectedSha256\n实际: $actual"
                }
            }
            return null
        } catch (t: Throwable) {
            return "校验异常: $t"
        }
    }

    fun sha256(file: File): String {
        val md = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buf = ByteArray(64 * 1024)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                md.update(buf, 0, n)
            }
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }

    // ===== 4. 安装 =====

    /**
     * root 静默安装：cat apk | pm install -S <size> -r（流式喂 pm，绕过 OEM SELinux 禁 /data/local/tmp）
     * 180s 超时；返回 true=成功
     */
    fun installRoot(apk: File): Boolean {
        try {
            val size = apk.length()
            // su -c 执行 pm install，apk 内容从 stdin 喂入
            val cmd = "cat ${shellQuote(apk.absolutePath)} | pm install -S $size -r"
            val process = Runtime.getRuntime().exec(arrayOf("su", "-c", cmd))
            // 读输出（防 pipe 阻塞）
            val errOut = StringBuilder()
            Thread {
                process.errorStream.bufferedReader().use { it.readLines().forEach { l -> errOut.append(l).append('\n') } }
            }.start()
            val ok = process.waitFor(180, java.util.concurrent.TimeUnit.SECONDS)
            if (!ok) {
                process.destroy()
                return false
            }
            val code = process.exitValue()
            return code == 0 && !errOut.toString().contains("Failure")
        } catch (t: Throwable) {
            return false
        }
    }

    /** 系统安装器回退（ACTION_VIEW + FileProvider） */
    fun installSystem(context: Context, apk: File): Boolean {
        return try {
            val uri: Uri = FileProvider.getUriForFile(
                context,
                "${context.packageName}.fileprovider",
                apk
            )
            val intent = Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(uri, "application/vnd.android.package-archive")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                if (Build.VERSION.SDK_INT >= 24) addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(intent)
            true
        } catch (t: Throwable) {
            false
        }
    }

    /** shell 参数转义（纯内部路径用，防注入） */
    private fun shellQuote(s: String): String {
        return "'" + s.replace("'", "'\\''") + "'"
    }
}
