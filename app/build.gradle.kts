plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.dustinky.spyprobe"
    compileSdk = 36
    buildToolsVersion = "36.0.0"
    ndkVersion = "27.1.12297006"

    defaultConfig {
        minSdk = 26
        targetSdk = 35
        versionCode = 52
        versionName = "1.37.0"

        // v1.10: native 抓包（shadowhook inline hook）——只编真机常用 ABI，控制体积
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a")
        }
        externalNativeBuild {
            cmake {
                cppFlags += "-std=c++17"
            }
        }
    }

    // v1.10: CMake 构建 native_hook（shadowhook + nghttp2）
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            // v1.11: release 也用 debug keystore 签名（与历史版本同证书，用户可无缝覆盖安装）
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    // v1.8: 启用 BuildConfig（标题动态取 VERSION_NAME，杜绝硬编码不同步）
    // v1.11: Compose UI 重构
    buildFeatures {
        buildConfig = true
        compose = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    packaging {
        resources {
            merges += "META-INF/xposed/*"
            excludes += "**"
        }
    }
}

dependencies {
    compileOnly("io.github.libxposed:api:101.0.0")
    implementation("io.github.libxposed:service:101.0.0")
    // v1.9: DexKit（导出 dex / 字符串反查）—— native 库会让 APK 变大
    implementation("org.luckypray:dexkit:2.0.7")

    // v1.11: Compose UI
    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    // v1.31.1 P3-12: 去掉 material-icons-extended（APK -5MB）——历史复制图标改为自定义 CopyIcon（LogsScreen.kt）
    implementation("androidx.compose.material:material-icons-core")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    debugImplementation("androidx.compose.ui:ui-tooling")
}

// patch: debug 签名
android {
    signingConfigs {
        getByName("debug") {
            storeFile = file("../debug.keystore")
            storePassword = "android"
            keyAlias = "androiddebugkey"
            keyPassword = "android"
        }
    }
}

// 禁用 release lint（离线环境无 lint-gradle 依赖）
android {
    lint {
        checkReleaseBuilds = false
        abortOnError = false
    }
}

// ===== v1.37 P0-3: Xposed 入口完整性校验任务 =====
// 借鉴 Guise verifyReleaseXposedEntries 工程思想（GPL-3.0 不抄代码，自研实现）：
// 发布前校验 Xposed 入口声明（java_init.list）与源码/Manifest 一致——
// 防"入口类改名/移动但 list 没同步 → LSPosed 里模块静默不加载"的隐性翻车。
// 未来开启 R8 混淆后，此任务会自动扩展校验 mapping.txt（入口类不被改名）。
tasks.register("verifyReleaseXposedEntries") {
    group = "verification"
    description = "校验 Xposed 入口声明（java_init.list）与源码一致，防模块静默失效"
    doLast {
        val root = project.projectDir
        val listFile = root.resolve("src/main/resources/META-INF/xposed/java_init.list")
        if (!listFile.exists()) {
            throw GradleException("缺少 Xposed 入口声明: $listFile")
        }
        val entry = listFile.readText().trim()
        val expectedEntry = "com.dustinky.spyprobe.ModuleMain"
        if (entry != expectedEntry) {
            throw GradleException("java_init.list 入口异常: '$entry'，期望 '$expectedEntry'")
        }
        val entryClass = root.resolve("src/main/java/com/dustinky/spyprobe/ModuleMain.java")
        if (!entryClass.exists()) {
            throw GradleException("入口类源码缺失: $entryClass（java_init.list 指向它但文件不存在）")
        }
        val manifest = root.resolve("src/main/AndroidManifest.xml")
        if (!manifest.exists()) {
            throw GradleException("AndroidManifest.xml 缺失")
        }
        val manifestText = manifest.readText()
        if (!manifestText.contains(".MainActivity")) {
            throw GradleException("Manifest 缺少 MainActivity（launcher 入口丢失）")
        }
        // R8 mapping 校验（当前 release 未开混淆 isMinifyEnabled=false，此段为未来开启时自动生效）
        val mapping = root.resolve("build/outputs/mapping/release/mapping.txt")
        if (mapping.exists()) {
            val mappingText = mapping.readText()
            if (!mappingText.contains(expectedEntry)) {
                throw GradleException("R8 混淆后入口类被改名/删除: $expectedEntry 不在 mapping.txt")
            }
        }
        println("✅ Xposed 入口校验通过: $expectedEntry")
    }
}

// 发布前自动执行入口校验
afterEvaluate {
    tasks.named("preReleaseBuild").configure {
        dependsOn("verifyReleaseXposedEntries")
    }
}
