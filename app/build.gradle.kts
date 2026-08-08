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
        versionCode = 17
        versionName = "1.16"

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
