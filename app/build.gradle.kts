plugins {
    id("com.android.application")
}

android {
    namespace = "com.dustinky.spyprobe"
    compileSdk = 36
    buildToolsVersion = "36.0.0"

    defaultConfig {
        minSdk = 26
        targetSdk = 35
        versionCode = 10
        versionName = "1.9"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    // v1.8: 启用 BuildConfig（MainActivity 标题动态取 VERSION_NAME，杜绝硬编码不同步）
    buildFeatures {
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
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
