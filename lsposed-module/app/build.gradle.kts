plugins {
    id("com.android.application")
}

android {
    namespace = "com.hu.sceneunlock"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.hu.sceneunlock"
        minSdk = 26
        targetSdk = 34
        versionCode = 103
        versionName = "1.4-alpha10"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    lint {
        checkReleaseBuilds = false
        abortOnError = false
    }
}

dependencies {
    // legacy Xposed API —— 仅编译期存根（运行时类由 LSPosed framework.dex 注入，不入包）
    compileOnly(files("stubs/xposed-stubs.jar"))
}
