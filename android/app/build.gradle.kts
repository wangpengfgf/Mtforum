import java.util.Properties
import java.io.FileInputStream

plugins {
    id("com.android.application")
    id("kotlin-android")
    id("dev.flutter.flutter-gradle-plugin")
}

val keystoreProperties = Properties()
val keystoreFile = rootProject.file("../key.properties")
if (keystoreFile.exists()) {
    keystoreProperties.load(FileInputStream(keystoreFile))
}

// key.properties 里的 storeFile 指向开发者本机路径，CI 上并不存在。
// 只有本机同时存在 key.properties 和真实签名文件时才启用 release 签名，
// 否则回退到 debug 签名，保证自动打包流程不会因为签名缺失而中断。
val releaseStoreFile = (keystoreProperties["storeFile"] as String?)
    ?.takeIf { it.isNotBlank() }
    ?.let { file(it) }
val hasReleaseSigning = keystoreFile.exists() &&
    releaseStoreFile != null &&
    releaseStoreFile.exists()

android {
    namespace = "com.binmt.mtforum"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    kotlinOptions {
        jvmTarget = JavaVersion.VERSION_11.toString()
    }

    defaultConfig {
        applicationId = "com.binmt.mtforum"
        minSdk = flutter.minSdkVersion
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName
    }

    signingConfigs {
        if (hasReleaseSigning) {
            create("release") {
                storeFile = releaseStoreFile!!
                storePassword = keystoreProperties["storePassword"] as String
                keyAlias = keystoreProperties["keyAlias"] as String
                keyPassword = keystoreProperties["keyPassword"] as String
            }
        }
    }

    buildTypes {
        release {
            signingConfig = if (hasReleaseSigning) {
                signingConfigs.getByName("release")
            } else {
                signingConfigs.getByName("debug")
            }
        }
    }
}

flutter {
    source = "../.."
}
