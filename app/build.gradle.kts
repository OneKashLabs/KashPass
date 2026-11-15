import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.compose.compiler)
}

val versionProps = Properties().apply {
    rootProject.file("version.properties").inputStream().use { load(it) }
}

android {
    namespace = "org.onekash.kashpass"
    compileSdk = 37

    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }

    defaultConfig {
        applicationId = "org.onekash.kashpass"
        minSdk = 31
        targetSdk = 37
        versionCode = versionProps.getProperty("VERSION_CODE").toInt()
        versionName = versionProps.getProperty("VERSION_NAME")
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            // No signing config: the release APK is built unsigned and signed afterwards with
            // apksigner. A signing config changes R8's output, so a build with one would not
            // match the unsigned build a reproducible-build check makes from the same commit.
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    kotlin {
        compilerOptions {
            jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21
        }
    }

    buildFeatures {
        compose = true
    }

    // English only: library strings in other languages would mix with KashPass's English text.
    androidResources {
        localeFilters += "en"
    }

    packaging {
        // Compressed dex and native libraries halve the APK people download; Android extracts
        // them at install.
        dex {
            useLegacyPackaging = true
        }
        jniLibs {
            useLegacyPackaging = true
        }
        // Library version and licence files and Kotlin's reflection metadata, which nothing in
        // the app reads. NOTICE lists the licences. META-INF/services stays: coroutines loads its
        // main dispatcher through it.
        resources {
            excludes += listOf("META-INF/*.version", "META-INF/androidx/**", "kotlin/**")
        }
    }

    lint {
        error += "ContentDescription"
        error += "ClickableViewAccessibility"
    }

    testOptions {
        unitTests {
            isIncludeAndroidResources = true
            all {
                it.maxParallelForks = (Runtime.getRuntime().availableProcessors() / 2).coerceIn(1, 8)
                // Robolectric on SDK 37 sets raw FileDescriptor fields for
                // ApplicationSharedMemory through jdk.internal.access, which
                // JDK 21 does not export. Test JVM only.
                it.jvmArgs("--add-exports=java.base/jdk.internal.access=ALL-UNNAMED")
                // -Proborazzi.test.record=true makes a Roborazzi capture write its image; without
                // it a capture does nothing. A daemon-side -D does not reach the test JVM.
                for (name in listOf("roborazzi.test.record", "roborazzi.test.verify", "roborazzi.test.compare")) {
                    providers.gradleProperty(name).orNull?.let { value -> it.systemProperty(name, value) }
                }
                // -Pkashpass.propertySeed=<seed>|random and -Pkashpass.propertyIterations=<n>
                // change the property tests' seed and iterations, as in vault-core (PropertyRuns).
                for (name in listOf("kashpass.propertySeed", "kashpass.propertyIterations")) {
                    providers.gradleProperty(name).orNull?.takeIf { p -> p.isNotEmpty() }?.let { value ->
                        it.systemProperty(name, value)
                        it.outputs.upToDateWhen { false }
                    }
                }
            }
        }
    }
}

tasks.matching { it.name == "testReleaseUnitTest" }.configureEach {
    enabled = false
}

dependencies {
    implementation(project(":vault-core"))

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.activity.compose)

    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.material3)

    implementation(libs.kotlinx.coroutines.android)

    testImplementation(libs.junit)
    testImplementation(libs.robolectric)
    testImplementation(libs.androidx.test.core)
    testImplementation(testFixtures(project(":vault-core")))
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(platform(libs.androidx.compose.bom))
    testImplementation(libs.androidx.ui.test.junit4)
    testImplementation(libs.androidx.test.espresso.core)
    // Roborazzi captures Compose screens under Robolectric's native graphics, with no device.
    // Libraries only, no Gradle plugin, so the build doesn't depend on the plugin's AGP support.
    testImplementation(libs.roborazzi)
    testImplementation(libs.roborazzi.compose)
    debugImplementation(libs.androidx.ui.test.manifest)
}

