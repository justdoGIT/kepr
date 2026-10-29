// kepr for JetBrains IDEs. Build: gradle buildPlugin (needs network for the IntelliJ Platform).
// The IDE-independent part (src/main/java/io/kepr/CliView.java) is tested without Gradle: ./test.sh
plugins {
    id("java")
    id("org.jetbrains.intellij.platform") version "2.1.0"
}

group = "io.kepr"
version = "0.1.0"

repositories {
    mavenCentral()
    intellijPlatform { defaultRepositories() }
}

dependencies {
    intellijPlatform { intellijIdeaCommunity("2024.1") }
}

java { toolchain { languageVersion = JavaLanguageVersion.of(17) } }

sourceSets {
    main {
        java {
            // CliView parses with the Java SDK's JSON reader.
            srcDir("src/main/java")
            srcDir("../../sdk/java/src/main/java")
        }
    }
}
