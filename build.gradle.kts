import com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar

plugins {
    kotlin("jvm") version "1.8.22"
    id("com.gradleup.shadow") version "8.3.0"
}

group = "com.rafaelb13"
version = "1.0.1-kc16"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.keycloak:keycloak-services:16.1.1")
    implementation("org.keycloak:keycloak-server-spi:16.1.1")
    implementation("org.keycloak:keycloak-server-spi-private:16.1.1")
    implementation("javax.ws.rs:javax.ws.rs-api:2.1.1")
    implementation("org.jetbrains.kotlin:kotlin-stdlib:1.8.22")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.14.2")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.14.2")
    implementation("com.google.zxing:core:3.5.1")
    implementation("com.google.zxing:javase:3.5.1")
    testImplementation(platform("org.junit:junit-bom:5.9.1"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.jetbrains.kotlin:kotlin-test")
}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(11)
}

tasks {
    val shadowJar by existing(ShadowJar::class) {
        dependencies {
            include(dependency("org.jetbrains.kotlin:kotlin-stdlib:1.8.22"))
            include(dependency("com.google.zxing:core:3.5.1"))
            include(dependency("com.google.zxing:javase:3.5.1"))
        }
        dependsOn(build)
        archiveFileName.set("keycloak-totp-spi.jar")
    }
}