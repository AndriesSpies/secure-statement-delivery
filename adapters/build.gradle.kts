plugins {
    alias(libs.plugins.springBoot)
    alias(libs.plugins.springDependencyManagement)
}

dependencies {
    implementation(project(":application"))
    implementation(project(":domain"))

    implementation(libs.spring.boot.starter.web)
    implementation(libs.spring.boot.starter.security)
    implementation(libs.spring.boot.starter.oauth2.resource.server)
    implementation(libs.spring.boot.starter.data.jpa)
    implementation(libs.spring.boot.starter.data.redis)
    implementation(libs.spring.boot.starter.actuator)
    implementation(libs.spring.boot.starter.validation)

    implementation(libs.flyway.core)
    implementation(libs.flyway.postgres)
    runtimeOnly(libs.postgres)

    implementation(libs.aws.s3)
    implementation(libs.bucket4j.redis)
    implementation(libs.pdfbox)
    implementation(libs.nimbus.jose.jwt)

    implementation(libs.micrometer.registry.prometheus)
    implementation(libs.micrometer.tracing.bridge.otel)
    implementation(libs.otel.exporter.otlp)
    implementation(libs.logstash.encoder)
    implementation(libs.springdoc.openapi)

    testImplementation(libs.spring.boot.starter.test)
    testImplementation(libs.spring.security.test)
    testImplementation(libs.testcontainers.junit)
    testImplementation(libs.testcontainers.postgres)
    testImplementation(libs.testcontainers.minio)
    testImplementation(libs.testcontainers.redis)
}

tasks.named<org.springframework.boot.gradle.tasks.bundling.BootJar>("bootJar") {
    archiveFileName.set("app.jar")
    layered { enabled.set(true) }
}