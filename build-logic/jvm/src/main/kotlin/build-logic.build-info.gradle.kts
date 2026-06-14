import buildlogic.BuildInfoTask

plugins {
    java
}

val generateBuildInfo = tasks.register("generateBuildInfo", BuildInfoTask::class) {
    version.set(project.version.toString())
    genDir.set(project.layout.buildDirectory.dir("generated/buildinfo"))
}

sourceSets.main {
    java.srcDir(generateBuildInfo)
}
