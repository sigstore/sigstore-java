dependencyResolutionManagement {
    repositories {
        gradlePluginPortal()
    }
}

rootProject.name = "build-logic"

includeBuild("../build-logic-commons")
include("build-parameters")
include("basics")
include("jvm")
include("publishing")
include("root-build")
