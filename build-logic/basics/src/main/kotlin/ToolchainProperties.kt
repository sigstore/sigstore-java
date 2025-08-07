import buildparameters.BuildParametersExtension
import org.gradle.api.JavaVersion

class ToolchainProperties(
    val version: Int,
    val vendor: String?,
    val implementation: String?,
)

// TODO: update when ossfuzz bumps Java to 21, see https://github.com/google/oss-fuzz/issues/14266
val BuildParametersExtension.buildJdk: ToolchainProperties?
    get() = (17.takeIf { System.getenv("CIFUZZ").equals("true", ignoreCase = true) }
        ?: jdkBuildVersion.takeIf { it != 0 })
        ?.let { ToolchainProperties(it, jdkBuildVendor.orNull, jdkBuildImplementation.orNull) }

val BuildParametersExtension.buildJdkVersion: Int
    get() = buildJdk?.version ?: JavaVersion.current().majorVersion.toInt()

val BuildParametersExtension.testJdk: ToolchainProperties?
    get() = jdkTestVersion.orNull?.takeIf { it != 0 }
        ?.let { ToolchainProperties(it, jdkTestVendor.orNull, jdkTestImplementation.orNull) }
        ?: buildJdk

val BuildParametersExtension.testJdkVersion: Int
    get() = jdkTestVersion.orNull ?: buildJdkVersion
