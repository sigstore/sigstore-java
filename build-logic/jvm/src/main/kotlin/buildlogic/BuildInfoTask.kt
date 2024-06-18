package buildlogic

import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFile
import org.gradle.api.provider.Property
import org.gradle.api.provider.Provider
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.TaskAction

abstract class BuildInfoTask : DefaultTask() {
    @get:Input
    abstract val packageName: Property<String>

    @get:Input
    abstract val version: Property<String>

    @get:OutputDirectory
    abstract val genDir: DirectoryProperty

    @TaskAction
    fun run() {
        val output = """
            package ${packageName.get()};

            public class BuildInfo {
              public static final String VERSION = "${version.get()}";
            }
        """.trimIndent()
        val outputPath = genDir.file(packageName.get().replace(".", "/").plus("/BuildInfo.java")).get().asFile
        outputPath.parentFile.mkdirs()
        outputPath.writeText(output)
    }
}
