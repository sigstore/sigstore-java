package buildlogic

import org.gradle.kotlin.dsl.DependencyHandlerScope
import org.gradle.kotlin.dsl.`kotlin-dsl`
import org.gradle.plugin.use.PluginDependenciesSpec
import org.gradle.plugin.use.PluginDependencySpec

val DependencyHandlerScope.kotlinDslVersion: String
    get() = PluginDependenciesSpec {
        object : PluginDependencySpec {
            var version: String? = null
            override fun version(version: String?) = apply { this.version = version }
            override fun apply(apply: Boolean) = this
            override fun toString() = version ?: ""
        }
    }.`kotlin-dsl`.toString()

fun DependencyHandlerScope.embeddedKotlinDsl() =
    "org.gradle.kotlin.kotlin-dsl:org.gradle.kotlin.kotlin-dsl.gradle.plugin:$kotlinDslVersion" 
