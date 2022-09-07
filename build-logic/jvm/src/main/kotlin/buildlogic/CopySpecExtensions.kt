package buildlogic

import org.apache.tools.ant.filters.FixCrLfFilter
import org.gradle.api.file.CopySpec
import org.gradle.kotlin.dsl.filter

/**
 * Converts end-of-line markers in the current [CopySpec] to the given value.
 * See [org.apache.tools.ant.filters.FixCrLfFilter.CrLf] for the possible values of `eol`.
 * See https://github.com/gradle/gradle/issues/8688.
 */
fun CopySpec.filterEolSimple(eol: String) {
    filteringCharset = "UTF-8"
    filter(
        FixCrLfFilter::class, mapOf(
            "eol" to FixCrLfFilter.CrLf.newInstance(eol),
            "fixlast" to true,
            "ctrlz" to FixCrLfFilter.AddAsisRemove.newInstance("asis")
        )
    )
}
