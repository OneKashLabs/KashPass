package org.onekash.kashpass.vault.testing

import io.kotest.common.ExperimentalKotest
import io.kotest.property.PropTestConfig
import io.kotest.property.PropertyTesting

/**
 * Runs every property with one fixed seed by default, so a new failure cannot appear in an
 * unrelated commit. `-Pkashpass.propertySeed=<seed>` replays a seed a failure printed and
 * `-Pkashpass.propertySeed=random` draws a new one; `-Pkashpass.propertyIterations=<n>` multiplies
 * each property's iterations for a longer run. A failure prints its seed and its input, shrunk
 * where the input's generator shrinks (lists and numbers do, a generated vault does not); no failed
 * seed is written under the home folder.
 */
object PropertyRuns {

    /** System property set by `-Pkashpass.propertySeed`. */
    const val SEED_PROPERTY = "kashpass.propertySeed"

    /** System property set by `-Pkashpass.propertyIterations`. */
    const val ITERATIONS_PROPERTY = "kashpass.propertyIterations"

    /** The seed of the default suite. */
    const val DEFAULT_SEED = 20_261_101L

    init {
        PropertyTesting.writeFailedSeed = false
    }

    /** Returns the run's seed: [DEFAULT_SEED], the one requested, or a new random one. */
    fun seed(): Long = when (val asked = System.getProperty(SEED_PROPERTY)?.takeIf { it.isNotBlank() }) {
        null -> DEFAULT_SEED
        "random" -> kotlin.random.Random.nextLong()
        else -> asked.toLong()
    }

    /** Returns the run settings: [seed], and [iterations] times the requested multiplier. */
    @OptIn(ExperimentalKotest::class) // PropTestConfig's constructor is experimental in Kotest 6.
    fun config(iterations: Int): PropTestConfig {
        val times = System.getProperty(ITERATIONS_PROPERTY)?.takeIf { it.isNotBlank() }?.toInt() ?: 1
        return PropTestConfig(seed = seed(), iterations = iterations * times)
    }
}
