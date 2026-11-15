package org.onekash.kashpass.vault.fuzz

import com.code_intelligence.jazzer.junit.FuzzTest

/**
 * The Jazzer harnesses ([FuzzTargets]). With -Pkashpass.fuzz each runs in fuzzing mode under a
 * 256 MiB heap; one hour per target, run by hand, is the gate before a container change ships.
 * Without it each runs on an empty input and on any inputs a fuzzing run saved next to the tests
 * (gitignored), and [FuzzReplayTest] replays the corpus.
 */
class DecoderFuzzTest {

    @FuzzTest(maxDuration = "1h")
    fun decode(data: ByteArray) = FuzzTargets.decode(data)

    @FuzzTest(maxDuration = "1h")
    fun body(data: ByteArray) = FuzzTargets.body(data)

    @FuzzTest(maxDuration = "1h")
    fun innerHeader(data: ByteArray) = FuzzTargets.innerHeader(data)

    @FuzzTest(maxDuration = "1h")
    fun dictionary(data: ByteArray) = FuzzTargets.dictionary(data)

    @FuzzTest(maxDuration = "1h")
    fun xml(data: ByteArray) = FuzzTargets.xml(data)

    @FuzzTest(maxDuration = "1h")
    fun roundTrip(data: ByteArray) = FuzzTargets.roundTrip(data)

    @FuzzTest(maxDuration = "1h")
    fun crossEncode(data: ByteArray) = FuzzTargets.crossEncode(data)
}
