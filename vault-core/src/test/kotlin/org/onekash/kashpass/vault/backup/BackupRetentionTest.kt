package org.onekash.kashpass.vault.backup

import java.time.Duration
import java.time.Instant
import kotlin.test.assertEquals
import org.junit.jupiter.api.Test

class BackupRetentionTest {

    private val now = Instant.parse("2026-10-20T12:00:00Z")

    // Five copies a day apart, newest first: b0 is the newest.
    private val five = (0 until 5).map { i -> BackupInfo("b$i", now.minus(Duration.ofDays(i.toLong())), 1, BackupKind.OPENED, "") }

    @Test
    fun `the newest keep copies stay, by count only`() {
        assertEquals(listOf("b3", "b4"), BackupRetention.toDelete(five, 3).map { it.id })
        assertEquals(listOf("b1", "b2", "b3", "b4"), BackupRetention.toDelete(five, 1).map { it.id })
    }

    @Test
    fun `old copies inside the count stay, whatever their age`() {
        val old = five.map { it.copy(createdAt = it.createdAt.minus(Duration.ofDays(400))) }
        assertEquals(emptyList(), BackupRetention.toDelete(old, 5))
    }

    @Test
    fun `a count outside 1 to 30 is limited, so the newest always stays`() {
        assertEquals(4, BackupRetention.toDelete(five, 0).size)
        assertEquals(emptyList(), BackupRetention.toDelete(five, 99))
    }

    @Test
    fun `a saved count out of range or unset reads as the default 3`() {
        assertEquals(3, BackupRetention.keepOf(null))
        assertEquals(3, BackupRetention.keepOf(0))
        assertEquals(3, BackupRetention.keepOf(31))
        assertEquals(1, BackupRetention.keepOf(1))
        assertEquals(30, BackupRetention.keepOf(30))
    }

    @Test
    fun `equal times break by id, newest name first`() {
        val tied = listOf("a", "c", "b").map { BackupInfo(it, now, 1, BackupKind.SAVED, "") }
        assertEquals(listOf("a"), BackupRetention.toDelete(tied, 2).map { it.id })
    }

    @Test
    fun `a location hash is the SHA-256 of its text`() {
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", Sha256.ofLocation(""))
    }

    @Test
    fun `the copy added last counts as the newest whatever its time`() {
        val future = BackupInfo("future", now.plus(Duration.ofDays(400)), 1, BackupKind.OPENED, "")
        val added = BackupInfo("added", now, 1, BackupKind.SAVED, "")
        assertEquals(listOf("future"), BackupRetention.toDelete(listOf(future, added), 1, justAdded = "added").map { it.id })
    }
}
