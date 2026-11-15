package org.onekash.kashpass.session

/** Why the lock screen says the last change is not in the file. */
enum class LostChange {
    /** The save failed, was refused, or its choices were unanswered when the vault locked. */
    NOT_SAVED,

    /** The save ran past the lock's 30 s limit; its provider write can finish after the lock. */
    MAYBE_NOT_SAVED,
}
