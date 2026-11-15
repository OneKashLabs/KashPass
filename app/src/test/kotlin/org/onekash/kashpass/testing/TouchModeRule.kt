package org.onekash.kashpass.testing

import androidx.test.platform.app.InstrumentationRegistry
import org.junit.rules.ExternalResource

/**
 * Puts windows in touch mode, as a phone in use is. Outside touch mode Compose gives focus to
 * the first focusable element whenever nothing has it, so clearing focus would not stick. The
 * setting reaches only windows created afterwards: order this rule before the Compose test rule.
 */
class TouchModeRule : ExternalResource() {
    override fun before() = InstrumentationRegistry.getInstrumentation().setInTouchMode(true)
}
