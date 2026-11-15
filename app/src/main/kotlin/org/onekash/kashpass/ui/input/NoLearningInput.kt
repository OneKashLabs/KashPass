package org.onekash.kashpass.ui.input

import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputConnection
import androidx.compose.runtime.Composable
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.autofill.ContentDataType
import androidx.compose.ui.platform.InterceptPlatformTextInput
import androidx.compose.ui.platform.PlatformTextInputInterceptor
import androidx.compose.ui.platform.PlatformTextInputMethodRequest
import androidx.compose.ui.platform.PlatformTextInputSession
import androidx.compose.ui.semantics.contentDataType
import androidx.compose.ui.semantics.semantics

/**
 * Runs [content] with every text field in it setting the flag that tells the keyboard not to
 * learn what is typed (`EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING`). Compose has no keyboard
 * option for that flag, so the request each field sends to the keyboard is wrapped
 * ([noLearning]).
 */
@OptIn(ExperimentalComposeUiApi::class)
@Composable
fun NoPersonalizedLearning(content: @Composable () -> Unit) = InterceptPlatformTextInput(NoLearningInterceptor, content)

@OptIn(ExperimentalComposeUiApi::class)
private object NoLearningInterceptor : PlatformTextInputInterceptor {
    override suspend fun interceptStartInputMethod(request: PlatformTextInputMethodRequest, nextHandler: PlatformTextInputSession): Nothing =
        nextHandler.startInputMethod(noLearning(request))
}

/**
 * Wraps [request] so the flag is added after the field fills in its own options: the field assigns
 * `imeOptions` outright, so setting the flag first would be lost. [NoLearningInputTest] pins it.
 */
internal fun noLearning(request: PlatformTextInputMethodRequest) = object : PlatformTextInputMethodRequest {
    override fun createInputConnection(outAttributes: EditorInfo): InputConnection =
        request.createInputConnection(outAttributes).also {
            outAttributes.imeOptions = outAttributes.imeOptions or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
        }
}

/**
 * Marks a text field as holding no data an autofill service should fill or save. Compose reports a
 * focused field to the autofill framework by its data type whatever the view's importance, so
 * `importantForAutofill` on the window alone isn't enough (compose ui 1.12.1).
 */
fun Modifier.noAutofill(): Modifier = semantics { contentDataType = ContentDataType.None }
