package app.sineloco.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * KNOWN GAP G1 (docs/ANDROID_PORT.md 3.4): this field keeps its text in a Kotlin String, which cannot be wiped and may be copied by the
 * runtime. The planned replacement is an input view that feeds committed IME text straight into the Rust core's zeroizing buffers and
 * draws only dots (passwords) or a borrowed view of the draft. Every secret-bearing field goes through THIS function, so the swap
 * is one place. Android flags (no personalised learning, password type) are applied by the host in that replacement.
 */
@Composable
fun SecureField(
    value: String, onChange: (String) -> Unit, placeholder: String,
    modifier: Modifier = Modifier, secret: Boolean = false, numeric: Boolean = false, singleLine: Boolean = true, maxLines: Int = 1,
) {
    val fg = MaterialTheme.colorScheme.onSurface
    BasicTextField(
        value = value, onValueChange = onChange, singleLine = singleLine, maxLines = maxLines,
        textStyle = TextStyle(color = fg, fontSize = 16.sp),
        cursorBrush = SolidColor(MaterialTheme.colorScheme.primary),
        visualTransformation = if (secret) PasswordVisualTransformation() else VisualTransformation.None,
        keyboardOptions = KeyboardOptions(keyboardType = if (secret) KeyboardType.Password else if (numeric) KeyboardType.Number else KeyboardType.Text, autoCorrectEnabled = false),
        modifier = modifier,
        decorationBox = { inner ->
            Box(Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(24.dp)).padding(horizontal = 18.dp, vertical = 14.dp), contentAlignment = Alignment.CenterStart) {
                if (value.isEmpty()) Text(placeholder, color = SineTheme.colors.muted, fontSize = 16.sp)
                inner()
            }
        },
    )
}
