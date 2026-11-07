package io.nekohasekai.sfa.compose.component

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.nekohasekai.sfa.R
import io.nekohasekai.sfa.database.CoreProfile

/** Picks the core a profile runs on: auto (detected), sing-box, Xray or mihomo. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CoreSelector(selected: String, onSelected: (String) -> Unit, modifier: Modifier = Modifier, enabled: Boolean = true) {
    val context = LocalContext.current
    Column(modifier = modifier, verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            text = stringResource(R.string.profile_core),
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.primary,
        )
        SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
            CoreProfile.choices.forEachIndexed { index, core ->
                SegmentedButton(
                    shape = SegmentedButtonDefaults.itemShape(index = index, count = CoreProfile.choices.size),
                    onClick = { onSelected(core) },
                    selected = CoreProfile.normalize(selected) == core,
                    enabled = enabled,
                ) {
                    Text(CoreProfile.label(context, core), maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
            }
        }
        Text(
            text = stringResource(R.string.profile_core_hint),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
