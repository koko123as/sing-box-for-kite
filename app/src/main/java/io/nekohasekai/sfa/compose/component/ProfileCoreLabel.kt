package io.nekohasekai.sfa.compose.component

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.platform.LocalContext
import io.nekohasekai.sfa.database.CoreProfile
import io.nekohasekai.sfa.database.Profile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * The name of the core [profile] runs on ("sing-box", "Xray", "mihomo"), for
 * profile labels such as "mihomo • Remote • 10 minutes ago". A profile set to
 * auto is resolved from its saved content off the main thread; null until
 * known or when the content cannot be resolved.
 */
@Composable
fun rememberProfileCoreLabel(profile: Profile): String? {
    val context = LocalContext.current
    val declared = CoreProfile.normalize(profile.typed.core)
    val core by produceState(
        initialValue = declared.takeIf { it != CoreProfile.AUTO },
        profile.id,
        profile.typed.core,
        profile.typed.lastUpdated,
        profile.typed.path,
    ) {
        value = withContext(Dispatchers.IO) { CoreProfile.cachedCore(profile) }
    }
    return core?.let { CoreProfile.label(context, it) }
}
