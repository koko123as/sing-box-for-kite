package io.nekohasekai.sfa.database

import android.content.Context
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.sfa.R
import java.io.File

/**
 * Which core (sing-box, Xray or mihomo) runs a profile. Every profile runs
 * directly on its own core; nothing is converted from one core to another at
 * start. Share links / Base64 node lists are turned into a full profile of the
 * chosen core when they are saved.
 */
object CoreProfile {
    const val AUTO = "auto"
    const val SING_BOX = "sing-box"
    const val XRAY = "xray"
    const val MIHOMO = "mihomo"

    val choices = listOf(AUTO, SING_BOX, XRAY, MIHOMO)

    fun normalize(core: String?): String = if (core in choices) core!! else AUTO

    /** The empty configuration a new local profile of [core] starts with. */
    fun emptyConfig(core: String): String = when (normalize(core)) {
        XRAY -> "{\n  \"log\": {\n    \"loglevel\": \"warning\"\n  },\n  \"outbounds\": [\n    {\n      \"tag\": \"direct\",\n      \"protocol\": \"freedom\"\n    }\n  ]\n}\n"
        MIHOMO -> "log-level: warning\nproxies: []\nproxy-groups: []\nrules:\n  - MATCH,DIRECT\n"
        else -> "{}"
    }

    data class Prepared(val core: String, val content: String)

    /**
     * Content ready to save for [declaredCore] ("auto" detects): share links are
     * converted, and the result is checked by its own core's parser.
     */
    fun prepare(declaredCore: String, content: String): Prepared {
        require(content.isNotBlank()) { "Empty configuration" }
        val prepared = if (Libbox.detectCoreConfig(content) == Libbox.CoreLinks) {
            val converted = Libbox.convertCoreShareLinksFor(normalize(declaredCore), content)
            Prepared(converted.core, converted.content)
        } else {
            Prepared(Libbox.resolveProfileCore(normalize(declaredCore), content), content)
        }
        Libbox.checkCoreConfig(prepared.core, prepared.content)
        return prepared
    }

    /** Checks [content] with the core [declaredCore] resolves to. */
    fun check(declaredCore: String, content: String) {
        Libbox.checkCoreConfig(Libbox.resolveProfileCore(normalize(declaredCore), content), content)
    }

    /** The core that runs [profile] with its saved content. */
    fun resolve(profile: Profile, content: String = File(profile.typed.path).readText()): String = Libbox.resolveProfileCore(profile.typed.core, content)

    fun resolveOrNull(profile: Profile): String? = runCatching { resolve(profile) }.getOrNull()

    /** The subscription User-Agent for a profile declared as [declaredCore]. */
    fun subscriptionUserAgent(declaredCore: String, default: String): String = when (normalize(declaredCore)) {
        XRAY -> Libbox.coreSubscriptionUserAgent(XRAY, "")
        MIHOMO -> Libbox.coreSubscriptionUserAgent(MIHOMO, "")
        else -> default
    }

    fun label(context: Context, core: String): String = when (core) {
        SING_BOX -> "sing-box"
        XRAY -> "Xray"
        MIHOMO -> "mihomo"
        else -> context.getString(R.string.core_auto)
    }
}
