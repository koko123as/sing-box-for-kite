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

    /** The concrete cores, in the order Settings > Core lists them. */
    val cores = listOf(SING_BOX, MIHOMO, XRAY)

    data class Prepared(val core: String, val content: String, val remarks: String = "", val key: String = "")

    /**
     * Content ready to save for [declaredCore] ("auto" detects): share links are
     * converted, and the result is checked by its own core's parser. A JSON
     * array of several configs is rejected here: use [prepareAll].
     */
    fun prepare(declaredCore: String, content: String): Prepared {
        val entries = prepareAll(declaredCore, content)
        require(entries.size == 1) { "The configuration holds ${entries.size} configs; each becomes its own profile" }
        return entries.first()
    }

    /**
     * Like [prepare], but a JSON array of configs (a subscription serving
     * several configs) is split into one entry per config. Each entry's [Prepared.key]
     * finds the same config again when the subscription updates: its
     * "remarks" when it has one, otherwise its position ("#2").
     * Errors name the config and the core that rejected it.
     */
    fun prepareAll(declaredCore: String, content: String): List<Prepared> {
        require(content.isNotBlank()) { "Empty configuration" }
        if (Libbox.detectCoreConfig(content) != Libbox.CoreArray) {
            return listOf(prepareOne(declaredCore, content))
        }
        val entries = Libbox.splitCoreConfigArrayEach(content)
        val usedKeys = mutableSetOf<String>()
        return (0 until entries.len()).map { index ->
            val remarks = entries.remarks(index)
            val key = remarks.takeIf { it.isNotEmpty() && usedKeys.add(it) } ?: "#${index + 1}"
            val core = if (normalize(declaredCore) == AUTO) entries.core(index) else declaredCore
            try {
                prepareOne(core, entries.content(index)).copy(remarks = remarks, key = key)
            } catch (e: Exception) {
                val name = if (remarks.isNotEmpty()) "${index + 1} ($remarks)" else "${index + 1}"
                throw Exception("config $name: ${e.message}", e)
            }
        }
    }

    private fun prepareOne(declaredCore: String, content: String): Prepared {
        val prepared = if (Libbox.detectCoreConfig(content) == Libbox.CoreLinks) {
            val converted = try {
                Libbox.convertCoreShareLinksFor(normalize(declaredCore), content)
            } catch (e: Exception) {
                throw Exception("${coreName(declaredCore)}: ${e.message}", e)
            }
            Prepared(converted.core, converted.content)
        } else {
            Prepared(Libbox.resolveProfileCore(normalize(declaredCore), content), content)
        }
        // The error names the core that rejected the content ("mihomo: ...").
        Libbox.checkCoreConfig(prepared.core, prepared.content)
        return prepared
    }

    private fun coreName(core: String): String = if (normalize(core) == AUTO) "auto" else Libbox.coreDisplayName(core)

    // ---- enabled cores (Settings > Core) ----

    fun isEnabled(core: String): Boolean = core !in Settings.disabledCores

    val enabledCores: List<String> get() = cores.filter { isEnabled(it) }

    /** Turns [core] on or off; the last enabled core cannot be turned off. */
    fun setEnabled(core: String, enabled: Boolean): Boolean {
        val disabled = Settings.disabledCores.toMutableSet()
        if (enabled) {
            disabled.remove(core)
        } else {
            if (cores.count { it !in disabled && it != core } == 0) return false
            disabled.add(core)
        }
        Settings.disabledCores = disabled
        return true
    }

    // ---- resolved core of saved profiles, cached by file version ----

    private data class CacheKey(val path: String, val declared: String, val modified: Long, val length: Long)

    private val resolvedCache = java.util.concurrent.ConcurrentHashMap<String, Pair<CacheKey, String?>>()

    /**
     * The core that runs [profile] (reads the file only when it changed), or
     * null when its content cannot be resolved.
     */
    fun cachedCore(profile: Profile): String? {
        val declared = normalize(profile.typed.core)
        if (declared != AUTO) return declared
        val file = File(profile.typed.path)
        val key = CacheKey(profile.typed.path, declared, file.lastModified(), file.length())
        resolvedCache[profile.typed.path]?.let { (cachedKey, core) -> if (cachedKey == key) return core }
        val core = runCatching { resolve(profile) }.getOrNull()
        resolvedCache[profile.typed.path] = key to core
        return core
    }

    /** The core of the selected profile (the one the service runs), or null. */
    suspend fun selectedCore(): String? {
        val id = Settings.selectedProfile
        if (id == -1L) return null
        val profile = ProfileManager.get(id) ?: return null
        return cachedCore(profile)
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
