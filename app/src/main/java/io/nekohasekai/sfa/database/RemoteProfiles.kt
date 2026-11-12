package io.nekohasekai.sfa.database

import io.nekohasekai.sfa.Application
import io.nekohasekai.sfa.utils.HTTPClient
import java.io.File
import java.util.Date

/**
 * Creates and updates subscription (remote) profiles. A subscription that
 * serves a JSON array of configs becomes one profile per config: each keeps
 * the subscription URL and the key of its config ([TypedProfile.arrayKey]),
 * and an update writes each profile's own config and adds profiles for
 * configs the subscription started serving.
 */
object RemoteProfiles {
    private fun configFile(fileID: Long): File {
        val directory = File(Application.application.filesDir, "configs").also { it.mkdirs() }
        return File(directory, "$fileID.json")
    }

    private fun entryName(baseName: String, entry: CoreProfile.Prepared, count: Int): String = if (count <= 1) {
        baseName
    } else {
        "$baseName - ${entry.remarks.ifEmpty { entry.key }}"
    }

    private suspend fun saveNew(
        name: String,
        url: String,
        declaredCore: String,
        autoUpdate: Boolean,
        autoUpdateInterval: Int,
        entry: CoreProfile.Prepared,
        arrayKey: String,
        select: Boolean,
    ): Profile {
        val typed = TypedProfile().apply {
            type = TypedProfile.Type.Remote
            remoteURL = url
            this.autoUpdate = autoUpdate
            this.autoUpdateInterval = autoUpdateInterval
            lastUpdated = Date()
            core = declaredCore
            this.arrayKey = arrayKey
        }
        val profile = Profile(name = name, typed = typed).apply {
            userOrder = ProfileManager.nextOrder()
        }
        val file = configFile(ProfileManager.nextFileID())
        typed.path = file.path
        file.writeText(entry.content)
        return ProfileManager.create(profile, andSelect = select)
    }

    /**
     * Fetches [url] and saves its profiles. Returns them in subscription
     * order; the first one is selected when [select] is set.
     */
    suspend fun create(
        name: String,
        url: String,
        declaredCore: String,
        autoUpdate: Boolean,
        autoUpdateInterval: Int,
        select: Boolean = true,
    ): List<Profile> {
        val content = HTTPClient().use { it.getString(url, declaredCore) }
        val entries = CoreProfile.prepareAll(declaredCore, content)
        return entries.mapIndexed { index, entry ->
            saveNew(
                name = entryName(name, entry, entries.size),
                url = url,
                declaredCore = declaredCore,
                autoUpdate = autoUpdate,
                autoUpdateInterval = autoUpdateInterval,
                entry = entry,
                arrayKey = if (entries.size > 1) entry.key else "",
                select = select && index == 0,
            )
        }
    }

    /**
     * Fetches [profile]'s subscription and writes its config. Returns true
     * when the saved content of [profile] changed. Configs of the same
     * subscription that no profile holds yet are added as new profiles.
     */
    suspend fun update(profile: Profile): Boolean {
        val typed = profile.typed
        val content = HTTPClient().use { it.getString(typed.remoteURL, typed.core) }
        val entries = CoreProfile.prepareAll(typed.core, content)
        val mine = entries.firstOrNull { typed.arrayKey.isNotEmpty() && it.key == typed.arrayKey }
            ?: entries.singleOrNull()
            ?: entries.takeIf { typed.arrayKey.isEmpty() }?.first()
            ?: throw Exception("config \"${typed.arrayKey}\" is no longer served by this subscription")

        val previousKey = typed.arrayKey
        typed.arrayKey = if (entries.size > 1) mine.key else ""
        val file = File(typed.path)
        val changed = !file.exists() || file.readText() != mine.content
        if (changed) {
            file.writeText(mine.content)
        }
        typed.lastUpdated = Date()
        ProfileManager.update(profile)

        if (entries.size > 1) {
            val siblings = ProfileManager.list().filter {
                it.id != profile.id && it.typed.type == TypedProfile.Type.Remote && it.typed.remoteURL == typed.remoteURL
            }
            val held = siblings.map { it.typed.arrayKey }.toSet() + typed.arrayKey
            // The profile was named "<subscription> - <config>" when it was split.
            val ownLabel = " - " + mine.remarks.ifEmpty { previousKey.ifEmpty { mine.key } }
            val baseName = profile.name.removeSuffix(ownLabel)
            for (entry in entries) {
                if (entry.key in held) continue
                saveNew(
                    name = entryName(baseName, entry, entries.size),
                    url = typed.remoteURL,
                    declaredCore = typed.core,
                    autoUpdate = typed.autoUpdate,
                    autoUpdateInterval = typed.autoUpdateInterval,
                    entry = entry,
                    arrayKey = entry.key,
                    select = false,
                )
            }
        }
        return changed
    }
}
