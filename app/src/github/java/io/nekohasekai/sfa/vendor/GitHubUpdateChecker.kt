package io.nekohasekai.sfa.vendor

import android.os.Build
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.sfa.BuildConfig
import io.nekohasekai.sfa.ktx.unwrap
import io.nekohasekai.sfa.update.UpdateInfo
import io.nekohasekai.sfa.update.UpdateTrack
import io.nekohasekai.sfa.utils.HTTPClient
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.Closeable

class GitHubUpdateChecker : Closeable {
    companion object {
        // KiteBox updates come only from this repository's GitHub releases.
        private const val RELEASES_URL = "https://api.github.com/repos/koko123as/sing-box-for-kite/releases"
        private const val METADATA_FILENAME = "SFA-version-metadata.json"
    }

    private val client = Libbox.newHTTPClient().apply {
        modernTLS()
        keepAlive()
    }

    private val json = Json { ignoreUnknownKeys = true }

    fun checkUpdate(track: UpdateTrack, githubToken: String): UpdateInfo? {
        val request = client.newRequest()
        request.setURL(
            when (track) {
                UpdateTrack.STABLE -> "$RELEASES_URL/latest"
                UpdateTrack.BETA -> "$RELEASES_URL?per_page=3"
            },
        )
        request.setHeader("Accept", "application/vnd.github+json")
        val token = githubToken.trim()
        if (token.isNotEmpty()) {
            request.setHeader("Authorization", "Bearer $token")
        }
        request.setUserAgent(HTTPClient.userAgent)
        val content = request.execute().content.unwrap
        val releases = when (track) {
            UpdateTrack.STABLE -> listOf(json.decodeFromString<GitHubRelease>(content))
            UpdateTrack.BETA -> json.decodeFromString<List<GitHubRelease>>(content)
        }
        val release = releases.filter { !it.draft }.reduceOrNull { best, candidate ->
            if (Libbox.compareSemver(candidate.version, best.version)) candidate else best
        } ?: return null
        if (!Libbox.compareSemver(release.version, BuildConfig.VERSION_NAME)) {
            return null
        }
        // The metadata file is optional: KiteBox releases need only the APKs.
        val metadata = runCatching { downloadMetadata(release) }.getOrNull()

        return UpdateInfo(
            versionCode = metadata?.versionCode?.takeIf { it > 0 }
                ?: versionCodeFromNotes(release.body)
                ?: (BuildConfig.VERSION_CODE + 1),
            versionName = release.version,
            downloadUrl = pickApk(release.assets)?.browserDownloadUrl ?: release.htmlUrl,
            releaseUrl = release.htmlUrl,
            releaseNotes = release.body,
            isPrerelease = release.prerelease,
            fileSize = pickApk(release.assets)?.size ?: 0,
        )
    }

    /**
     * The APK for this device: one built for its primary ABI
     * (KiteBox-<version>-arm64-v8a.apk), else a universal one.
     */
    private fun pickApk(assets: List<GitHubAsset>): GitHubAsset? {
        val isLegacy = Build.VERSION.SDK_INT < Build.VERSION_CODES.M
        val apks = assets.filter { asset ->
            asset.name.endsWith(".apk") &&
                !asset.name.contains("play") &&
                !asset.name.contains("debug") &&
                asset.name.contains("legacy-android-5") == isLegacy
        }
        for (abi in Build.SUPPORTED_ABIS) {
            apks.firstOrNull { it.name.contains("-$abi") }?.let { return it }
        }
        val abiNames = listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
        return apks.firstOrNull { asset -> abiNames.none { asset.name.contains("-$it") } }
    }

    /** "Version code: 748" in the release notes (written by the release workflow). */
    private fun versionCodeFromNotes(body: String?): Int? = body?.let {
        Regex("""(?i)version[ _-]?code\W+(\d+)""").find(it)?.groupValues?.get(1)?.toIntOrNull()
    }

    private fun downloadMetadata(release: GitHubRelease): VersionMetadata? {
        val metadataAsset = release.assets.find { it.name == METADATA_FILENAME }
            ?: return null

        val request = client.newRequest()
        request.setURL(metadataAsset.browserDownloadUrl)
        request.setUserAgent(HTTPClient.userAgent)

        val response = request.execute()
        val content = response.content.unwrap

        return json.decodeFromString<VersionMetadata>(content)
    }

    override fun close() {
        client.close()
    }

    @Serializable
    data class GitHubRelease(
        @SerialName("tag_name") val tagName: String = "",
        val name: String = "",
        val body: String? = null,
        val draft: Boolean = false,
        val prerelease: Boolean = false,
        @SerialName("html_url") val htmlUrl: String = "",
        val assets: List<GitHubAsset> = emptyList(),
    ) {
        val version: String get() = tagName.removePrefix("v")
    }

    @Serializable
    data class GitHubAsset(
        val name: String = "",
        @SerialName("browser_download_url") val browserDownloadUrl: String = "",
        val size: Long = 0,
    )

    @Serializable
    data class VersionMetadata(
        @SerialName("version_code") val versionCode: Int = 0,
    )
}
