package io.nekohasekai.sfa.bg

import android.util.Log
import io.nekohasekai.libbox.Libbox
import java.io.File

/**
 * Geo data for Xray (geoip.dat / geosite.dat) and mihomo (GeoIP/GeoSite/MMDB/ASN),
 * kept in the shared directory libbox reports (Libbox.geoDataDir). mihomo
 * downloads what it misses by itself; Xray cannot, so the files an Xray profile
 * references are downloaded before it starts (with the device network, before
 * the VPN is up).
 */
object GeoData {
    private const val TAG = "GeoData"

    val resources = listOf(Libbox.GeoResourceGeoIP, Libbox.GeoResourceGeoSite, Libbox.GeoResourceMMDB, Libbox.GeoResourceASN)

    fun file(name: String): File = File(Libbox.geoDataDir(), Libbox.geoResourceFileName(name))

    /** Downloads geoip.dat / geosite.dat when an Xray config uses them and they are missing. */
    fun ensureForXray(content: String) {
        val needed = buildList {
            if (content.contains("geoip:")) add(Libbox.GeoResourceGeoIP)
            if (content.contains("geosite:")) add(Libbox.GeoResourceGeoSite)
        }
        for (name in needed) {
            if (file(name).isFile) continue
            runCatching { update(name) }.onFailure {
                Log.w(TAG, "download $name", it)
            }
        }
    }

    /** Downloads one resource from its default URL; throws on failure, keeping the old file. */
    fun update(name: String) {
        File(Libbox.geoDataDir()).mkdirs()
        Libbox.updateGeoResource(Libbox.geoDataDir(), name, "")
    }
}
