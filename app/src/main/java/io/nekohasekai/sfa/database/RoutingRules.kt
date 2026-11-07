package io.nekohasekai.sfa.database

import kotlinx.serialization.SerialName
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.util.UUID

/**
 * One user routing rule (like v2rayNG's routing settings). Matches when
 * (any domain OR any IP) AND (any app) AND port AND network; empty parts are
 * left out. The same list applies to every profile and is translated for the
 * core that runs it (libbox ApplyCoreRoutingRules); field names are the JSON
 * libbox reads.
 */
@Serializable
data class RoutingRule(
    val id: String = UUID.randomUUID().toString(),
    val remarks: String = "",
    val enabled: Boolean = true,
    val domain: List<String> = emptyList(),
    val ip: List<String> = emptyList(),
    @SerialName("package") val packages: List<String> = emptyList(),
    val port: String = "",
    val network: String = "",
    @SerialName("target_type") val targetType: String = TARGET_PROXY,
    val outbound: String = "",
) {
    companion object {
        const val TARGET_PROXY = "proxy"
        const val TARGET_DIRECT = "direct"
        const val TARGET_BLOCK = "block"

        const val NETWORK_ANY = ""
        const val NETWORK_TCP = "tcp"
        const val NETWORK_UDP = "udp"
    }
}

object RoutingRules {
    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    fun load(): List<RoutingRule> = decode(Settings.routingRules)

    fun save(rules: List<RoutingRule>) {
        Settings.routingRules = encode(rules)
    }

    fun decode(content: String): List<RoutingRule> {
        if (content.isBlank()) return emptyList()
        return runCatching { json.decodeFromString<List<RoutingRule>>(content) }.getOrDefault(emptyList())
    }

    fun encode(rules: List<RoutingRule>): String = json.encodeToString(rules)

    /** The rules libbox applies at start/reload (enabled ones only). */
    fun toCoreJson(rules: List<RoutingRule>): String = encode(rules.filter { it.enabled })

    /** Splits user input (one entry per line or comma separated). */
    fun splitEntries(text: String): List<String> = text.split('\n', ',').map { it.trim() }.filter { it.isNotEmpty() }.distinct()
}
