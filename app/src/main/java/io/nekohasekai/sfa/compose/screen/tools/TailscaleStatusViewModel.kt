package io.nekohasekai.sfa.compose.screen.tools

import android.util.Log
import androidx.lifecycle.viewModelScope
import io.nekohasekai.libbox.TailscaleStatusHandler
import io.nekohasekai.libbox.TailscaleStatusSubscription
import io.nekohasekai.libbox.TailscaleStatusUpdate
import io.nekohasekai.sfa.compose.base.BaseViewModel
import io.nekohasekai.sfa.database.CoreProfile
import io.nekohasekai.sfa.utils.CommandTarget
import io.nekohasekai.sfa.utils.StreamSubscription
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

data class TailscalePeerData(
    val id: String,
    val stableID: String,
    val hostName: String,
    val dnsName: String,
    val os: String,
    val tailscaleIPs: List<String>,
    val sshHostKeys: List<String>,
    val online: Boolean,
    val exitNode: Boolean,
    val exitNodeOption: Boolean,
    val shareeNode: Boolean,
    val expired: Boolean,
    val active: Boolean,
    val rxBytes: Long,
    val txBytes: Long,
    val keyExpiry: Long,
    val lastSeen: Long,
    val canReceiveFiles: Boolean,
) {
    val displayName: String get() = dnsName.substringBefore(".").ifEmpty { hostName }
}

data class TailscaleUserGroupData(
    val id: Long,
    val loginName: String,
    val displayName: String,
    val profilePicURL: String,
    val peers: List<TailscalePeerData>,
)

data class TailscaleEndpointData(
    val endpointTag: String,
    val backendState: String,
    val stateText: String,
    val authURL: String,
    val networkName: String,
    val magicDNSSuffix: String,
    val selfPeer: TailscalePeerData?,
    val exitNode: TailscalePeerData?,
    val userGroups: List<TailscaleUserGroupData>,
    val keyAuth: Boolean,
    val canShareFiles: Boolean,
    val waitingFileCount: Int,
    val receivingFileCount: Int,
    val unreadFileCount: Int,
) {
    val taildropFileCount: Int get() = waitingFileCount + receivingFileCount

    val hasExitNodeCandidates: Boolean
        get() {
            if (exitNode != null) return true
            val selfStableID = selfPeer?.stableID
            return userGroups.any { group ->
                group.peers.any { it.exitNodeOption && it.stableID != selfStableID }
            }
        }
}

data class TailscaleStatusState(
    val endpoints: List<TailscaleEndpointData> = emptyList(),
    val isSubscribed: Boolean = false,
    val hasUpdate: Boolean = false,
)

class TailscaleStatusViewModel : BaseViewModel<TailscaleStatusState, Nothing>() {
    private companion object {
        const val TAG = "TailscaleStatus"

        // How often the active core is re-checked, and how long to wait
        // before reopening a stream that ended (e.g. during a core switch).
        const val CORE_CHECK_INTERVAL = 1500L
        const val RETRY_DELAY = 1000L
    }

    private val statusSubscription = StreamSubscription<TailscaleStatusSubscription> { it.close() }
    private var subscriptionJob: Job? = null

    override fun createInitialState() = TailscaleStatusState()

    /**
     * Follows the Tailscale status of the running service. Tailscale exists
     * only in sing-box: while the selected profile runs on Xray or mihomo the
     * status is not queried at all. A stream that fails (the core is being
     * switched, or the next one is still starting) is reopened silently
     * instead of showing an error.
     */
    fun subscribe() {
        if (currentState.isSubscribed) return
        updateState { copy(isSubscribed = true) }
        subscriptionJob?.cancel()
        subscriptionJob = viewModelScope.launch(Dispatchers.IO) {
            while (isActive) {
                if (!singBoxActive()) {
                    clearEndpoints()
                    delay(CORE_CHECK_INTERVAL)
                    continue
                }
                val ended = CompletableDeferred<String>()
                val token = statusSubscription.open()
                try {
                    val session = CommandTarget.standaloneClient()
                        .subscribeTailscaleStatus(object : TailscaleStatusHandler {
                            override fun onStatusUpdate(status: TailscaleStatusUpdate) {
                                val endpoints = convertUpdate(status)
                                viewModelScope.launch {
                                    if (!currentState.isSubscribed) return@launch
                                    updateState { copy(endpoints = endpoints, hasUpdate = true) }
                                }
                            }

                            override fun onError(message: String) {
                                ended.complete(message)
                            }
                        })
                    statusSubscription.store(token, session)
                } catch (e: Exception) {
                    ended.complete(e.message ?: "")
                }
                // Stay on this stream until it ends or the service switches
                // to a core without Tailscale.
                while (isActive && !ended.isCompleted) {
                    withTimeoutOrNull(CORE_CHECK_INTERVAL) { ended.await() }
                    if (!ended.isCompleted && !singBoxActive()) break
                }
                statusSubscription.close()
                if (ended.isCompleted) {
                    Log.d(TAG, "status stream ended, retrying: ${ended.await()}")
                }
                delay(RETRY_DELAY)
            }
        }
    }

    private suspend fun singBoxActive(): Boolean {
        // A remote server reports its own Tailscale status; locally only the
        // sing-box core has Tailscale endpoints.
        if (CommandTarget.isRemote) return true
        val core = CoreProfile.selectedCore() ?: return true
        return core == CoreProfile.SING_BOX
    }

    private suspend fun clearEndpoints() {
        withContext(Dispatchers.Main) {
            if (currentState.endpoints.isNotEmpty() || currentState.hasUpdate) {
                updateState { copy(endpoints = emptyList(), hasUpdate = false) }
            }
        }
    }

    fun cancel() {
        subscriptionJob?.cancel()
        subscriptionJob = null
        statusSubscription.close()
        updateState { copy(endpoints = emptyList(), isSubscribed = false, hasUpdate = false) }
    }

    fun setExitNode(endpointTag: String, stableID: String) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                CommandTarget.standaloneClient().setTailscaleExitNode(endpointTag, stableID)
            } catch (e: Exception) {
                sendErrorMessage(e.message ?: "set exit node failed")
            }
        }
    }

    fun logout(endpointTag: String) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                CommandTarget.standaloneClient().tailscaleLogout(endpointTag)
            } catch (e: Exception) {
                sendErrorMessage(e.message ?: "logout failed")
            }
        }
    }

    fun endpoint(tag: String): TailscaleEndpointData? = currentState.endpoints.firstOrNull { it.endpointTag == tag }

    fun peer(endpointTag: String, peerId: String): TailscalePeerData? {
        val ep = endpoint(endpointTag) ?: return null
        if (ep.selfPeer?.id == peerId) return ep.selfPeer
        for (group in ep.userGroups) {
            val found = group.peers.firstOrNull { it.id == peerId }
            if (found != null) return found
        }
        return null
    }

    override fun onCleared() {
        cancel()
        super.onCleared()
    }

    private fun convertUpdate(status: TailscaleStatusUpdate): List<TailscaleEndpointData> {
        val endpoints = mutableListOf<TailscaleEndpointData>()
        val iterator = status.endpoints()
        while (iterator.hasNext()) {
            endpoints.add(convertEndpoint(iterator.next()))
        }
        return endpoints
    }

    private fun convertEndpoint(
        endpoint: io.nekohasekai.libbox.TailscaleEndpointStatus,
    ): TailscaleEndpointData {
        val userGroups = mutableListOf<TailscaleUserGroupData>()
        val groupIterator = endpoint.userGroups()
        while (groupIterator.hasNext()) {
            userGroups.add(convertUserGroup(groupIterator.next()))
        }
        val self = endpoint.getSelf()
        val exitNode = endpoint.exitNode
        return TailscaleEndpointData(
            endpointTag = endpoint.endpointTag,
            backendState = endpoint.backendState,
            stateText = endpoint.stateText,
            authURL = endpoint.authURL,
            networkName = endpoint.networkName,
            magicDNSSuffix = endpoint.magicDNSSuffix,
            selfPeer = if (self != null) convertPeer(self) else null,
            exitNode = if (exitNode != null) convertPeer(exitNode) else null,
            userGroups = userGroups,
            keyAuth = endpoint.keyAuth,
            canShareFiles = endpoint.canShareFiles,
            waitingFileCount = endpoint.waitingFileCount,
            receivingFileCount = endpoint.receivingFileCount,
            unreadFileCount = endpoint.unreadFileCount,
        )
    }

    private fun convertUserGroup(
        group: io.nekohasekai.libbox.TailscaleUserGroup,
    ): TailscaleUserGroupData {
        val peers = mutableListOf<TailscalePeerData>()
        val peerIterator = group.peers()
        while (peerIterator.hasNext()) {
            peers.add(convertPeer(peerIterator.next()))
        }
        return TailscaleUserGroupData(
            id = group.userID,
            loginName = group.loginName,
            displayName = group.displayName,
            profilePicURL = group.profilePicURL,
            peers = peers,
        )
    }

    private fun convertPeer(peer: io.nekohasekai.libbox.TailscalePeer): TailscalePeerData {
        val ips = mutableListOf<String>()
        val ipIterator = peer.tailscaleIPs()
        while (ipIterator.hasNext()) {
            ips.add(ipIterator.next())
        }
        val sshKeys = mutableListOf<String>()
        val keyIterator = peer.sshHostKeys()
        while (keyIterator.hasNext()) {
            sshKeys.add(keyIterator.next())
        }
        val dnsName = peer.getDNSName()
        return TailscalePeerData(
            id = if (dnsName.isNotEmpty()) dnsName else peer.hostName,
            stableID = peer.stableID,
            hostName = peer.hostName,
            dnsName = dnsName,
            os = peer.getOS(),
            tailscaleIPs = ips,
            sshHostKeys = sshKeys,
            online = peer.online,
            exitNode = peer.exitNode,
            exitNodeOption = peer.exitNodeOption,
            shareeNode = peer.shareeNode,
            expired = peer.expired,
            active = peer.active,
            rxBytes = peer.rxBytes,
            txBytes = peer.txBytes,
            keyExpiry = peer.keyExpiry,
            lastSeen = peer.lastSeen,
            canReceiveFiles = peer.canReceiveFiles,
        )
    }
}
