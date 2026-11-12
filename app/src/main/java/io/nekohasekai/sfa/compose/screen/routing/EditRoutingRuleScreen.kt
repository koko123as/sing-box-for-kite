package io.nekohasekai.sfa.compose.screen.routing

import android.content.pm.ApplicationInfo
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Apps
import androidx.compose.material.icons.outlined.ArrowDropDown
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.Save
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.sfa.R
import io.nekohasekai.sfa.compose.base.UiEvent
import io.nekohasekai.sfa.compose.base.rememberApplyServiceChangeNotifier
import io.nekohasekai.sfa.compose.topbar.LocalScaffoldPadding
import io.nekohasekai.sfa.compose.topbar.OverrideTopBar
import io.nekohasekai.sfa.constant.Status
import io.nekohasekai.sfa.database.CoreProfile
import io.nekohasekai.sfa.database.ProfileManager
import io.nekohasekai.sfa.database.RoutingRule
import io.nekohasekai.sfa.database.RoutingRules
import io.nekohasekai.sfa.database.Settings
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

private data class RuleTargets(val profileName: String, val names: List<String>)

private data class InstalledApp(val label: String, val packageName: String)

/** Adds or edits one routing rule. [ruleId] is "new" for a new rule. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EditRoutingRuleScreen(navController: NavController, ruleId: String, serviceStatus: Status = Status.Stopped) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val notifyApplyChange = rememberApplyServiceChangeNotifier(serviceStatus)
    val isNew = ruleId == "new"

    var loaded by remember { mutableStateOf(false) }
    var original by remember { mutableStateOf(RoutingRule()) }
    var remarks by remember { mutableStateOf("") }
    var enabled by remember { mutableStateOf(true) }
    var domains by remember { mutableStateOf("") }
    var ips by remember { mutableStateOf("") }
    var packages by remember { mutableStateOf("") }
    var port by remember { mutableStateOf("") }
    var network by remember { mutableStateOf(RoutingRule.NETWORK_ANY) }
    var targetType by remember { mutableStateOf(RoutingRule.TARGET_PROXY) }
    var outbound by remember { mutableStateOf("") }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    var showDeleteDialog by remember { mutableStateOf(false) }
    var showAppPicker by remember { mutableStateOf(false) }
    var targets by remember { mutableStateOf<RuleTargets?>(null) }
    var targetMenuExpanded by remember { mutableStateOf(false) }

    LaunchedEffect(ruleId) {
        val rule = withContext(Dispatchers.IO) {
            RoutingRules.load().firstOrNull { it.id == ruleId }
        } ?: RoutingRule()
        original = rule
        remarks = rule.remarks
        enabled = rule.enabled
        domains = rule.domain.joinToString("\n")
        ips = rule.ip.joinToString("\n")
        packages = rule.packages.joinToString("\n")
        port = rule.port
        network = rule.network
        targetType = rule.targetType
        outbound = rule.outbound
        loaded = true
        // Outbounds and groups of the selected profile, read with its own core.
        targets = withContext(Dispatchers.IO) {
            runCatching {
                val profile = ProfileManager.get(Settings.selectedProfile) ?: return@runCatching null
                val content = File(profile.typed.path).readText()
                val core = Libbox.resolveProfileCore(profile.typed.core, content)
                val names = Libbox.coreProfileTargets(core, content).split('\n').filter { it.isNotBlank() }
                RuleTargets("${profile.name} (${CoreProfile.label(context, core)})", names)
            }.getOrNull()
        }
    }

    fun buildRule(): RoutingRule = original.copy(
        remarks = remarks.trim(),
        enabled = enabled,
        domain = RoutingRules.splitEntries(domains),
        ip = RoutingRules.splitEntries(ips),
        packages = RoutingRules.splitEntries(packages),
        port = port.trim(),
        network = network,
        targetType = targetType,
        outbound = if (targetType == RoutingRule.TARGET_PROXY) outbound.trim() else "",
    )

    fun save() {
        val rule = buildRule()
        if (rule.domain.isEmpty() && rule.ip.isEmpty() && rule.packages.isEmpty() && rule.port.isEmpty() && rule.network.isEmpty()) {
            errorMessage = context.getString(R.string.routing_rule_error_no_match)
            return
        }
        if (rule.targetType == RoutingRule.TARGET_PROXY && rule.outbound.isEmpty()) {
            errorMessage = context.getString(R.string.routing_rule_error_no_outbound)
            return
        }
        scope.launch {
            withContext(Dispatchers.IO) {
                val rules = RoutingRules.load().toMutableList()
                val index = rules.indexOfFirst { it.id == rule.id }
                if (index >= 0) rules[index] = rule else rules.add(rule)
                RoutingRules.save(rules)
            }
            notifyApplyChange(UiEvent.ApplyServiceChange.Mode.Reload)
            navController.navigateUp()
        }
    }

    fun delete() {
        scope.launch {
            withContext(Dispatchers.IO) {
                RoutingRules.save(RoutingRules.load().filter { it.id != original.id })
            }
            notifyApplyChange(UiEvent.ApplyServiceChange.Mode.Reload)
            navController.navigateUp()
        }
    }

    OverrideTopBar {
        TopAppBar(
            title = { Text(stringResource(if (isNew) R.string.routing_rule_add else R.string.routing_rule_edit)) },
            navigationIcon = {
                IconButton(onClick = { navController.navigateUp() }) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.content_description_back))
                }
            },
            actions = {
                if (!isNew) {
                    IconButton(onClick = { showDeleteDialog = true }) {
                        Icon(Icons.Outlined.Delete, contentDescription = stringResource(R.string.menu_delete))
                    }
                }
                IconButton(onClick = { save() }, enabled = loaded) {
                    Icon(Icons.Outlined.Save, contentDescription = stringResource(R.string.save))
                }
            },
        )
    }

    val scaffoldPadding = LocalScaffoldPadding.current
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(scaffoldPadding)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        SectionCard {
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(
                    value = remarks,
                    onValueChange = { remarks = it },
                    label = { Text(stringResource(R.string.routing_rule_remarks)) },
                    singleLine = true,
                    modifier = Modifier.weight(1f),
                )
                Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.padding(start = 12.dp)) {
                    Text(stringResource(R.string.routing_rule_enabled), style = MaterialTheme.typography.labelMedium)
                    Switch(checked = enabled, onCheckedChange = { enabled = it })
                }
            }
        }

        SectionCard {
            OutlinedTextField(
                value = domains,
                onValueChange = { domains = it },
                label = { Text(stringResource(R.string.routing_rule_domain)) },
                supportingText = { Text(stringResource(R.string.routing_rule_domain_hint)) },
                minLines = 3,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = ips,
                onValueChange = { ips = it },
                label = { Text(stringResource(R.string.routing_rule_ip)) },
                supportingText = { Text(stringResource(R.string.routing_rule_ip_hint)) },
                minLines = 2,
                modifier = Modifier.fillMaxWidth(),
            )
        }

        SectionCard {
            OutlinedTextField(
                value = packages,
                onValueChange = { packages = it },
                label = { Text(stringResource(R.string.routing_rule_apps)) },
                supportingText = { Text(stringResource(R.string.routing_rule_apps_hint)) },
                minLines = 2,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedButton(onClick = { showAppPicker = true }) {
                Icon(Icons.Outlined.Apps, contentDescription = null)
                Text(stringResource(R.string.routing_rule_apps_select), modifier = Modifier.padding(start = 8.dp))
            }
        }

        SectionCard {
            OutlinedTextField(
                value = port,
                onValueChange = { port = it },
                label = { Text(stringResource(R.string.routing_rule_port)) },
                supportingText = { Text(stringResource(R.string.routing_rule_port_hint)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Text(stringResource(R.string.routing_rule_network), style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary)
            val networks = listOf(RoutingRule.NETWORK_ANY, RoutingRule.NETWORK_TCP, RoutingRule.NETWORK_UDP)
            SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                networks.forEachIndexed { index, value ->
                    SegmentedButton(
                        shape = SegmentedButtonDefaults.itemShape(index = index, count = networks.size),
                        onClick = { network = value },
                        selected = network == value,
                    ) {
                        Text(if (value.isEmpty()) stringResource(R.string.routing_rule_network_any) else value.uppercase())
                    }
                }
            }
        }

        SectionCard {
            Text(stringResource(R.string.routing_rule_target), style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary)
            val types = listOf(RoutingRule.TARGET_PROXY, RoutingRule.TARGET_DIRECT, RoutingRule.TARGET_BLOCK)
            SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                types.forEachIndexed { index, value ->
                    SegmentedButton(
                        shape = SegmentedButtonDefaults.itemShape(index = index, count = types.size),
                        onClick = { targetType = value },
                        selected = targetType == value,
                    ) {
                        Text(
                            when (value) {
                                RoutingRule.TARGET_DIRECT -> stringResource(R.string.routing_rule_target_direct)
                                RoutingRule.TARGET_BLOCK -> stringResource(R.string.routing_rule_target_block)
                                else -> stringResource(R.string.routing_rule_target_proxy)
                            },
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }
            }
            if (targetType == RoutingRule.TARGET_PROXY) {
                Column {
                    OutlinedTextField(
                        value = outbound,
                        onValueChange = { outbound = it },
                        label = { Text(stringResource(R.string.routing_rule_outbound)) },
                        singleLine = true,
                        trailingIcon = {
                            IconButton(onClick = { targetMenuExpanded = true }) {
                                Icon(Icons.Outlined.ArrowDropDown, contentDescription = null)
                            }
                        },
                        supportingText = {
                            val current = targets
                            Text(
                                when {
                                    current == null -> stringResource(R.string.routing_rule_no_targets)
                                    current.names.isEmpty() -> stringResource(R.string.routing_rule_no_targets)
                                    else -> stringResource(R.string.routing_rule_targets_of, current.profileName)
                                },
                            )
                        },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    DropdownMenu(expanded = targetMenuExpanded, onDismissRequest = { targetMenuExpanded = false }) {
                        val names = targets?.names.orEmpty()
                        if (names.isEmpty()) {
                            DropdownMenuItem(text = { Text(stringResource(R.string.routing_rule_no_targets)) }, onClick = { targetMenuExpanded = false }, enabled = false)
                        }
                        names.forEach { name ->
                            DropdownMenuItem(
                                text = { Text(name, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                                onClick = {
                                    outbound = name
                                    targetMenuExpanded = false
                                },
                            )
                        }
                    }
                }
            }
        }
    }

    errorMessage?.let { message ->
        AlertDialog(
            onDismissRequest = { errorMessage = null },
            confirmButton = { TextButton(onClick = { errorMessage = null }) { Text(stringResource(R.string.ok)) } },
            text = { Text(message) },
        )
    }

    if (showDeleteDialog) {
        AlertDialog(
            onDismissRequest = { showDeleteDialog = false },
            confirmButton = {
                TextButton(onClick = {
                    showDeleteDialog = false
                    delete()
                }) { Text(stringResource(R.string.menu_delete)) }
            },
            dismissButton = { TextButton(onClick = { showDeleteDialog = false }) { Text(stringResource(R.string.cancel)) } },
            text = { Text(stringResource(R.string.routing_rule_delete_confirm)) },
        )
    }

    if (showAppPicker) {
        AppPickerDialog(
            selected = RoutingRules.splitEntries(packages).toSet(),
            onDismiss = { showAppPicker = false },
            onConfirm = { chosen ->
                packages = chosen.joinToString("\n")
                showAppPicker = false
            },
        )
    }
}

@Composable
private fun SectionCard(content: @Composable () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f)),
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            content()
        }
    }
}

/** Picks package names from the installed apps (user apps first). */
@Composable
private fun AppPickerDialog(selected: Set<String>, onDismiss: () -> Unit, onConfirm: (List<String>) -> Unit) {
    val context = LocalContext.current
    var apps by remember { mutableStateOf<List<InstalledApp>?>(null) }
    var chosen by remember { mutableStateOf(selected) }
    var query by remember { mutableStateOf("") }

    LaunchedEffect(Unit) {
        apps = withContext(Dispatchers.IO) {
            val packageManager = context.packageManager
            runCatching {
                packageManager.getInstalledApplications(0)
                    .filter { it.packageName != context.packageName }
                    .sortedWith(compareBy<ApplicationInfo> { (it.flags and ApplicationInfo.FLAG_SYSTEM) != 0 })
                    .map { InstalledApp(it.loadLabel(packageManager).toString(), it.packageName) }
            }.getOrDefault(emptyList())
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.routing_rule_apps_select)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it },
                    label = { Text(stringResource(R.string.routing_rule_apps_search)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                val list = apps
                if (list == null) {
                    CircularProgressIndicator(modifier = Modifier.padding(16.dp))
                } else {
                    // Chosen packages that are not installed stay selectable.
                    val missing = chosen.filter { name -> list.none { it.packageName == name } }.map { InstalledApp(it, it) }
                    val filtered = (missing + list).filter {
                        query.isBlank() || it.label.contains(query, ignoreCase = true) || it.packageName.contains(query, ignoreCase = true)
                    }
                    LazyColumn(modifier = Modifier.heightIn(max = 400.dp)) {
                        items(filtered, key = { it.packageName }) { app ->
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable {
                                        chosen = if (app.packageName in chosen) chosen - app.packageName else chosen + app.packageName
                                    },
                            ) {
                                Checkbox(
                                    checked = app.packageName in chosen,
                                    onCheckedChange = { checked ->
                                        chosen = if (checked) chosen + app.packageName else chosen - app.packageName
                                    },
                                )
                                Column {
                                    Text(app.label, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                    Text(
                                        app.packageName,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                    )
                                }
                            }
                        }
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = { onConfirm(chosen.sorted()) }) { Text(stringResource(R.string.ok)) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}
