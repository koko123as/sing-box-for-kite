package io.nekohasekai.sfa.compose.screen.routing

import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.CloudDownload
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.KeyboardArrowDown
import androidx.compose.material.icons.outlined.KeyboardArrowUp
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import io.nekohasekai.sfa.R
import io.nekohasekai.sfa.bg.GeoData
import io.nekohasekai.sfa.compose.base.UiEvent
import io.nekohasekai.sfa.compose.base.rememberApplyServiceChangeNotifier
import io.nekohasekai.sfa.compose.topbar.LocalScaffoldPadding
import io.nekohasekai.sfa.compose.topbar.OverrideTopBar
import io.nekohasekai.sfa.constant.Status
import io.nekohasekai.sfa.database.RoutingRule
import io.nekohasekai.sfa.database.RoutingRules
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** The user's routing rules, in the order they are applied (v2rayNG-style routing settings). */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RoutingRulesScreen(navController: NavController, serviceStatus: Status = Status.Stopped) {
    OverrideTopBar {
        TopAppBar(
            title = { Text(stringResource(R.string.routing_rules)) },
            navigationIcon = {
                IconButton(onClick = { navController.navigateUp() }) {
                    Icon(
                        imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                        contentDescription = stringResource(R.string.content_description_back),
                    )
                }
            },
            actions = {
                IconButton(onClick = { navController.navigate("settings/routing/edit/new") }) {
                    Icon(
                        imageVector = Icons.Outlined.Add,
                        contentDescription = stringResource(R.string.routing_rule_add),
                    )
                }
            },
        )
    }

    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val notifyApplyChange = rememberApplyServiceChangeNotifier(serviceStatus)
    var rules by remember { mutableStateOf<List<RoutingRule>>(emptyList()) }
    var updatingGeo by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        rules = withContext(Dispatchers.IO) { RoutingRules.load() }
    }

    fun persist(updated: List<RoutingRule>) {
        rules = updated
        scope.launch(Dispatchers.IO) {
            RoutingRules.save(updated)
            withContext(Dispatchers.Main) {
                notifyApplyChange(UiEvent.ApplyServiceChange.Mode.Reload)
            }
        }
    }

    fun move(index: Int, offset: Int) {
        val target = index + offset
        if (target !in rules.indices) return
        val updated = rules.toMutableList()
        val item = updated.removeAt(index)
        updated.add(target, item)
        persist(updated)
    }

    val scaffoldPadding = LocalScaffoldPadding.current
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.surface),
        contentPadding = PaddingValues(
            top = scaffoldPadding.calculateTopPadding() + 8.dp,
            bottom = scaffoldPadding.calculateBottomPadding() + 16.dp,
            start = 16.dp,
            end = 16.dp,
        ),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
            ) {
                Row(modifier = Modifier.padding(16.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    Icon(Icons.Outlined.Info, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                    Text(
                        text = stringResource(R.string.routing_rules_note),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
            ) {
                ListItem(
                    headlineContent = { Text(stringResource(R.string.geo_data_update)) },
                    supportingContent = { Text(stringResource(R.string.geo_data_update_summary)) },
                    leadingContent = {
                        Icon(Icons.Outlined.CloudDownload, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                    },
                    trailingContent = {
                        if (updatingGeo) CircularProgressIndicator(modifier = Modifier.size(24.dp), strokeWidth = 2.dp)
                    },
                    modifier = Modifier.clickable(enabled = !updatingGeo) {
                        updatingGeo = true
                        scope.launch {
                            val error = withContext(Dispatchers.IO) {
                                runCatching { GeoData.resources.forEach { GeoData.update(it) } }.exceptionOrNull()
                            }
                            updatingGeo = false
                            val message = if (error == null) {
                                context.getString(R.string.geo_data_updated)
                            } else {
                                context.getString(R.string.geo_data_update_failed, error.message ?: error.toString())
                            }
                            Toast.makeText(context, message, Toast.LENGTH_LONG).show()
                        }
                    },
                    colors = ListItemDefaults.colors(containerColor = Color.Transparent),
                )
            }
        }
        if (rules.isEmpty()) {
            item {
                Text(
                    text = stringResource(R.string.routing_rules_empty),
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(16.dp),
                )
            }
        }
        itemsIndexed(rules, key = { _, rule -> rule.id }) { index, rule ->
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
            ) {
                ListItem(
                    headlineContent = {
                        Text(
                            rule.remarks.ifBlank { stringResource(R.string.routing_rule_untitled) },
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    },
                    supportingContent = {
                        Column {
                            Text(targetLabel(rule), color = MaterialTheme.colorScheme.primary, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            Text(
                                stringResource(R.string.routing_rule_summary_counts, rule.domain.size, rule.ip.size, rule.packages.size),
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                    },
                    trailingContent = {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            IconButton(onClick = { move(index, -1) }, enabled = index > 0) {
                                Icon(Icons.Outlined.KeyboardArrowUp, contentDescription = stringResource(R.string.routing_rule_move_up))
                            }
                            IconButton(onClick = { move(index, 1) }, enabled = index < rules.lastIndex) {
                                Icon(Icons.Outlined.KeyboardArrowDown, contentDescription = stringResource(R.string.routing_rule_move_down))
                            }
                            Switch(
                                checked = rule.enabled,
                                onCheckedChange = { checked ->
                                    persist(rules.map { if (it.id == rule.id) it.copy(enabled = checked) else it })
                                },
                            )
                        }
                    },
                    modifier = Modifier.clickable { navController.navigate("settings/routing/edit/${rule.id}") },
                    colors = ListItemDefaults.colors(containerColor = Color.Transparent),
                )
            }
        }
    }
}

@Composable
private fun targetLabel(rule: RoutingRule): String = when (rule.targetType) {
    RoutingRule.TARGET_DIRECT -> stringResource(R.string.routing_rule_target_direct)
    RoutingRule.TARGET_BLOCK -> stringResource(R.string.routing_rule_target_block)
    else -> "→ " + rule.outbound
}
