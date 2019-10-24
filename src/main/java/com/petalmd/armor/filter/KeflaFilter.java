package com.petalmd.armor.filter;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.petalmd.armor.service.ArmorConfigService;
import com.petalmd.armor.service.ArmorService;
import com.petalmd.armor.util.ArmorConstants;
import com.petalmd.armor.util.ConfigConstants;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.admin.indices.mapping.get.GetFieldMappingsAction;
import org.elasticsearch.action.admin.indices.mapping.get.GetMappingsAction;
import org.elasticsearch.action.fieldcaps.FieldCapabilitiesAction;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.cluster.metadata.AliasOrIndex;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.SortedMap;

/**
 * Created by jehuty0shift on 11/10/19.
 */
public class KeflaFilter extends AbstractActionFilter {

    private static final Logger log = LogManager.getLogger(KeflaFilter.class);
    private boolean enabled;
    private final String graylogEndpoint;
    public final List<String> actions = ImmutableList.of(
            GetMappingsAction.NAME,
            FieldCapabilitiesAction.NAME,
            GetFieldMappingsAction.NAME
    );

    public KeflaFilter(final Settings settings, final ArmorService armorService, final ArmorConfigService armorConfigService, final ClusterService clusterService, final ThreadPool threadPool) {
        super(settings, armorService.getAuthenticationBackend(), armorService.getAuthorizator(), clusterService, armorService, armorConfigService, armorService.getAuditListener(), threadPool);
        this.enabled = settings.getAsBoolean(ConfigConstants.ARMOR_KEFLA_FILTER_ENABLED, false);
        graylogEndpoint = settings.get(ConfigConstants.ARMOR_KEFLA_PLUGIN_ENDPOINT, "");
        if (graylogEndpoint.isBlank()) {
            log.error("Graylog Endpoint has not been configured, deactivating Kefla");
            enabled = false;
        }
        log.info("Kefla filter is {}enabled", enabled ? "" : "not ");
    }

    @Override
    public void applySecure(Task task, String action, ActionRequest request, ActionListener listener, ActionFilterChain chain) {
        if (!enabled) {
            log.trace("Kefla Filter not enabled, will proceed");
            chain.proceed(task, action, request, listener);
            return;
        }

        log.debug("kefla will analyze aliases and actions");
        Optional<String> actionToFilter = actions.stream().filter(k -> action.startsWith(k)).findAny();
        if(!actionToFilter.isPresent()) {
            log.trace("action {} does not ask filter, will proceed", action);
            chain.proceed(task,action,request,listener);
            return;
        }
        log.debug("We will filter action {}, because it matches action {}",action, actionToFilter.get());

        // retrieve aliases from ThreadContext
        List<String> aliases = threadpool.getThreadContext().getTransient(ArmorConstants.ARMOR_KEFLA_ALIASES);

        if(aliases.isEmpty()) {
            log.debug("aliases is empty, will proceed");
            chain.proceed(task, action, request, listener);
            return;
        }

        // retrieve filter from aliases
        SortedMap<String, AliasOrIndex> aliasMap = clusterService.state().metaData().getAliasAndIndexLookup();

        // retrieve mapping from Graylog or from Cache


        // install Listener according to action and mappings
            // listener should fuse mapping from most recent to less recent
            // should keep GRAYLOG_FIELDS and remove _id.


        //proceed with caution


    }
}
