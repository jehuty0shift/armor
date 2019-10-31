package com.petalmd.armor.filter;

import com.google.common.collect.ImmutableList;
import com.petalmd.armor.filter.kefla.*;
import com.petalmd.armor.service.ArmorConfigService;
import com.petalmd.armor.service.ArmorService;
import com.petalmd.armor.util.ArmorConstants;
import com.petalmd.armor.util.ConfigConstants;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.admin.indices.mapping.get.GetFieldMappingsAction;
import org.elasticsearch.action.admin.indices.mapping.get.GetMappingsAction;
import org.elasticsearch.action.fieldcaps.FieldCapabilitiesAction;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.cluster.metadata.AliasOrIndex;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.compress.CompressedXContent;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;

import java.util.*;

/**
 * Created by jehuty0shift on 11/10/19.
 */
public class KeflaFilter extends AbstractActionFilter {

    private static final Logger log = LogManager.getLogger(KeflaFilter.class);
    private boolean enabled;
    private final String graylogEndpoint;
    private final KeflaEngine kEngine;
    public final List<String> actions = ImmutableList.of(
            GetMappingsAction.NAME,
            FieldCapabilitiesAction.NAME,
            GetFieldMappingsAction.NAME
    );

    public final KeflaResponseFactory keflaResponseFactory;

    public KeflaFilter(final Settings settings, final KeflaEngine kEngine, final ArmorService armorService, final ArmorConfigService armorConfigService, final ClusterService clusterService, final ThreadPool threadPool) {
        super(settings, armorService.getAuthenticationBackend(), armorService.getAuthorizator(), clusterService, armorService, armorConfigService, armorService.getAuditListener(), threadPool);
        this.enabled = settings.getAsBoolean(ConfigConstants.ARMOR_KEFLA_FILTER_ENABLED, false);
        graylogEndpoint = settings.get(ConfigConstants.ARMOR_KEFLA_PLUGIN_ENDPOINT, "");
        if (graylogEndpoint.isBlank()) {
            log.error("Graylog Endpoint has not been configured, deactivating Kefla");
            enabled = false;
        }
        this.kEngine = kEngine;
        log.info("Kefla filter is {}enabled", enabled ? "" : "not ");
        keflaResponseFactory = new KeflaResponseFactory();
    }

    @Override
    public int order() {
        return Integer.MIN_VALUE + 9;
    }

    @Override
    public void applySecure(Task task, String action, ActionRequest request, ActionListener listener, ActionFilterChain chain) {
        if (!enabled) {
            log.trace("Kefla Filter not enabled, will proceed");
            chain.proceed(task, action, request, listener);
            return;
        }

        log.debug("kefla will analyze aliases and actions");
        Optional<String> actionToFilter = actions.stream().filter(k -> action.equals(k)).findAny();
        if (!actionToFilter.isPresent()) {
            log.trace("action {} does not ask filter, will proceed", action);
            chain.proceed(task, action, request, listener);
            return;
        }
        log.debug("We will filter action {}, because it matches action {}", action, actionToFilter.get());

        // retrieve aliases from ThreadContext
        List<String> aliases = threadpool.getThreadContext().getTransient(ArmorConstants.ARMOR_KEFLA_ALIASES);

        if (aliases.isEmpty()) {
            log.debug("aliases is empty, will proceed");
            chain.proceed(task, action, request, listener);
            return;
        }

        // retrieve filter from aliases
        Set<String> streamIds = new HashSet<>();
        SortedMap<String, AliasOrIndex> aliasMap = clusterService.state().metaData().getAliasAndIndexLookup();
        for (String alias : aliases) {
            AliasOrIndex alOrInd = aliasMap.get(alias);
            if (alOrInd == null) {
                log.warn("this alias {} is null, maybe it has been deleted", alias);
                continue;
            }
            CompressedXContent filter = alOrInd.getIndices().get(0).getAliases().get(alias).filter();
            streamIds.addAll(KeflaUtils.streamFromFilters(filter));
        }


        // retrieve mapping from Graylog or from Cache
        Map<String, Map<String, Map<String, KeflaRestType>>> strIndFieldsMap = kEngine.getFieldsForStream(streamIds);
        log.debug("retrieved {} stream mappings", strIndFieldsMap.size());
        // install Listeners according to action and mappings
        ActionListener keflaListener = new KeflaFilterListener(action, listener, strIndFieldsMap);
        log.debug("listener created");
        //proceed with caution
        chain.proceed(task, action, request, keflaListener);

    }

    public class KeflaFilterListener<Response extends ActionResponse> implements ActionListener<Response> {

        public final String action;
        public final ActionListener<Response> origListener;
        public final Map<String, Map<String, Map<String, KeflaRestType>>> streamIndexMap;

        public KeflaFilterListener(String action, ActionListener<Response> listener, Map<String, Map<String, Map<String, KeflaRestType>>> streamIndexFieldsMap) {
            this.action = action;
            this.origListener = listener;
            this.streamIndexMap = streamIndexFieldsMap;
        }

        @Override
        public void onResponse(Response response) {
            Response newResponse = (Response) keflaResponseFactory.getResponse(action, response, streamIndexMap);
            if (newResponse == null) {
                origListener.onFailure(new ElasticsearchException("Response has not been contextualized for action {}",action));
            } else {
                log.debug("response is contextualized {}",newResponse.toString());
                origListener.onResponse(newResponse);
            }
        }

        @Override
        public void onFailure(Exception e) {
            origListener.onFailure(e);
        }
    }

}
