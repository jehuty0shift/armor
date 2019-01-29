package com.petalmd.armor.filter;

import com.petalmd.armor.service.ArmorConfigService;
import com.petalmd.armor.service.ArmorService;
import com.petalmd.armor.util.ConfigConstants;
import com.petalmd.armor.util.SecurityUtil;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;
import org.elasticsearch.ElasticsearchTimeoutException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoResponse;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.ReceiveTimeoutTransportException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * Created by bdiasse on 09/03/17.
 */
public class ActionCacheFilter extends AbstractActionFilter {


    protected final Logger log = LogManager.getLogger(ActionCacheFilter.class);
    private final boolean enabled;
    private final List<String> cacheablesActions = new ArrayList<>();
    private final Map<String, ActionResponse> actionsCache;

    private static final  int CACHE_TIMEOUT_SECONDS = 10;


    @Inject
    public ActionCacheFilter(final Settings settings, final ClusterService clusterService, final ThreadPool threadPool, final ArmorService armorService, final ArmorConfigService armorConfigService) {
        super(settings, armorService.getAuthenticationBackend(),armorService.getAuthorizator(), clusterService, armorService, armorConfigService, armorService.getAuditListener(),threadPool);
        enabled = settings.getAsBoolean(ConfigConstants.ARMOR_ACTION_CACHE_ENABLED, false);
        log.info("Action Cache Filter is : " + (enabled?"enabled":"disabled"));
        List<String> actionsToCache = settings.getAsList(ConfigConstants.ARMOR_ACTION_CACHE_LIST);
        for (final String action : actionsToCache) {
            if (action.startsWith("cluster:monitor")) {
                cacheablesActions.add(action);
                log.info("Adding action " + action + " to cacheables actions");
            }
        }
        actionsCache = new HashMap<>(cacheablesActions.size());
    }


    @Override
    public void applySecure(Task task, final String action, final ActionRequest request, final ActionListener listener, final ActionFilterChain chain) {
        if (!enabled) {
            chain.proceed(task, action, request, listener);
            return;
        }
        log.debug("evaluating action " + action);
        for (final String cacheableAction : cacheablesActions) {
            log.debug("comparing "  + action + " with " + cacheableAction);
            if (SecurityUtil.isWildcardMatch(action, cacheableAction, false)) {
                log.debug("action " + action + " is cacheable due to " + cacheableAction);
                final boolean isCached = actionsCache.containsKey(cacheableAction);
                if (request instanceof NodesInfoRequest) {
                    NodesInfoRequest niRequest = (NodesInfoRequest) request;
                    if (isCached && (niRequest.timeout() == null || niRequest.timeout().getSeconds() > CACHE_TIMEOUT_SECONDS)) {
                        niRequest.timeout(TimeValue.timeValueSeconds(CACHE_TIMEOUT_SECONDS));
                    }
                    chain.proceed(task,action,request, new CachedActionListener<NodesInfoResponse>(listener,actionsCache,action));
                    return;
                }
            }
        }

        chain.proceed(task, action, request, listener);
    }


    public class CachedActionListener<Response extends ActionResponse>  implements ActionListener<Response> {

        private ActionListener<Response> privListener;
        private Map<String,ActionResponse> cacheMap;
        private String action;

        public CachedActionListener(final ActionListener<Response> privListener,final Map<String,ActionResponse> cacheMap, String action) {
            this.privListener = privListener;
            this.cacheMap = cacheMap;
            this.action = action;
        }

        @Override
        public void onResponse(Response response) {
            cacheMap.put(action, response);
            log.trace("Cached new Response for " + action);
            privListener.onResponse(response);
        }

        @Override
        public void onFailure(Exception e) {
            if (e instanceof ElasticsearchTimeoutException || e instanceof ReceiveTimeoutTransportException) {
                if (cacheMap.containsKey(action)) {
                    log.debug("Request for action " + action + " has timeouted, returning cached value");
                    privListener.onResponse((Response)cacheMap.get(action));
                    return;
                }
            }
            privListener.onFailure(e);
        }

    }

}