package com.petalmd.armor.filter;

import com.petalmd.armor.audit.AuditListener;
import com.petalmd.armor.authentication.backend.AuthenticationBackend;
import com.petalmd.armor.authorization.Authorizator;
import com.petalmd.armor.service.ArmorConfigService;
import com.petalmd.armor.util.ConfigConstants;
import com.petalmd.armor.util.SecurityUtil;
import org.elasticsearch.ElasticsearchTimeoutException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoResponse;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.ClusterService;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.transport.ReceiveTimeoutTransportException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * Created by bdiasse on 09/03/17.
 */
public class ActionCacheFilter extends AbstractActionFilter {


    protected final ESLogger log = Loggers.getLogger(ActionCacheFilter.class);
    private final boolean enabled;
    private final List<String> cacheablesActions = new ArrayList<>();
    private final Map<String, ActionResponse> actionsCache;
    private final Client client;

    private static final  int CACHE_TIMEOUT_SECONDS = 5;


    @Inject
    public ActionCacheFilter(final Settings settings, final AuthenticationBackend backend, final Authorizator authorizator,
                             final ClusterService clusterService, final ArmorConfigService armorConfigService, final AuditListener auditListener, final Client client) {
        super(settings, backend, authorizator, clusterService, armorConfigService, auditListener);
        enabled = settings.getAsBoolean(ConfigConstants.ARMOR_ACTION_CACHE_ENABLED, false);
        log.info("Action Cache Filter is : " + (enabled?"enabled":"disabled"));
        this.client = client;
        String[] actionsToCache = settings.getAsArray(ConfigConstants.ARMOR_ACTION_CACHE_LIST);
        for (String action : actionsToCache) {
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
                    if (isCached && niRequest.timeout() == null) {
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
        public void onFailure(Throwable e) {
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