package com.petalmd.armor.filter;

import com.petalmd.armor.authorization.ForbiddenException;
import com.petalmd.armor.service.ArmorConfigService;
import com.petalmd.armor.service.ArmorService;
import com.petalmd.armor.util.ConfigConstants;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.fieldcaps.FieldCapabilitiesAction;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.index.IndexNotFoundException;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;

/**
 * Created by jehuty0shift on 24/10/18.
 */
public class KibanaHelperFilter extends AbstractActionFilter {

    protected final Logger log = LogManager.getLogger(KibanaHelperFilter.class);
    private final boolean enabled;

    public KibanaHelperFilter(final Settings settings, final ClusterService clusterService, final ThreadPool threadPool, final ArmorService armorService, final ArmorConfigService armorConfigService) {
        super(settings, armorService.getAuthenticationBackend(), armorService.getAuthorizator(), clusterService, armorService, armorConfigService, armorService.getAuditListener(), threadPool);
        enabled = settings.getAsBoolean(ConfigConstants.ARMOR_KIBANA_HELPER_ENABLED,true);
        log.info("Kibana Helper Filter is {}", enabled?"enabled":"disabled");
    }

    public void applySecure(Task task, final String action, final ActionRequest request, final ActionListener listener, final ActionFilterChain chain) {
        if (!enabled) {
            chain.proceed(task, action, request, listener);
            return;
        }
        if (action.equals(FieldCapabilitiesAction.NAME)) {
            chain.proceed(task, action, request, new KibanaHelperActionListener(listener, action));
        } else {
            chain.proceed(task, action, request, listener);
        }

    }


    private class KibanaHelperActionListener<Response extends ActionResponse> implements ActionListener<Response> {

        private final ActionListener<Response> privListener;
        private final String action;

        public KibanaHelperActionListener(final ActionListener<Response> privListener, final String action) {
            this.privListener = privListener;
            this.action = action;
        }

        @Override
        public void onResponse(Response response) {
            privListener.onResponse(response);
        }

        @Override
        public void onFailure(Exception e) {
            //Handle only fieldCaps for now
            if(action.equals(FieldCapabilitiesAction.NAME)) {
                if (e instanceof ForbiddenException) {
                    String indexName = ((ForbiddenException) e).getIndex() != null?((ForbiddenException) e).getIndex().getName():"unknown";
                    privListener.onFailure(new IndexNotFoundException(indexName));
                    return;
                }
            }
            privListener.onFailure(e);
        }
    }

}
