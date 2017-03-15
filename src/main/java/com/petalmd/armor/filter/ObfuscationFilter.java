package com.petalmd.armor.filter;

import com.petalmd.armor.audit.AuditListener;
import com.petalmd.armor.authentication.backend.AuthenticationBackend;
import com.petalmd.armor.authorization.Authorizator;
import com.petalmd.armor.filter.obfuscation.ObfFilterFactory;
import com.petalmd.armor.service.ArmorConfigService;
import com.petalmd.armor.util.ConfigConstants;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.ClusterService;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.tasks.Task;

import java.util.Map;

/**
 * Created by bdiasse on 10/03/17.
 */
public class ObfuscationFilter extends AbstractActionFilter {


    protected final ESLogger log = Loggers.getLogger(ObfuscationFilter.class);
    private final boolean enabled;

    @Inject
    public ObfuscationFilter(final Settings settings, final AuthenticationBackend backend, final Authorizator authorizator,
                             final ClusterService clusterService, final ArmorConfigService armorConfigService, final AuditListener auditListener) {
        super(settings, backend, authorizator, clusterService, armorConfigService, auditListener);
        enabled = settings.getAsBoolean(ConfigConstants.ARMOR_OBFUSCATION_FILTER_ENABLED, false);
        log.info("ObfuscationFilter is " + (enabled?"enabled":"disabled"));
    }


    public void applySecure(Task task, final String action, final ActionRequest request, final ActionListener listener, final ActionFilterChain chain) {
        if (!enabled) {
            chain.proceed(task, action, request, listener);
            return;
        }

        ObfFilterFactory factory = ObfFilterFactory.getObfFilterFactory();

        if (factory.canObfuscate(action)){
            chain.proceed(task, action, request, new ObfuscatedActionListener<ActionResponse>(listener,action));
        } else {
            chain.proceed(task, action, request, listener);
        }
    }

    public class ObfuscatedActionListener<Response extends ActionResponse> implements ActionListener<Response> {

        private final ActionListener<Response> privListener;
        private final String action;

        public ObfuscatedActionListener(final ActionListener<Response> privListener, final String action) {
            this.privListener = privListener;
            this.action = action;
        }

        @Override
        public void onResponse(Response response) {
            final ObfFilterFactory factory = ObfFilterFactory.getObfFilterFactory();
            Response obfResp = (Response)factory.getObfResponse(action,response);
            privListener.onResponse(obfResp);
        }

        @Override
        public void onFailure(Throwable e) {
            privListener.onFailure(e);
        }

    }

}
