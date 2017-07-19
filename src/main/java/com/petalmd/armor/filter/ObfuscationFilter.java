/*
 * Copyright 2017 PetalMD.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
 * @author jehuty0shift
 * Created by jehuty0shift on 10/03/17.
 */
public class ObfuscationFilter extends AbstractActionFilter {


    protected final ESLogger log = Loggers.getLogger(ObfuscationFilter.class);
    private final boolean enabled;
    ObfFilterFactory factory;

    @Inject
    public ObfuscationFilter(final Settings settings, final AuthenticationBackend backend, final Authorizator authorizator,
                             final ClusterService clusterService, final ArmorConfigService armorConfigService, final AuditListener auditListener) {
        super(settings, backend, authorizator, clusterService, armorConfigService, auditListener);
        enabled = settings.getAsBoolean(ConfigConstants.ARMOR_OBFUSCATION_FILTER_ENABLED, false);
        if(enabled) {
            factory = new ObfFilterFactory(settings);
        }
        log.info("ObfuscationFilter is " + (enabled?"enabled":"disabled"));
    }


    public void applySecure(Task task, final String action, final ActionRequest request, final ActionListener listener, final ActionFilterChain chain) {
        if (!enabled) {
            chain.proceed(task, action, request, listener);
            return;
        }


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
            Response obfResp = (Response)factory.getObfResponse(action,response);
            if(obfResp == null) {
                privListener.onFailure(new IllegalStateException("Obfuscated Response is null"));
                return;
            }
            privListener.onResponse(obfResp);
        }

        @Override
        public void onFailure(Throwable e) {
            privListener.onFailure(e);
        }

    }

}
