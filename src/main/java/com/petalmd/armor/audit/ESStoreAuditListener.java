/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
 * Copyright 2015 PetalMD
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package com.petalmd.armor.audit;

import com.petalmd.armor.util.ArmorConstants;
import com.petalmd.armor.util.ConfigConstants;
import com.petalmd.armor.util.SecurityUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.admin.indices.create.CreateIndexAction;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequestBuilder;
import org.elasticsearch.action.admin.indices.create.CreateIndexResponse;
import org.elasticsearch.action.admin.indices.exists.indices.IndicesExistsAction;
import org.elasticsearch.action.admin.indices.exists.indices.IndicesExistsRequest;
import org.elasticsearch.action.admin.indices.exists.indices.IndicesExistsResponse;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.json.JsonXContent;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.transport.TransportRequest;

import java.io.IOException;
import java.net.UnknownHostException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

public class ESStoreAuditListener implements AuditListener {

    private final Client client;
    private final Settings settings;
    private final String securityConfigurationIndex;
    protected final Logger log = LogManager.getLogger(this.getClass());

    private static final String AUDIT_USER = "audit_user";
    private static final String AUDIT_DATE = "audit_date";
    private static final String AUDIT_DETAILS_REST = "audit_details_rest";
    private static final String AUDIT_DETAILS_CLASS = "audit_details_class";
    private static final String AUDIT_IP = "audit_ip";
    private static final String AUDIT_MESSAGE = "audit_message";
    private static final AtomicBoolean auditIndexCreated = new AtomicBoolean(false);

    @Inject
    public ESStoreAuditListener(final Client client, final Settings settings) {
        super();
        this.client = client;
        this.settings = settings;

        securityConfigurationIndex = settings.get(ConfigConstants.ARMOR_CONFIG_INDEX_NAME + "_audit",
                ConfigConstants.DEFAULT_SECURITY_CONFIG_INDEX + "_audit");

    }

    @Override
    public void onFailedLogin(final String username, final RestRequest request, final ThreadContext threadContext) {

        final AuditMessage msg = new AuditMessage(username, "failed_login", request, settings);
        index(msg, threadContext);

    }

    @Override
    public void onMissingPrivileges(final String username, final RestRequest request, final ThreadContext threadContext) {

        final AuditMessage msg = new AuditMessage(username, "missing_privileges", request, threadContext);
        index(msg, threadContext);

    }

    @Override
    public void onFailedLogin(final String username, final TransportRequest request, ThreadContext threadContext) {

        final AuditMessage msg = new AuditMessage(username, "failed_login", request, threadContext);
        index(msg, threadContext);

    }

    @Override
    public void onMissingPrivileges(final String username, final TransportRequest request, final ThreadContext threadContext) {

        final AuditMessage msg = new AuditMessage(username, "missing_privileges", request, threadContext);
        index(msg, threadContext);

    }

    protected void index(final AuditMessage msg, ThreadContext threadContext) {
        AtomicBoolean isRequestExternal = threadContext.getTransient(ArmorConstants.ARMOR_REQUEST_IS_EXTERNAL);
        if (isRequestExternal != null) {
            isRequestExternal.set(false);
        } else {
            threadContext.putTransient(ArmorConstants.ARMOR_REQUEST_IS_EXTERNAL, new AtomicBoolean(false));
        }
        try {

            if (auditIndexCreated.get()) {
                client.prepareIndex(securityConfigurationIndex, "records").setSource(msg.auditInfo).execute(new ActionListener<IndexResponse>() {

                    @Override
                    public void onResponse(final IndexResponse response) {
                        log.trace("write audit message {}", msg);

                    }

                    @Override
                    public void onFailure(final Exception e) {
                        log.error("Unable to write audit log due to {}", e, e.toString());
                    }
                });
            }
        } finally {
            if (isRequestExternal != null) {
                isRequestExternal.set(true);
            }
        }
    }


    @Override
    public boolean isReady() {
        return auditIndexCreated.get();
    }

    @Override
    public boolean setupAuditListener() {

        if (!auditIndexCreated.get()) {
            try {
                log.info("Checking if the audit index exists");
                IndicesExistsResponse resp = client.execute(IndicesExistsAction.INSTANCE, new IndicesExistsRequest(securityConfigurationIndex)).actionGet(TimeValue.timeValueSeconds(10));

                if (resp != null) {
                    if (!resp.isExists()) {
                        log.info("Audit index does not exists, creating it !");
                        final int numOfReplicas = settings.getAsInt(ConfigConstants.ARMOR_AUDITLOG_NUM_REPLICAS, 1);
                        final String compression = settings.get(ConfigConstants.ARMOR_AUDITLOG_COMPRESSION, "best_compression");
                        try {
                            CreateIndexRequestBuilder criBuilder = new CreateIndexRequestBuilder(client, CreateIndexAction.INSTANCE, securityConfigurationIndex);
                            XContentBuilder mappingBuilder = JsonXContent.contentBuilder();
                            mappingBuilder.startObject()
                                    .startObject("properties")
                                    .startObject(AUDIT_USER)
                                    .field("type", "keyword")
                                    .endObject()
                                    .startObject(AUDIT_MESSAGE)
                                    .field("type", "keyword")
                                    .endObject()
                                    .startObject(AUDIT_DATE)
                                    .field("type", "date")
                                    .endObject()
                                    .startObject(AUDIT_DETAILS_CLASS)
                                    .field("type", "keyword")
                                    .endObject()
                                    //ADD Audit item
                                    .startObject(AUDIT_ITEMS)
                                    .field("type", "keyword")
                                    .endObject()
                                    //ADD First Item to Fail
                                    .startObject(AUDIT_DETAILS_REST)
                                    .field("type", "keyword")
                                    .endObject()
                                    .startObject(AUDIT_IP)
                                    .field("type", "ip")
                                    .endObject()
                                    .endObject()
                                    .endObject();
                            final Settings auditIndexSettings = Settings.builder()
                                    .put("index.number_of_shards", 1)
                                    .put("index.number_of_replicas", numOfReplicas)
                                    //should take as little space than possible
                                    .put("index.codec", compression)
                                    .build();

                            criBuilder.setSettings(auditIndexSettings);
                            criBuilder.addMapping("records", mappingBuilder);
                            criBuilder.setTimeout(TimeValue.timeValueMinutes(1));
                            criBuilder.execute(new ActionListener<CreateIndexResponse>() {
                                @Override
                                public void onResponse(CreateIndexResponse createIndexResponse) {

                                    if (createIndexResponse.isAcknowledged()) {
                                        auditIndexCreated.set(true);
                                        log.info("the security audit index {} has been created", securityConfigurationIndex);
                                    } else {
                                        log.warn("the security audit index {} has not been created, Check if it has been created by another node", securityConfigurationIndex);
                                    }
                                }

                                @Override
                                public void onFailure(Exception e) {
                                    log.warn("the security audit index {} has not been created due to {}", securityConfigurationIndex, e);
                                }
                            });


                        } catch (IOException e) {
                            log.error("creation of audit index failed due to IOException", e);
                        }
                    } else {
                        log.warn("the audit index does exist");
                        auditIndexCreated.set(true);
                    }
                }
            } catch (RuntimeException e) {
                log.error("unexpected error during Audit Index Creation ", e);
            }
        }
        return auditIndexCreated.get();
    }

    private static class AuditMessage {
        final Map<String, Object> auditInfo = new HashMap<String, Object>();

        private AuditMessage(final String username, final String message, final TransportRequest request, final ThreadContext threadContext) {
            auditInfo.put("audit_user", username);
            auditInfo.put("audit_message", message);
            auditInfo.put("audit_date", LocalDateTime.now().format(DateTimeFormatter.ISO_DATE_TIME));
            //TODO add first failing item
            if (threadContext.getTransient(AUDIT_ITEMS) != null) {
                List<String> failingItems = threadContext.getTransient(AUDIT_ITEMS);
                auditInfo.put(AUDIT_ITEMS, failingItems);
            }
            //auditInfo.put("audit_details_context", String.valueOf(request.getContext()));
            //auditInfo.put("audit_details_headers", String.valueOf(request.getHeaders()));
            auditInfo.put("audit_details_class", request.getClass().toString());
            final String ip = String.valueOf(request.remoteAddress());
            if (!"null".equals(ip)) {
                auditInfo.put("audit_ip", ip);
            }
        }

        private AuditMessage(final String username, final String message, final RestRequest request, final ThreadContext threadContext) {
            auditInfo.put("audit_user", username);
            auditInfo.put("audit_message", message);
            auditInfo.put("audit_date", LocalDateTime.now().format(DateTimeFormatter.ISO_DATE_TIME));
            //TODO add first failing item
            if (threadContext.getTransient(AUDIT_ITEMS) != null) {
                List<String> failingItems = threadContext.getTransient(AUDIT_ITEMS);
                auditInfo.put(AUDIT_ITEMS, failingItems);
            }
            //auditInfo.put("audit_details_context", String.valueOf(request.getContext()));
            //auditInfo.put("audit_details_headers", String.valueOf(request.getHeaders()));
            auditInfo.put("audit_details_class", request.getClass().toString());
            final String ip = String.valueOf(request.getHttpChannel().getRemoteAddress().getAddress().getHostAddress());
            if (!"null".equals(ip)) {
                auditInfo.put("audit_ip", ip);
            }
        }

        private AuditMessage(final String username, final String message, final RestRequest request, final Settings settings) {
            auditInfo.put("audit_user", username);
            auditInfo.put("audit_message", message);
            auditInfo.put("audit_date", LocalDateTime.now().format(DateTimeFormatter.ISO_DATE_TIME));
            //TODO
            //auditInfo.put("audit_details_context", String.valueOf(request.getContext()));
            //auditInfo.put("audit_details_headers", Iterables.toString(request.headers()));
            auditInfo.put("audit_details_rest", request.method() + " " + request.path() + " " + request.params());
            auditInfo.put("audit_details_class", request.getClass().toString());

            try {
                final String ip = SecurityUtil.getProxyResolvedHostAddressFromRequest(request, settings).getHostAddress();
                if (ip != null && !"null".equals(ip)) {
                    auditInfo.put("audit_ip", ip);
                }
            } catch (final UnknownHostException e) {
                //no-op
            }
        }

        @Override
        public String toString() {
            return "AuditMessage [auditInfo=" + auditInfo + "]";
        }

    }

}
