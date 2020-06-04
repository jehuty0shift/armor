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

package com.petalmd.armor.service;

import com.petalmd.armor.audit.AuditListener;
import com.petalmd.armor.util.ConfigConstants;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.component.AbstractLifecycleComponent;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.common.util.concurrent.EsExecutors;
import org.elasticsearch.common.util.concurrent.FutureUtils;
import org.elasticsearch.index.IndexNotFoundException;

import java.util.concurrent.*;

public class ArmorConfigService extends AbstractLifecycleComponent {

    private final AuditListener auditListener;
    private final Client client;
    private final String securityConfigurationIndex;
    private volatile BytesReference securityConfiguration;
    private ScheduledThreadPoolExecutor scheduler;
    private ScheduledFuture scheduledFuture;
    private final CountDownLatch latch = new CountDownLatch(1);

    private static final Logger log = LogManager.getLogger(ArmorConfigService.class);

    @Inject
    public ArmorConfigService(final Settings settings, final Client client, final AuditListener auditListener) {
        super();
        this.client = client;
        this.auditListener = auditListener;
        securityConfigurationIndex = settings.get(ConfigConstants.ARMOR_CONFIG_INDEX_NAME,
                ConfigConstants.DEFAULT_SECURITY_CONFIG_INDEX);

    }

    public BytesReference getSecurityConfiguration() {
        try {
            if (!latch.await(15, TimeUnit.SECONDS)) {
                log.info("Is reload task terminated ? {}", scheduledFuture.isCancelled());
                throw new ElasticsearchException("Security configuration cannot be loaded for unknown reasons");
            }
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return securityConfiguration;
    }

    //blocking
    private void reloadConfig() {

        try {
            boolean first = securityConfiguration == null;

            if(first) {
                log.info("retrieving Security configuration document for the first time");
            }

            log.debug("retrieving Security configuration document");
            GetResponse getResponse = client.prepareGet(securityConfigurationIndex, "ac", "ac").setRefresh(true).get(TimeValue.timeValueSeconds(10));


            if (getResponse.isExists() && !getResponse.isSourceEmpty()) {
                securityConfiguration = getResponse.getSourceAsBytesRef();
                latch.countDown();
                if (first) {
                    log.info("Security Configuration loaded with size {}",securityConfiguration.length());
                }
                log.debug("Security configuration reloaded");
            } else {
                throw new IllegalStateException("Document does not yet exists !");
            }
        } catch (Exception e) {
            if (e instanceof IndexNotFoundException) {
                log.error(
                        "Tried to refresh security configuration but it failed due to {} - This might be ok if security setup not complete yet.",
                        e.toString());
            } else {
                log.warn("Tried to refresh security configuration but it failed due to {}", e, e.toString());
            }
        }
    }

    private void configAuditListener(){

        if (!auditListener.isReady()) {
            if(auditListener.setupAuditListener()){
                log.info("audit Listener is ready");
            } else {
                log.info("audit Listener is not yet ready");
            }
        } else {
            log.debug("audit Listener is already ready");
        }

    }

    private class Reload implements Runnable {
        @Override
        public void run() {
            synchronized (ArmorConfigService.this) {
                reloadConfig();
                configAuditListener();
            }
        }
    }

    @Override
    protected void doStart() throws ElasticsearchException {
        this.scheduler = (ScheduledThreadPoolExecutor) Executors.newScheduledThreadPool(1,
                EsExecutors.daemonThreadFactory(client.settings(), "armor_config_service"));
        this.scheduler.setExecuteExistingDelayedTasksAfterShutdownPolicy(false);
        this.scheduler.setContinueExistingPeriodicTasksAfterShutdownPolicy(false);
        this.scheduledFuture = this.scheduler.scheduleWithFixedDelay(new Reload(), 5, 1, TimeUnit.SECONDS);
        log.info("ArmorConfigService started");
    }

    @Override
    protected void doStop() throws ElasticsearchException {
        FutureUtils.cancel(this.scheduledFuture);
        this.scheduler.shutdown();
        log.info("ArmorConfigService stopped");
    }

    @Override
    protected void doClose() throws ElasticsearchException {
        FutureUtils.cancel(this.scheduledFuture);
        this.scheduler.shutdown();
    }
}
