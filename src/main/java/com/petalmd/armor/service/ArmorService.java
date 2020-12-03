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
import com.petalmd.armor.authentication.backend.AuthenticationBackend;
import com.petalmd.armor.authentication.http.HTTPAuthenticator;
import com.petalmd.armor.authorization.Authorizator;
import com.petalmd.armor.http.SessionStore;
import com.petalmd.armor.util.ConfigConstants;
import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.component.AbstractLifecycleComponent;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.ingest.IngestService;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FilePermission;
import java.security.AccessController;
import java.security.PrivilegedExceptionAction;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicReference;

public class ArmorService extends AbstractLifecycleComponent {

    //private final String securityConfigurationIndex;
    private final Settings settings;
    protected final Logger log = LogManager.getLogger(this.getClass());
    private final AuditListener auditListener;
    private final ClusterService clusterService;
    private IngestService ingestService;
    private static AtomicReference<SecretKey> secretKey = new AtomicReference<>();
    private final Authorizator authorizator;
    private final AuthenticationBackend authenticationBackend;
    private final HTTPAuthenticator httpAuthenticator;
    private final SessionStore sessionStore;

    @Inject
    public ArmorService(final Settings settings, final ClusterService clusterService,
            final Authorizator authorizator, final AuthenticationBackend authenticationBackend, final HTTPAuthenticator httpAuthenticator,
            final SessionStore sessionStore, final AuditListener auditListener) {
        super();
        this.settings = settings;
        this.authenticationBackend = authenticationBackend;
        this.authorizator = authorizator;
        this.httpAuthenticator = httpAuthenticator;
        this.sessionStore = sessionStore;
        this.clusterService = clusterService;

        //TODO FUTURE index change audit trail
        this.auditListener = auditListener;

        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }


        final String keyPath = System.getProperty("es.path.conf");
        SecretKey sc = null;
        try {
            AccessController.checkPermission(new FilePermission(keyPath+File.separator+"armor_node_key.key", "write"));
            sc = AccessController.doPrivileged(new PrivilegedExceptionAction<SecretKey>() {
                @Override
                public SecretKey run() throws Exception {
                    final File keyFile = new File(keyPath, "armor_node_key.key");
                    SecretKey sc = null;
                    if (keyFile.exists()) {
                        log.debug("Loaded key from {}", keyFile.getAbsolutePath());
                        sc = new SecretKeySpec(FileUtils.readFileToByteArray(keyFile), "AES");
                    } else {
                        final SecureRandom secRandom = SecureRandom.getInstance("SHA1PRNG");
                        final KeyGenerator kg = KeyGenerator.getInstance("AES");
                        kg.init(128, secRandom);
                        final SecretKey secretKey = kg.generateKey();
                        final byte[] enckey = secretKey.getEncoded();

                        if (enckey == null || enckey.length != 16) {
                            throw new Exception("invalid key " + (enckey == null ? -1 : enckey.length));
                        }
                        FileUtils.writeByteArrayToFile(keyFile, enckey);
                        sc = secretKey;
                        log.info("New key written to {}, make sure all nodes have this key", keyFile.getAbsolutePath());
                    }
                    return sc;
                }
            });
        } catch (final Exception e) {
            log.error("Cannot generate or read secrety key", e);
            throw new ElasticsearchException(e.toString());
        }

        ArmorService.secretKey.set(sc);
    }

    public ClusterService getClusterService() { return clusterService; }

    public static SecretKey getSecretKey() {
        return secretKey.get();
    }

    public SessionStore getSessionStore() {
        return sessionStore;
    }

    public Settings getSettings() {
        return settings;
    }

    public Authorizator getAuthorizator() {
        return authorizator;
    }

    public AuthenticationBackend getAuthenticationBackend() {
        return authenticationBackend;
    }

    public HTTPAuthenticator getHttpAuthenticator() {
        return httpAuthenticator;
    }

    public AuditListener getAuditListener() { return auditListener;}

    public IngestService getIngestService() {
        return ingestService;
    }

    public void setIngestService(final IngestService ingestService) {
        this.ingestService = ingestService;
    }

    @Override
    protected void doStart() throws ElasticsearchException {

        log.trace("With settings " + this.settings.toString());

    }

    /*public String getSecurityConfigurationIndex() {
        return securityConfigurationIndex;
    }*/

    @Override
    protected void doStop() throws ElasticsearchException {
        //no-op
    }


    @Override
    protected void doClose() throws ElasticsearchException {
        //no-op

    }
}
