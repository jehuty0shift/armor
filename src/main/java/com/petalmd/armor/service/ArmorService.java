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
import com.petalmd.armor.util.SecurityUtil;
import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.client.Client;
import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.component.AbstractLifecycleComponent;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLoggerFactory;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.PrivilegedExceptionAction;
import java.security.SecureRandom;

public class ArmorService extends AbstractLifecycleComponent {

    //private final String securityConfigurationIndex;
    private final Settings settings;
    protected final Logger log = ESLoggerFactory.getLogger(this.getClass());
    private Method method;
    private Method searchServiceSetCallbackMethod;
    private final AuditListener auditListener;
    private final ClusterService clusterService;
    private static SecretKey secretKey;
    private final Authorizator authorizator;
    private final AuthenticationBackend authenticationBackend;
    private final HTTPAuthenticator httpAuthenticator;
    private final SessionStore sessionStore;
    public Authorizator getAuthorizator() {
        return authorizator;
    }

    public AuthenticationBackend getAuthenticationBackend() {
        return authenticationBackend;
    }

    public HTTPAuthenticator getHttpAuthenticator() {
        return httpAuthenticator;
    }


    @Inject
    public ArmorService(final Settings settings, final ClusterService clusterService,
            final Authorizator authorizator, final AuthenticationBackend authenticationBackend, final HTTPAuthenticator httpAuthenticator,
            final SessionStore sessionStore, final AuditListener auditListener) {
        super(settings);
        this.settings = settings;
        //securityConfigurationIndex = settings
        //        .get(ConfigConstants.ARMOR_CONFIG_INDEX_NAME, ConfigConstants.DEFAULT_SECURITY_CONFIG_INDEX);
        this.authenticationBackend = authenticationBackend;
        this.authorizator = authorizator;
        this.httpAuthenticator = httpAuthenticator;
        this.sessionStore = sessionStore;
        this.clusterService = clusterService;

        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

//        try {
//            AccessController.doPrivileged(new PrivilegedExceptionAction<Boolean>() {
//                @Override
//                public Boolean run() throws Exception {
//                    method = RestController.class.getDeclaredMethod("getHandler", RestRequest.class);
//                    method.setAccessible(true);
//
//                    return true;
//                }
//            });
//        } catch (final Exception e) {
//            log.error(e.toString(), e);
//            throw new ElasticsearchException(e.toString());
//        }

        final String keyPath = settings.get(ConfigConstants.ARMOR_KEY_PATH,".");
//        AccessController.checkPermission(new FilePermission(keyPath+File.separator+"armor_node_key.key", "write"));
        SecretKey sc = null;
        try {
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

        this.auditListener = auditListener;
        //TODO FUTURE index change audit trail
        

        /*final String scriptingStatus = settings.get(ScriptService.DISABLE_DYNAMIC_SCRIPTING_SETTING,
                ScriptService.DISABLE_DYNAMIC_SCRIPTING_DEFAULT);

        if (scriptingStatus.equalsIgnoreCase(ScriptService.DISABLE_DYNAMIC_SCRIPTING_DEFAULT)) {
            log.warn("{} has the default value {}, consider setting it to false if not needed",
                    ScriptService.DISABLE_DYNAMIC_SCRIPTING_SETTING, scriptingStatus);
        }

        if (scriptingStatus.equalsIgnoreCase("true")) {
            log.error("{} is configured insecure, consider setting it to false or " + ScriptService.DISABLE_DYNAMIC_SCRIPTING_DEFAULT,
                    ScriptService.DISABLE_DYNAMIC_SCRIPTING_SETTING);
        }*/

        ArmorService.secretKey = sc;
    }

    public ClusterService getClusterService() { return clusterService; }

    public static SecretKey getSecretKey() {
        return secretKey;
    }

    public SessionStore getSessionStore() {
        return sessionStore;
    }

    public Settings getSettings() {
        return settings;
    }


    @Override
    protected void doStart() throws ElasticsearchException {

//        restController.registerFilter(new DefaultRestFilter(this, null, null, auditListener));
//
//        final String[] restActionFilters = settings.getAsArray(ConfigConstants.ARMOR_RESTACTIONFILTER);
//        for (int i = 0; i < restActionFilters.length; i++) {
//            final String filterName = restActionFilters[i];
//            restController.registerFilter(new RestActionFilter(this, "restactionfilter", filterName, auditListener));
//            //filterRegistered = true;
//        }

        //TODO FUTURE version compatibility
        /* if(!Version.CURRENT.before(Version.V_1_4_2)) {
             throw new ElasticsearchException("Wrong ES version, use 1.4.2 or later");
         }*/

 /*if (!filterRegistered) {
            throw new ElasticsearchException("No filter configured");
        }*/
//        log.info("Starting Search Guard with {} filters",
//            (restActionFilters.length + dlsFilters.length + flsFilters.length + arFilters.length));
        log.trace("With settings " + this.settings.getAsMap());

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
