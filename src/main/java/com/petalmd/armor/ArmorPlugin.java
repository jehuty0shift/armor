/*
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
package com.petalmd.armor;

import com.petalmd.armor.audit.AuditListener;
import com.petalmd.armor.audit.ESStoreAuditListener;
import com.petalmd.armor.audit.NullStoreAuditListener;
import com.petalmd.armor.authentication.backend.AuthenticationBackend;
import com.petalmd.armor.authentication.backend.GuavaCachingAuthenticationBackend;
import com.petalmd.armor.authentication.backend.NonCachingAuthenticationBackend;
import com.petalmd.armor.authentication.backend.simple.SettingsBasedAuthenticationBackend;
import com.petalmd.armor.authentication.http.HTTPAuthenticator;
import com.petalmd.armor.authentication.http.basic.HTTPBasicAuthenticator;
import com.petalmd.armor.authorization.Authorizator;
import com.petalmd.armor.authorization.GuavaCachingAuthorizator;
import com.petalmd.armor.authorization.NonCachingAuthorizator;
import com.petalmd.armor.authorization.simple.SettingsBasedAuthorizator;
import com.petalmd.armor.filter.*;
import com.petalmd.armor.filter.kefla.KeflaEngine;
import com.petalmd.armor.http.DefaultSessionStore;
import com.petalmd.armor.http.NullSessionStore;
import com.petalmd.armor.http.SessionStore;
import com.petalmd.armor.http.netty.SSLNettyHttpServerTransport;
import com.petalmd.armor.processor.LDPProcessor;
import com.petalmd.armor.processor.kafka.KafkaOutputFactory;
import com.petalmd.armor.rest.ArmorInfoAction;
import com.petalmd.armor.rest.ArmorRestShield;
import com.petalmd.armor.service.ArmorConfigService;
import com.petalmd.armor.service.ArmorService;
import com.petalmd.armor.service.KafkaEngineService;
import com.petalmd.armor.service.MongoDBService;
import com.petalmd.armor.transport.SSLNettyTransport;
import com.petalmd.armor.util.ArmorConstants;
import com.petalmd.armor.util.ConfigConstants;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.util.SetOnce;
import org.elasticsearch.Version;
import org.elasticsearch.action.support.ActionFilter;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.node.DiscoveryNodes;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.*;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.common.util.PageCacheRecycler;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.env.Environment;
import org.elasticsearch.env.NodeEnvironment;
import org.elasticsearch.http.HttpServerTransport;
import org.elasticsearch.indices.breaker.CircuitBreakerService;
import org.elasticsearch.ingest.IngestService;
import org.elasticsearch.ingest.Processor;
import org.elasticsearch.plugins.ActionPlugin;
import org.elasticsearch.plugins.IngestPlugin;
import org.elasticsearch.plugins.NetworkPlugin;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.repositories.RepositoriesService;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestHandler;
import org.elasticsearch.rest.RestHeaderDefinition;
import org.elasticsearch.script.ScriptService;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.SharedGroupFactory;
import org.elasticsearch.transport.Transport;
import org.elasticsearch.watcher.ResourceWatcherService;

import java.lang.reflect.InvocationTargetException;
import java.util.*;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;
import java.util.stream.Collectors;
import java.util.stream.Stream;


//TODO FUTURE store users/roles also in elasticsearch armor index
//TODO FUTURE Multi authenticator/authorizator
//TODO FUTURE special handling scroll searches
//TODO FUTURE negative rules/users in acrules
//TODO update some settings during runtime
public final class ArmorPlugin extends Plugin implements ActionPlugin, NetworkPlugin, IngestPlugin {

    private static final String ARMOR_DEBUG = "armor.debug";
    private static final String CLIENT_TYPE = "client.type";

    private static final Logger log = LogManager.getLogger(ArmorPlugin.class);
    private final boolean isPureClient;
    private final boolean enabled;
    private final Settings settings;
    private final SetOnce<SharedGroupFactory> groupFactory = new SetOnce<>();

    private ArmorService armorService;
    private IngestService ingestService;
    private ArmorInfoAction armorInfoAction;
    private ArmorRestShield armorRestShield;
    private ArmorConfigService armorConfigService;
    private AuditListener auditListener;
    private Authorizator authorizator;
    private AuthenticationBackend authenticationBackend;
    private Client client;
    private ClusterService clusterService;
    private HTTPAuthenticator httpAuthenticator;
    private KafkaEngineService kafkaEngineService;
    private KeflaEngine keflaEngine;
    private MongoDBService mongoDbService;
    private NamedXContentRegistry xContentRegistry;
    private SessionStore sessionStore;
    private ThreadPool threadPool;

    static {
        if (Boolean.parseBoolean(System.getProperty(ArmorPlugin.ARMOR_DEBUG, "false"))) {
            System.setProperty("javax.net.debug", "all");
            System.setProperty("sun.security.krb5.debug", "true");
            System.setProperty("java.security.debug", "all");
        }
    }

    public ArmorPlugin(final Settings settings) {
        this.settings = settings;
        enabled = this.settings.getAsBoolean(ConfigConstants.ARMOR_ENABLED, false);
        isPureClient = !"node".equals(settings.get(CLIENT_TYPE, "node"));
    }

    @Override
    public Collection<Object> createComponents(Client client, ClusterService clusterService, ThreadPool threadPool, ResourceWatcherService resourceWatcherService, ScriptService scriptService, NamedXContentRegistry xContentRegistry, Environment environment, NodeEnvironment nodeEnvironment, NamedWriteableRegistry namedWriteableRegistry, IndexNameExpressionResolver indexNameExpressionResolver, Supplier<RepositoriesService> repositoriesServiceSupplier) {

        List<Object> componentsList = new ArrayList<>();

        if (!enabled) {
            return componentsList;
        }

        final Class<? extends HTTPAuthenticator> defaultHTTPAuthenticatorClass = HTTPBasicAuthenticator.class;
        final Class<? extends NonCachingAuthorizator> defaultNonCachingAuthorizatorClass = SettingsBasedAuthorizator.class;
        final Class<? extends NonCachingAuthenticationBackend> defaultNonCachingAuthenticationClass = SettingsBasedAuthenticationBackend.class;

        //create Kafka Service

        //create Mongo Database
        mongoDbService = new MongoDBService(settings);
        componentsList.add(mongoDbService);

        kafkaEngineService = new KafkaEngineService(settings, mongoDbService);
        componentsList.add(kafkaEngineService);


        //create Authenticator
        try {
            this.clusterService = clusterService;
            this.threadPool = threadPool;
            this.xContentRegistry = xContentRegistry;
            this.client = client;

            String className = settings.get(ConfigConstants.ARMOR_AUTHENTICATION_AUTHENTICATION_BACKEND);
            Class authenticationBackendClass;
            authenticationBackendClass = className == null ? null : Class.forName(className);
            if (authenticationBackendClass != null && NonCachingAuthenticationBackend.class.isAssignableFrom(authenticationBackendClass)) {
                authenticationBackend = (AuthenticationBackend) authenticationBackendClass.getConstructor(Settings.class).newInstance(settings);
            } else {
                authenticationBackend = defaultNonCachingAuthenticationClass.getConstructor(Settings.class).newInstance(settings);
            }

            if (settings.getAsBoolean(ConfigConstants.ARMOR_AUTHENTICATION_AUTHENTICATION_BACKEND_CACHE_ENABLE, true)) {
                authenticationBackend = new GuavaCachingAuthenticationBackend((NonCachingAuthenticationBackend) authenticationBackend, settings);
            }
        } catch (InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException | NoSuchMethodException | ClassNotFoundException | SecurityException e) {
            log.error("Unable to instantiate the AuthenticationBackend Class ! ! ", e);
        }
        componentsList.add(authenticationBackend);

        //create Authorizator
        try {
            String className = settings.get(ConfigConstants.ARMOR_AUTHENTICATION_AUTHORIZATOR);
            Class authorizerClass;
            authorizerClass = className == null ? null : Class.forName(className);
            if (authorizerClass != null && NonCachingAuthorizator.class.isAssignableFrom(authorizerClass)) {
                authorizator = (Authorizator) authorizerClass.getConstructor(Settings.class).newInstance(settings);
            } else {
                authorizator = defaultNonCachingAuthorizatorClass.getConstructor(Settings.class).newInstance(settings);
            }

            if (settings.getAsBoolean(ConfigConstants.ARMOR_AUTHENTICATION_AUTHORIZATOR_CACHE_ENABLE, true)) {
                authorizator = new GuavaCachingAuthorizator((NonCachingAuthorizator) authorizator, settings);
            }
        } catch (InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException | NoSuchMethodException | ClassNotFoundException | SecurityException e) {
            log.error("Unable to instantiate the Authorizator Class ! ! ", e);
        }
        componentsList.add(authorizator);

        //create httpAuthenticator
        try {
            String className = settings.get(ConfigConstants.ARMOR_AUTHENTICATION_HTTP_AUTHENTICATOR);
            Class httpAuthenticatorClass;
            httpAuthenticatorClass = className == null ? null : Class.forName(className);
            if (httpAuthenticatorClass != null && HTTPAuthenticator.class.isAssignableFrom(httpAuthenticatorClass)) {
                httpAuthenticator = (HTTPAuthenticator) httpAuthenticatorClass.getConstructor(Settings.class).newInstance(settings);
            } else {
                httpAuthenticator = defaultHTTPAuthenticatorClass.getConstructor(Settings.class).newInstance(settings);
            }

        } catch (InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException | NoSuchMethodException | ClassNotFoundException | SecurityException e) {
            log.error("Unable to instantiate the HTTP Authenticator Class ! ! ", e);
        }
        componentsList.add(httpAuthenticator);

        //create sessionStore
        Boolean enableHTTPSession = settings.getAsBoolean(ConfigConstants.ARMOR_HTTP_ENABLE_SESSIONS, false);
        if (enableHTTPSession != null && enableHTTPSession) {
            sessionStore = new DefaultSessionStore();
        } else {
            sessionStore = new NullSessionStore();
        }
        componentsList.add(sessionStore);

        //create auditLog
        Boolean enableAuditLog = settings.getAsBoolean(ConfigConstants.ARMOR_AUDITLOG_ENABLED, true);
        if (enableAuditLog) {
            auditListener = new ESStoreAuditListener(client, settings);
        } else {
            auditListener = new NullStoreAuditListener();
        }
        componentsList.add(auditListener);

        //create Armor Service
        armorService = new ArmorService(settings, clusterService, authorizator, authenticationBackend, httpAuthenticator, sessionStore, auditListener);
        componentsList.add(armorService);

        //create Armor Rest Shield (will handle REST authentication)
        armorRestShield = new ArmorRestShield(settings, authenticationBackend, authorizator, httpAuthenticator, threadPool.getThreadContext(), auditListener, sessionStore);
        componentsList.add(armorRestShield);

        //create Armor Config Service
        armorConfigService = new ArmorConfigService(settings, client, auditListener,threadPool);
        componentsList.add(armorConfigService);

        //create Kefla Engine Service
        keflaEngine = new KeflaEngine(settings, clusterService);
        componentsList.add(keflaEngine);

        //IngestService
        armorService.setIngestService(ingestService);

        //armorInfoAction
        armorInfoAction = new ArmorInfoAction(settings,  Objects.requireNonNull(armorConfigService));

        log.info("added " + componentsList.size() + " components.");
        log.info(authenticationBackend.getClass().getName());
        return componentsList;

    }

    @Override
    public List<ActionFilter> getActionFilters() {
        List<ActionFilter> actionFilters = new ArrayList<>();
        if (enabled && !isPureClient) {
            actionFilters.add(new ArmorAuditFilter(settings, clusterService, threadPool));
            actionFilters.add(new KibanaHelperFilter(settings, clusterService, threadPool, armorService, armorConfigService));
            actionFilters.add(new BypassFilter(settings, clusterService, threadPool, armorService, armorConfigService));
            actionFilters.add(new RequestActionFilter(settings, clusterService, threadPool, armorService, armorConfigService));
            actionFilters.add(new ArmorActionFilter(settings, clusterService, threadPool, armorService, armorConfigService));
            actionFilters.add(new ObfuscationFilter(settings, clusterService, threadPool, armorService, armorConfigService));
            actionFilters.add(new ClearScrollFilter(settings, clusterService, threadPool, armorService, armorConfigService));
            actionFilters.add(new AggregationFilter(settings, clusterService, threadPool, armorService, armorConfigService, xContentRegistry));
            actionFilters.add(new IndicesUpdateSettingsFilter(settings, clusterService, threadPool, armorService, armorConfigService));
            actionFilters.add(new ActionCacheFilter(settings, clusterService, threadPool, armorService, armorConfigService));
            actionFilters.add(new KeflaFilter(settings, keflaEngine, armorService, armorConfigService, clusterService, threadPool));
            actionFilters.add(new IndexLifecycleFilter(settings, clusterService, armorService, armorConfigService, threadPool, mongoDbService, kafkaEngineService));
            actionFilters.add(new AliasLifeCycleFilter(settings, clusterService, armorService, armorConfigService, threadPool, mongoDbService, kafkaEngineService));
            actionFilters.add(new IndexTemplateFilter(settings, clusterService, armorService, armorConfigService, threadPool));
            actionFilters.add(new IngestPipelineFilter(settings, clusterService, armorService, armorConfigService, threadPool));
            actionFilters.add(new LDPIndexFilter(settings, client, clusterService, armorService, armorConfigService, armorInfoAction, threadPool));
            actionFilters.add(new DLSActionFilter(settings, client, clusterService, threadPool, armorService, armorConfigService));
            actionFilters.add(new FLSActionFilter(settings, client, clusterService, threadPool, armorService, armorConfigService));
        }

        return actionFilters;
    }


    @Override
    public Map<String, Processor.Factory> getProcessors(Processor.Parameters parameters) {
        ingestService = parameters.ingestService;
        KafkaOutputFactory factory = KafkaOutputFactory.makeInstance(parameters.env.settings());
        log.info("Add Processor LDP to processors");
        return Collections.singletonMap(LDPProcessor.TYPE, new LDPProcessor.Factory(factory, parameters.env.settings()));
    }

    @Override
    public List<RestHandler> getRestHandlers(Settings settings, RestController restController, ClusterSettings clusterSettings, IndexScopedSettings indexScopedSettings, SettingsFilter settingsFilter, IndexNameExpressionResolver indexNameExpressionResolver, Supplier<DiscoveryNodes> nodesInCluster) {

        if (!enabled) {
            return Collections.emptyList();
        } else {
            return Collections.singletonList(armorInfoAction);
        }
    }


    @Override
    public Collection<RestHeaderDefinition> getRestHeaders() {
        if (!enabled) {
            return Collections.emptyList();
        } else {
            return Stream.of(ArmorConstants.ARMOR_AUTHENTICATED_USER,
                    ArmorConstants.ARMOR_AUTHENTICATED_TRANSPORT_REQUEST,
                    ArmorConstants.ARMOR_TRANSPORT_CREDS,
                    "DeleteByQueryHeader")
                    .map(s -> new RestHeaderDefinition(s,false))
                    .collect(Collectors.toList());

        }
    }

    @Override
    public UnaryOperator<RestHandler> getRestHandlerWrapper(ThreadContext threadContext) {
        if (enabled) {
            return (rh) -> armorRestShield.shield(rh);
        } else {
            return (rh) -> (rh::handleRequest);
        }
    }

    @Override
    public List<Setting<?>> getSettings() {
        List<Setting<?>> settings = new ArrayList<>();

        //Generic Armor settings
        settings.add(Setting.simpleString(ConfigConstants.DEFAULT_SECURITY_CONFIG_INDEX, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_CONFIG_INDEX_NAME, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_ENABLED, false, Setting.Property.NodeScope));
        settings.add(Setting.intSetting(ConfigConstants.ARMOR_AUDITLOG_NUM_REPLICAS, 1, 1, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUDITLOG_COMPRESSION, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_ALLOW_ALL_FROM_LOOPBACK, true, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_ALLOW_NON_LOOPBACK_QUERY_ON_ARMOR_INDEX, false, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_ALLOW_KIBANA_ACTIONS, true, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_AUDITLOG_ENABLED, true, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_TRANSPORT_AUTH_ENABLED, false, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_HTTP_ENABLE_SESSIONS, false, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_HTTP_XFORWARDEDFOR_ENFORCE, false, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_HTTP_XFORWARDEDFOR_VALIDATEPROXIES, false, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_HTTP_XFORWARDEDFOR_HEADER, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.listSetting(ConfigConstants.ARMOR_HTTP_XFORWARDEDFOR_TRUSTEDPROXIES, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.groupSetting(ConfigConstants.ARMOR_HTTP_ADDITIONAL_RIGHTS_HEADER, Setting.Property.NodeScope));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_KEY_PATH, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUTHENTICATION_PROXY_HEADER, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.listSetting(ConfigConstants.ARMOR_AUTHENTICATION_PROXY_TRUSTED_IPS, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope, Setting.Property.Filtered));


        //armor filters
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_AGGREGATION_FILTER_ENABLED, true, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_ACTION_WILDCARD_EXPANSION_ENABLED, true, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_ACTION_CACHE_ENABLED, false, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.listSetting(ConfigConstants.ARMOR_ACTION_CACHE_LIST, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_INDICES_UPDATESETTINGSFILTER_ENABLED, false, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.listSetting(ConfigConstants.ARMOR_INDICES_UPDATESETTINGSFILTER_ALLOWED, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_OBFUSCATION_FILTER_ENABLED, true, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.groupSetting(ConfigConstants.ARMOR_OBFUSCATION_FILTERS, Setting.Property.NodeScope));  //TODO write a proper validator;
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_REWRITE_GET_AS_SEARCH, true, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.groupSetting(ConfigConstants.ARMOR_ACTIONREQUESTFILTERS, Setting.Property.NodeScope));  //TODO write a proper validator;
        settings.add(Setting.groupSetting(ConfigConstants.ARMOR_DLSFILTERS, Setting.Property.NodeScope));  //TODO write a proper validator;
        settings.add(Setting.groupSetting(ConfigConstants.ARMOR_FLSFILTERS, Setting.Property.NodeScope));  //TODO write a proper validator;
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_SCROLL_CLEAR_ALLOW_ALL, false, Setting.Property.NodeScope, Setting.Property.Filtered));

        //ssl HTTP
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_SSL_TRANSPORT_HTTP_ENABLED, false, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_SSL_TRANSPORT_HTTP_ENFORCE_CLIENTAUTH, false, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_SSL_TRANSPORT_HTTP_KEEP_ALIVE_ENABLED, false, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_SSL_TRANSPORT_HTTP_KEYSTORE_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_SSL_TRANSPORT_HTTP_KEYSTORE_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_SSL_TRANSPORT_HTTP_KEYSTORE_TYPE, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_SSL_TRANSPORT_HTTP_TRUSTSTORE_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_SSL_TRANSPORT_HTTP_TRUSTSTORE_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_SSL_TRANSPORT_HTTP_TRUSTSTORE_TYPE, Setting.Property.NodeScope, Setting.Property.Filtered));

        //ssl Transport
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_ENABLED, false, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_ENFORCE_CLIENTAUTH, false, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_ENFORCE_HOSTNAME_VERIFICATION, false, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, false, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_KEYSTORE_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_KEYSTORE_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_KEYSTORE_TYPE, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_TRUSTSTORE_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_TRUSTSTORE_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_TRUSTSTORE_TYPE, Setting.Property.NodeScope, Setting.Property.Filtered));

        //armor authentication
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUTHENTICATION_AUTHENTICATION_BACKEND, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_AUTHENTICATION_AUTHENTICATION_BACKEND_CACHE_ENABLE, false, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUTHENTICATION_HTTP_AUTHENTICATOR, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUTHENTICATION_HTTPS_CLIENTCERT_ATTRIBUTENAME, Setting.Property.NodeScope, Setting.Property.Filtered));

        //armor authorization
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUTHENTICATION_AUTHORIZATOR, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUTHENTICATION_AUTHORIZATOR_CACHE_ENABLE, Setting.Property.NodeScope, Setting.Property.Filtered));


        //multi backend
        settings.add(Setting.listSetting(ConfigConstants.ARMOR_AUTHENTICATION_MULTI_AUTH_BACKEND_LIST, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.listSetting(ConfigConstants.ARMOR_AUTHENTICATION_AUTHORIZATION_MULTI_BACKEND_LIST, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope, Setting.Property.Filtered));

        //settings backend
        settings.add(Setting.groupSetting(ConfigConstants.ARMOR_AUTHENTICATION_SETTINGSDB_USER, Setting.Property.NodeScope));
        settings.add(Setting.listSetting(ConfigConstants.ARMOR_AUTHENTICATION_SETTINGSDB_USERCREDS, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.groupSetting(ConfigConstants.ARMOR_AUTHENTICATION_AUTHORIZATION_SETTINGSDB_ROLES, Setting.Property.NodeScope));

        //KRB5
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUTHENTICATION_SPNEGO_KRB5_CONFIG_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUTHENTICATION_SPNEGO_LOGIN_CONFIG_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUTHENTICATION_SPNEGO_LOGIN_CONFIG_NAME, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUTHENTICATION_SPNEGO_STRIP_REALM, Setting.Property.NodeScope, Setting.Property.Filtered));

        //GRAYLOG backend
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUTHENTICATION_GRAYLOG_ENDPOINT, Setting.Property.NodeScope, Setting.Property.Filtered));

        //Encrypted Backend
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_MONGODB_ENCRYPTED_TOKEN_PRIVATE_KEY, Setting.Property.NodeScope, Setting.Property.Filtered));

        //ldap backend
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_AUTHENTICATION_AUTHORIZATION_LDAP_RESOLVE_NESTED_ROLES, false, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUTHENTICATION_AUTHORIZATION_LDAP_ROLEBASE, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUTHENTICATION_AUTHORIZATION_LDAP_ROLESEARCH, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUTHENTICATION_LDAP_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUTHENTICATION_LDAP_HOST, Setting.Property.NodeScope));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUTHENTICATION_LDAP_USERNAME_ATTRIBUTE, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUTHENTICATION_LDAP_BIND_DN, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUTHENTICATION_LDAP_USERBASE, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUTHENTICATION_LDAP_USERSEARCH, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUTHENTICATION_AUTHORIZATION_LDAP_ROLENAME, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_AUTHENTICATION_LDAP_LDAPS_STARTTLS_ENABLED, false, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_AUTHENTICATION_LDAP_LDAPS_SSL_ENABLED, false, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUTHENTICATION_LDAP_LDAPS_TRUSTSTORE_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUTHENTICATION_LDAP_LDAPS_TRUSTSTORE_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUTHENTICATION_LDAP_LDAPS_TRUSTSTORE_TYPE, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.intSetting(ConfigConstants.ARMOR_AUTHENTICATION_LDAP_MAX_ACTIVE_CONNECTIONS, 8, 1, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUTHENTICATION_AUTHORIZATION_LDAP_USERROLEATTRIBUTE, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUTHENTICATION_AUTHORIZATION_LDAP_USERROLENAME, Setting.Property.NodeScope, Setting.Property.Filtered));

        //WAFFLE
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_WAFFLE_WINDOWS_AUTH_PROVIDER_IMPL, Setting.Property.NodeScope, Setting.Property.Filtered));

        //Kibana Helper
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_KIBANA_HELPER_ENABLED, true, Setting.Property.NodeScope, Setting.Property.Filtered));

        //Kefla
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_KEFLA_FILTER_ENABLED, true, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_KEFLA_PLUGIN_ENDPOINT, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_KEFLA_PLUGIN_USER, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_KEFLA_PLUGIN_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered));

        // LDP Filter
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_LDP_FILTER_ENABLED, true, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_LDP_FILTER_LDP_PIPELINE_NAME, Setting.Property.NodeScope, Setting.Property.Filtered));

        //MongoDB
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_MONGODB_URI, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_MONGODB_ENGINE_DATABASE, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_MONGODB_GRAYLOG_DATABASE, Setting.Property.NodeScope, Setting.Property.Filtered));

        //Kafka
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_KAFKA_ENGINE_SERVICE_ENABLED, false, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_KAFKA_ENGINE_SERVICE_CLIENT_ID, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_KAFKA_ENGINE_SERVICE_PRIVATE_KEY, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_KAFKA_ENGINE_SERVICE_TOPIC_SUFFIX, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.listSetting(ConfigConstants.ARMOR_KAFKA_ENGINE_SERVICE_TOPIC_REGIONS, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope, Setting.Property.Filtered));

        //IndexLifeCycle
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_INDEX_LIFECYCLE_ENABLED, false, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.listSetting(ConfigConstants.ARMOR_INDEX_LIFECYCLE_ALLOWED_SETTINGS, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.intSetting(ConfigConstants.ARMOR_INDEX_LIFECYCLE_MAX_NUM_OF_SHARDS_BY_USER, 1000, 1, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.intSetting(ConfigConstants.ARMOR_INDEX_LIFECYCLE_MAX_NUM_OF_SHARDS_BY_INDEX, 16, 1, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.intSetting(ConfigConstants.ARMOR_INDEX_LIFECYCLE_MAX_NUM_OF_REPLICAS_BY_INDEX, 1, 1, Setting.Property.NodeScope, Setting.Property.Filtered));

        //AliasLifeCycle
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_ALIAS_LIFECYCLE_ENABLED, false, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.intSetting(ConfigConstants.ARMOR_ALIAS_LIFECYCLE_MAX_NUM_OF_ALIAS_BY_USER, 1000, 1, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.intSetting(ConfigConstants.ARMOR_ALIAS_LIFECYCLE_MAX_NUM_OF_INDICES_BY_ALIAS, 1000, 1, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.listSetting(ConfigConstants.ARMOR_ALIAS_LIFECYCLE_ADDITIONAL_RIGHTS_LIGHT_CHECK, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope, Setting.Property.Filtered));
        //Template
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_INDEX_TEMPLATE_FILTER_ENABLED, true, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.listSetting(ConfigConstants.ARMOR_INDEX_TEMPLATE_FILTER_ALLOWED_SETTINGS, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope, Setting.Property.Filtered));

        //Ingest
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_INGEST_PIPELINE_FILTER_ENABLED, true, Setting.Property.NodeScope, Setting.Property.Filtered));

        //LDP Index
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_LDP_INDEX, Setting.Property.NodeScope, Setting.Property.Filtered));

        //LDP Processor
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_LDP_PROCESSOR_KAFKA_ACKS_CONFIG, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_LDP_PROCESSOR_KAFKA_BATCH_SIZE, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_LDP_PROCESSOR_KAFKA_BOOTSTRAP_SERVERS, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_LDP_PROCESSOR_KAFKA_CLIENT_ID, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_LDP_PROCESSOR_KAFKA_COMPRESSION_CODEC, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_LDP_PROCESSOR_KAFKA_ENABLED, false, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_LDP_PROCESSOR_KAFKA_LINGER_MS, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_LDP_PROCESSOR_KAFKA_TOPIC, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_LDP_PROCESSOR_KAFKA_OUTPUT_USE_KAFKA_IMPL, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_LDP_PROCESSOR_KAFKA_SECURITY_PROTOCOL, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_LDP_PROCESSOR_KAFKA_SASL_USERNAME, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_LDP_PROCESSOR_KAFKA_SASL_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_LDP_PROCESSOR_KAFKA_SSL_TRUSTSTORE_LOCATION, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_LDP_PROCESSOR_KAFKA_SSL_TRUSTSTORE_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered));

        //Audit Kafka
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_AUDIT_KAFKA_ENABLED, false, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUDIT_KAFKA_CLIENT_ID, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUDIT_KAFKA_BOOTSTRAP_SERVERS, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUDIT_KAFKA_TOPIC, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUDIT_KAFKA_ACKS_CONFIG, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUDIT_KAFKA_COMPRESSION_CODEC, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUDIT_KAFKA_SECURITY_PROTOCOL, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUDIT_KAFKA_SASL_USERNAME, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUDIT_KAFKA_SASL_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUDIT_KAFKA_SSL_TRUSTSTORE_LOCATION, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUDIT_KAFKA_SSL_TRUSTSTORE_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_AUDIT_KAFKA_USE_IMPL, true, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUDIT_KAFKA_X_OVH_TOKEN, Setting.Property.NodeScope, Setting.Property.Filtered));


        return settings;
    }


    @Override
    public Map<String, Supplier<HttpServerTransport>> getHttpTransports(Settings settings, ThreadPool threadPool, BigArrays bigArrays, PageCacheRecycler pageCacheRecycler, CircuitBreakerService circuitBreakerService, NamedXContentRegistry xContentRegistry, NetworkService networkService, HttpServerTransport.Dispatcher dispatcher, ClusterSettings clusterSettings) {
        return Collections.singletonMap("armor_ssl_netty4", () -> new SSLNettyHttpServerTransport(settings, networkService, bigArrays, threadPool, xContentRegistry, dispatcher, clusterSettings, getSharedGroupFactory(settings)));
    }


    @Override
    public Map<String, Supplier<Transport>> getTransports(Settings settings, ThreadPool threadPool, PageCacheRecycler pageCacheRecycler,
                                                          CircuitBreakerService circuitBreakerService,
                                                          NamedWriteableRegistry namedWriteableRegistry, NetworkService networkService) {
        return Collections.singletonMap(SSLNettyTransport.TRANSPORT_NAME, () -> new SSLNettyTransport(settings, Version.CURRENT, threadPool, networkService, pageCacheRecycler, namedWriteableRegistry, circuitBreakerService, getSharedGroupFactory(settings)));
    }

    private SharedGroupFactory getSharedGroupFactory(Settings settings) {
        SharedGroupFactory groupFactory = this.groupFactory.get();
        if (groupFactory != null) {
            assert groupFactory.getSettings().equals(settings) : "Different settings than originally provided";
            return groupFactory;
        } else {
            this.groupFactory.set(new SharedGroupFactory(settings));
            return this.groupFactory.get();
        }
    }

    @Override
    public Settings additionalSettings() {
        return Settings.Builder.EMPTY_SETTINGS;
    }


}
