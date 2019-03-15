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
import com.petalmd.armor.http.DefaultSessionStore;
import com.petalmd.armor.http.NullSessionStore;
import com.petalmd.armor.http.SessionStore;
import com.petalmd.armor.http.netty.SSLNettyHttpServerTransport;
import com.petalmd.armor.rest.ArmorInfoAction;
import com.petalmd.armor.rest.ArmorRestShield;
import com.petalmd.armor.service.ArmorConfigService;
import com.petalmd.armor.service.ArmorService;
import com.petalmd.armor.util.ArmorConstants;
import com.petalmd.armor.util.ConfigConstants;
import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.action.support.ActionFilter;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.node.DiscoveryNodes;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.logging.ESLoggerFactory;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.*;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.http.HttpServerTransport;
import org.elasticsearch.indices.breaker.CircuitBreakerService;
import org.elasticsearch.plugins.ActionPlugin;
import org.elasticsearch.plugins.NetworkPlugin;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestHandler;
import org.elasticsearch.script.ScriptService;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.watcher.ResourceWatcherService;

import java.lang.reflect.InvocationTargetException;
import java.util.*;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;

//TODO FUTURE store users/roles also in elasticsearch armor index
//TODO FUTURE Multi authenticator/authorizator
//TODO FUTURE special handling scroll searches
//TODO FUTURE negative rules/users in acrules
//TODO update some settings during runtime
public final class ArmorPlugin extends Plugin implements ActionPlugin, NetworkPlugin {

    private static final String ARMOR_DEBUG = "armor.debug";
    private static final String CLIENT_TYPE = "client.type";
    private static final String HTTP_TYPE = "http.type";
    private static final String TRANSPORT_TYPE = "transport.type";

    private static final Logger log = ESLoggerFactory.getLogger(ArmorPlugin.class);
    private final boolean enabled;
    private final boolean clientBool;
    private final Settings settings;

    private ArmorService armorService;
    private ArmorRestShield armorRestShield;
    private ArmorConfigService armorConfigService;
    private AuditListener auditListener;
    private Authorizator authorizator;
    private AuthenticationBackend authenticationBackend;
    private ClusterService clusterService;
    private Client client;
    private HTTPAuthenticator httpAuthenticator;
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
        enabled = this.settings.getAsBoolean(ConfigConstants.ARMOR_ENABLED, true);
        clientBool = !"node".equals(this.settings.get(ArmorPlugin.CLIENT_TYPE, "node"));
    }


    @Override
    public Collection<Object> createComponents(Client client, ClusterService clusterService, ThreadPool threadPool, ResourceWatcherService resourceWatcherService, ScriptService scriptService, NamedXContentRegistry xContentRegistry) {


        List<Object> componentsList = new ArrayList<Object>();

        if (!enabled) {
            return componentsList;
        }

        this.clusterService = clusterService;
        this.client = client;
        this.threadPool = threadPool;

        final Class<? extends HTTPAuthenticator> defaultHTTPAuthenticatorClass = HTTPBasicAuthenticator.class;
        final Class<? extends NonCachingAuthorizator> defaultNonCachingAuthorizatorClass = SettingsBasedAuthorizator.class;
        final Class<? extends NonCachingAuthenticationBackend> defaultNonCachingAuthenticationClass = SettingsBasedAuthenticationBackend.class;

        //create Authenticator
        try {
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
        } catch (InstantiationException| IllegalAccessException | IllegalArgumentException | InvocationTargetException |NoSuchMethodException| ClassNotFoundException | SecurityException e) {
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
        } catch (InstantiationException| IllegalAccessException | IllegalArgumentException | InvocationTargetException |NoSuchMethodException| ClassNotFoundException | SecurityException e) {
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

        } catch (InstantiationException| IllegalAccessException | IllegalArgumentException | InvocationTargetException |NoSuchMethodException| ClassNotFoundException | SecurityException e) {
            log.error("Unable to instantiate the HTTP Authenticator Class ! ! ", e);
        }
        componentsList.add(httpAuthenticator);


        //create sessionStore
        Boolean enableHTTPSession = settings.getAsBoolean(ConfigConstants.ARMOR_HTTP_ENABLE_SESSIONS, false);
        if (enableHTTPSession != null && enableHTTPSession.booleanValue()) {
            sessionStore = new DefaultSessionStore();
        } else {
            sessionStore = new NullSessionStore();
        }
        componentsList.add(sessionStore);

        //create auditLog
        Boolean enableAuditLog = settings.getAsBoolean(ConfigConstants.ARMOR_AUDITLOG_ENABLED, true);
        if (enableAuditLog.booleanValue()) {
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
        armorConfigService = new ArmorConfigService(settings, client);
        componentsList.add(armorConfigService);

        log.info("added " + componentsList.size() + " number of components.");
        log.info(authenticationBackend.getClass().getName());
        return componentsList;

    }

    @Override
    public List<Class<? extends ActionFilter>> getActionFilters() {
        List<Class<? extends ActionFilter>> actionFilters = new ArrayList<>();
        if (!clientBool) {
            actionFilters.add(ArmorActionFilter.class);
            actionFilters.add(ObfuscationFilter.class);
            actionFilters.add(AggregationFilter.class);
            actionFilters.add(IndicesUpdateSettingsFilter.class);
            actionFilters.add(RequestActionFilter.class);
            actionFilters.add(ActionCacheFilter.class);
            actionFilters.add(DLSActionFilter.class);
            actionFilters.add(FLSActionFilter.class);
        }

        return actionFilters;
    }

    @Override
    public List<RestHandler> getRestHandlers(Settings settings, RestController restController, ClusterSettings clusterSettings, IndexScopedSettings indexScopedSettings, SettingsFilter settingsFilter, IndexNameExpressionResolver indexNameExpressionResolver, Supplier<DiscoveryNodes> nodesInCluster) {

        if (!enabled) {
            return Collections.emptyList();
        } else {
            return Collections.singletonList(new ArmorInfoAction(settings, restController, Objects.requireNonNull(armorService)));
        }
    }


    @Override
    public Collection<String> getRestHeaders() {
        if (!enabled) {
            return Collections.emptyList();
        } else {
            List<String> headerList = new ArrayList<String>();
            headerList.add(ArmorConstants.ARMOR_AUTHENTICATED_USER);
            headerList.add(ArmorConstants.ARMOR_AUTHENTICATED_TRANSPORT_REQUEST);
            headerList.add(ArmorConstants.ARMOR_TRANSPORT_CREDS);

            return headerList;

        }
    }

    @Override
    public UnaryOperator<RestHandler> getRestHandlerWrapper(ThreadContext threadContext) {
        return (rh) -> armorRestShield.shield(rh);
    }

    @Override
    public List<Setting<?>> getSettings() {
        List<Setting<?>> settings = new ArrayList<>();

        //Generic Armor settings
        settings.add(Setting.simpleString(ConfigConstants.DEFAULT_SECURITY_CONFIG_INDEX, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_CONFIG_INDEX_NAME, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_ENABLED, true, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_ALLOW_ALL_FROM_LOOPBACK, true, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_ALLOW_NON_LOOPBACK_QUERY_ON_ARMOR_INDEX, false, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_ALLOW_KIBANA_ACTIONS, true, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_AUDITLOG_ENABLED, true, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_TRANSPORT_AUTH_ENABLED, false, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_HTTP_ENABLE_SESSIONS, false, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_HTTP_XFORWARDEDFOR_ENFORCE, false, Setting.Property.NodeScope, Setting.Property.Filtered));
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

        //ssl HTTP
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_SSL_TRANSPORT_HTTP_ENABLED, false, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_SSL_TRANSPORT_HTTP_ENFORCE_CLIENTAUTH, false, Setting.Property.NodeScope, Setting.Property.Filtered));
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

        //ldap backend
        settings.add(Setting.boolSetting(ConfigConstants.ARMOR_AUTHENTICATION_AUTHORIZATION_LDAP_RESOLVE_NESTED_ROLES, false, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUTHENTICATION_AUTHORIZATION_LDAP_ROLEBASE, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUTHENTICATION_AUTHORIZATION_LDAP_ROLESEARCH, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUTHENTICATION_LDAP_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.groupSetting(ConfigConstants.ARMOR_AUTHENTICATION_LDAP_HOSTS, Setting.Property.NodeScope));
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
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUTHENTICATION_AUTHORIZATION_LDAP_USERROLEATTRIBUTE, Setting.Property.NodeScope, Setting.Property.Filtered));
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_AUTHENTICATION_AUTHORIZATION_LDAP_USERROLENAME, Setting.Property.NodeScope, Setting.Property.Filtered));

        //WAFFLE
        settings.add(Setting.simpleString(ConfigConstants.ARMOR_WAFFLE_WINDOWS_AUTH_PROVIDER_IMPL, Setting.Property.NodeScope, Setting.Property.Filtered));


        return settings;
    }


    @Override
    public Map<String, Supplier<HttpServerTransport>> getHttpTransports(Settings settings, ThreadPool threadPool, BigArrays bigArrays, CircuitBreakerService circuitBreakerService, NamedWriteableRegistry namedWriteableRegistry, NamedXContentRegistry xContentRegistry, NetworkService networkService, HttpServerTransport.Dispatcher dispatcher) {
        return Collections.singletonMap("armor_ssl_netty4",() -> new SSLNettyHttpServerTransport(settings,networkService,bigArrays,threadPool,xContentRegistry,dispatcher));
    }

    @Override
    public Settings additionalSettings() {
        return Settings.Builder.EMPTY_SETTINGS;
    }

    private void checkSSLConfig() {
        if (settings.getAsBoolean(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_ENABLED, false)) {
            final String keystoreFilePath = settings.get(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_KEYSTORE_FILEPATH,
                    System.getProperty("javax.net.ssl.keyStore", null));
            final String truststoreFilePath = settings.get(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_TRUSTSTORE_FILEPATH,
                    System.getProperty("javax.net.ssl.trustStore", null));

            if (StringUtils.isBlank(keystoreFilePath) || StringUtils.isBlank(truststoreFilePath)) {
                throw new ElasticsearchException(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_KEYSTORE_FILEPATH + " and "
                        + ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_TRUSTSTORE_FILEPATH + " must be set if transport ssl is requested.");
            }
        }

        if (settings.getAsBoolean(ConfigConstants.ARMOR_SSL_TRANSPORT_HTTP_ENABLED, false)) {
            final String keystoreFilePath = settings.get(ConfigConstants.ARMOR_SSL_TRANSPORT_HTTP_KEYSTORE_FILEPATH,
                    System.getProperty("javax.net.ssl.keyStore", null));
            final String truststoreFilePath = settings.get(ConfigConstants.ARMOR_SSL_TRANSPORT_HTTP_TRUSTSTORE_FILEPATH,
                    System.getProperty("javax.net.ssl.trustStore", null));

            if (StringUtils.isBlank(keystoreFilePath) || StringUtils.isBlank(truststoreFilePath)) {
                throw new ElasticsearchException(ConfigConstants.ARMOR_SSL_TRANSPORT_HTTP_KEYSTORE_FILEPATH + " and "
                        + ConfigConstants.ARMOR_SSL_TRANSPORT_HTTP_TRUSTSTORE_FILEPATH + " must be set if https is requested.");
            }
        }

    }


}
