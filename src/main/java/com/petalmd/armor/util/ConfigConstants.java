/*
 * Copyright 2015 PetalMD
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *  
 */

package com.petalmd.armor.util;

public final class ConfigConstants {
    public static final String DEFAULT_SECURITY_CONFIG_INDEX = "armor";
    public static final String ARMOR_ACTIONREQUESTFILTER = "armor.actionrequestfilter.names";
    public static final String ARMOR_ACTIONREQUESTFILTERS = "armor.actionrequestfilter.";
    public static final String ARMOR_ALLOW_ALL_FROM_LOOPBACK = "armor.allow_all_from_loopback";
    public static final String ARMOR_ALLOW_NON_LOOPBACK_QUERY_ON_ARMOR_INDEX = "armor.allow_non_loopback_query_on_armor_index";
    public static final String ARMOR_ALLOW_KIBANA_ACTIONS = "armor.allow_kibana_actions";
    public static final String ARMOR_AUDITLOG_ENABLED = "armor.auditlog.enabled";
    public static final String ARMOR_TRANSPORT_AUTH_ENABLED = "armor.transport_auth.enabled";
    public static final String ARMOR_AGGREGATION_FILTER_ENABLED = "armor.aggregation_filter.enabled";
    public static final String ARMOR_ACTION_WILDCARD_EXPANSION_ENABLED = "armor.action.wildcard.expansion.enabled";
    public static final String ARMOR_ACTION_CACHE_ENABLED = "armor.action.cache.filter.enabled";
    public static final String ARMOR_ACTION_CACHE_LIST = "armor.action.cache.filter.actions";
    public static final String ARMOR_ACTION_INDICES_LIKE_ALIASES = "armor.action.indices.like.aliases";
    public static final String ARMOR_AUDITLOG_NUM_REPLICAS = "armor.auditlog.number_of_replicas";
    public static final String ARMOR_AUDITLOG_COMPRESSION = "armor.auditlog.compression";
    public static final String ARMOR_AUTHENTICATION_AUTHENTICATION_BACKEND = "armor.authentication.authentication_backend.impl";
    public static final String ARMOR_AUTHENTICATION_AUTHENTICATION_BACKEND_CACHE_ENABLE = "armor.authentication.authentication_backend.cache.enable";
    public static final String ARMOR_AUTHENTICATION_AUTHORIZATION_MULTI_BACKEND_LIST = "armor.authentication.authorization.multi.auth.backends";
    public static final String ARMOR_AUTHENTICATION_AUTHORIZATION_LDAP_RESOLVE_NESTED_ROLES = "armor.authentication.authorization.ldap.resolve_nested_roles";
    public static final String ARMOR_AUTHENTICATION_AUTHORIZATION_LDAP_ROLEBASE = "armor.authentication.authorization.ldap.rolebase";
    public static final String ARMOR_AUTHENTICATION_AUTHORIZATION_LDAP_ROLENAME = "armor.authentication.authorization.ldap.rolename";
    public static final String ARMOR_AUTHENTICATION_AUTHORIZATION_LDAP_ROLESEARCH = "armor.authentication.authorization.ldap.rolesearch";
    public static final String ARMOR_AUTHENTICATION_AUTHORIZATION_LDAP_USERROLEATTRIBUTE = "armor.authentication.authorization.ldap.userroleattribute";
    public static final String ARMOR_AUTHENTICATION_AUTHORIZATION_LDAP_USERROLENAME = "armor.authentication.authorization.ldap.userrolename";
    public static final String ARMOR_AUTHENTICATION_AUTHORIZATION_SETTINGSDB_ROLES = "armor.authentication.authorization.settingsdb.roles.";
    public static final String ARMOR_AUTHENTICATION_AUTHORIZATOR = "armor.authentication.authorizer.impl";
    public static final String ARMOR_AUTHENTICATION_AUTHORIZATOR_CACHE_ENABLE = "armor.authentication.authorizer.cache.enable";
    public static final String ARMOR_AUTHENTICATION_GRAYLOG_ENDPOINT = "armor.authentication.graylog.endpoint";
    public static final String ARMOR_AUTHENTICATION_HTTP_AUTHENTICATOR = "armor.authentication.http_authenticator.impl";
    public static final String ARMOR_AUTHENTICATION_HTTPS_CLIENTCERT_ATTRIBUTENAME = "armor.authentication.https.clientcert.attributename";
    public static final String ARMOR_AUTHENTICATION_LDAP_BIND_DN = "armor.authentication.ldap.bind_dn";
    public static final String ARMOR_AUTHENTICATION_LDAP_HOST = "armor.authentication.ldap.host";
    public static final String ARMOR_AUTHENTICATION_LDAP_LDAPS_SSL_ENABLED = "armor.authentication.ldap.ldaps.ssl.enabled";
    public static final String ARMOR_AUTHENTICATION_LDAP_LDAPS_STARTTLS_ENABLED = "armor.authentication.ldap.ldaps.starttls.enabled";
    public static final String ARMOR_AUTHENTICATION_LDAP_LDAPS_TRUSTSTORE_FILEPATH = "armor.authentication.ldap.ldaps.truststore_filepath";
    public static final String ARMOR_AUTHENTICATION_LDAP_LDAPS_TRUSTSTORE_PASSWORD = "armor.authentication.ldap.ldaps.truststore_password";
    public static final String ARMOR_AUTHENTICATION_LDAP_LDAPS_TRUSTSTORE_TYPE = "armor.authentication.ldap.ldaps.truststore_type";
    public static final String ARMOR_AUTHENTICATION_LDAP_PASSWORD = "armor.authentication.ldap.password";
    public static final String ARMOR_AUTHENTICATION_LDAP_USERBASE = "armor.authentication.ldap.userbase";
    public static final String ARMOR_AUTHENTICATION_LDAP_USERNAME_ATTRIBUTE = "armor.authentication.ldap.username_attribute";
    public static final String ARMOR_AUTHENTICATION_LDAP_USERSEARCH = "armor.authentication.ldap.usersearch";
    public static final String ARMOR_AUTHENTICATION_LDAP_MAX_ACTIVE_CONNECTIONS = "armor.authentication.ldap.max_active_connections";
    public static final String ARMOR_AUTHENTICATION_MULTI_AUTH_BACKEND_LIST = "armor.authentication.multi.auth.backends";
    public static final String ARMOR_AUTHENTICATION_PROXY_HEADER = "armor.authentication.proxy.header";
    public static final String ARMOR_AUTHENTICATION_PROXY_TRUSTED_IPS = "armor.authentication.proxy.trusted_ips";
    public static final String ARMOR_AUTHENTICATION_SETTINGSDB_DIGEST = "armor.authentication.settingsdb.digest";
    public static final String ARMOR_AUTHENTICATION_SETTINGSDB_USER = "armor.authentication.settingsdb.user.";
    public static final String ARMOR_AUTHENTICATION_SETTINGSDB_USERCREDS = "armor.authentication.settingsdb.usercreds";
    public static final String ARMOR_AUTHENTICATION_SPNEGO_KRB5_CONFIG_FILEPATH = "armor.authentication.spnego.krb5_config_filepath";
    public static final String ARMOR_AUTHENTICATION_SPNEGO_LOGIN_CONFIG_FILEPATH = "armor.authentication.spnego.login_config_filepath";
    public static final String ARMOR_AUTHENTICATION_SPNEGO_LOGIN_CONFIG_NAME = "armor.authentication.spnego.login_config_name";
    public static final String ARMOR_AUTHENTICATION_SPNEGO_STRIP_REALM = "armor.authentication.spnego.strip_realm";
    public static final String ARMOR_AUTHENTICATION_WAFFLE_STRIP_DOMAIN = "armor.authentication.waffle.strip_domain";
    public static final String ARMOR_CONFIG_INDEX_NAME = "armor.config_index_name";
    public static final String ARMOR_DLSFILTER = "armor.dlsfilter.names";
    public static final String ARMOR_DLSFILTERS = "armor.dlsfilter.";
    public static final String ARMOR_ENABLED = "armor.enabled";
    public static final String ARMOR_FLSFILTER = "armor.flsfilter.names";
    public static final String ARMOR_FLSFILTERS = "armor.flsfilter.";
    public static final String ARMOR_HTTP_ADDITIONAL_RIGHTS_HEADER = "armor.http.additionalrights.header.";
    public static final String ARMOR_HTTP_ENABLE_SESSIONS = "armor.http.enable_sessions";
    public static final String ARMOR_HTTP_XFORWARDEDFOR_ENFORCE = "armor.http.xforwardedfor.enforce";
    public static final String ARMOR_HTTP_XFORWARDEDFOR_HEADER = "armor.http.xforwardedfor.header";
    public static final String ARMOR_HTTP_XFORWARDEDFOR_TRUSTEDPROXIES = "armor.http.xforwardedfor.trustedproxies";
    public static final String ARMOR_INDICES_UPDATESETTINGSFILTER_ENABLED = "armor.indices.updatesettingsfilter.enabled";
    public static final String ARMOR_INDICES_UPDATESETTINGSFILTER_ALLOWED = "armor.indices.updatesettingsfilter.allowed_settings";
    public static final String ARMOR_ALIAS_LIFECYCLE_ENABLED = "armor.alias_lifecycle.filter.enabled";
    public static final String ARMOR_ALIAS_LIFECYCLE_MAX_NUM_OF_ALIAS_BY_USER = "armor.alias_lifecycle.filter.max_num_of_alias_by_user";
    public static final String ARMOR_ALIAS_LIFECYCLE_MAX_NUM_OF_INDICES_BY_ALIAS = "armor.alias_lifecycle.filter.max_num_of_indices_by_alias";
    public static final String ARMOR_INDEX_LIFECYCLE_ENABLED = "armor.index_lifecycle.filter.enabled";
    public static final String ARMOR_INDEX_LIFECYCLE_ALLOWED_SETTINGS = "armor.index_lifecycle.filter.allowed_settings";
    public static final String ARMOR_INDEX_LIFECYCLE_MAX_NUM_OF_SHARDS_BY_USER = "armor.index_lifecycle.filter.max_num_of_shards_by_user";
    public static final String ARMOR_INDEX_LIFECYCLE_MAX_NUM_OF_SHARDS_BY_INDEX = "armor.index_lifecycle.filter.max_num_of_shards_by_index";
    public static final String ARMOR_INDEX_LIFECYCLE_MAX_NUM_OF_REPLICAS_BY_INDEX = "armor.index_lifecycle.filter.max_num_of_replicas_by_index";
    public static final String ARMOR_INGEST_PIPELINE_FILTER_ENABLED = "armor.ingest.pipeline.filter_enabled";
    public static final String ARMOR_KIBANA_HELPER_ENABLED = "armor.kibana.filter.enabled";
    public static final String ARMOR_KEFLA_FILTER_ENABLED = "armor.kefla.filter.enabled";
    public static final String ARMOR_KEFLA_PLUGIN_ENDPOINT = "armor.kefla.plugin.graylog.endpoint";
    public static final String ARMOR_KEFLA_PLUGIN_USER = "armor.kefla.plugin.user";
    public static final String ARMOR_KEFLA_PLUGIN_PASSWORD = "armor.kefla.plugin.password";
    public static final String ARMOR_KEY_PATH = "armor.key_path";
    public static final String ARMOR_LDP_INDEX = "armor.ldp_index";
    public static final String ARMOR_LDP_FILTER_ENABLED = "armor.ldp_filter.enabled";
    public static final String ARMOR_LDP_FILTER_LDP_PIPELINE_NAME = "armor.ldp_filter.ldp_pipeline_name";
    public static final String ARMOR_LDP_PROCESSOR_KAFKA_ACKS_CONFIG = "armor.ldp_processor.kafka.acks_config";
    public static final String ARMOR_LDP_PROCESSOR_KAFKA_BOOTSTRAP_SERVERS = "armor.ldp_processor.kafka.bootstrap_servers";
    public static final String ARMOR_LDP_PROCESSOR_KAFKA_CLIENT_ID = "armor.ldp_processor.kafka.client_id";
    public static final String ARMOR_LDP_PROCESSOR_KAFKA_COMPRESSION_CODEC = "armor.ldp_processor.kafka.compression_codec";
    public static final String ARMOR_LDP_PROCESSOR_KAFKA_BATCH_SIZE = "armor.ldp_processor.kafka.batch_size";
    public static final String ARMOR_LDP_PROCESSOR_KAFKA_LINGER_MS = "armor.ldp_processor.kafka.linger_ms";
    public static final String ARMOR_LDP_PROCESSOR_KAFKA_ENABLED = "armor.ldp_processor.kafka.enabled";
    public static final String ARMOR_LDP_PROCESSOR_KAFKA_TOPIC = "armor.ldp_processor.kafka.topic";
    public static final String ARMOR_LDP_PROCESSOR_KAFKA_OUTPUT_USE_KAFKA_IMPL = "armor.ldp_processor.kafka_output.use_kafka_impl";
    public static final String ARMOR_MONGODB_URI = "armor.mongodb.uri";
    public static final String ARMOR_MONGODB_ENGINE_DATABASE = "armor.mongo.engine_database";
    public static final String ARMOR_MONGODB_GRAYLOG_DATABASE = "armor.mongo.graylog_database";
    public static final String ARMOR_KAFKA_ENGINE_SERVICE_ENABLED = "armor.kafka_engine.enabled";
    public static final String ARMOR_KAFKA_ENGINE_SERVICE_CLIENT_ID = "armor.kafka_engine.client_id";
    public static final String ARMOR_KAFKA_ENGINE_SERVICE_PRIVATE_KEY = "armor.kafka_engine.private_key";
    public static final String ARMOR_KAFKA_ENGINE_SERVICE_TOPIC_SUFFIX = "armor.kafka_engine.topic_suffix";
    public static final String ARMOR_KAFKA_ENGINE_SERVICE_TOPIC_REGIONS = "armor.kafka_engine.topic_regions";
    public static final String ARMOR_OBFUSCATION_FILTER_ENABLED = "armor.obfuscation.filter.enabled";
    public static final String ARMOR_OBFUSCATION_FILTERS = "armor.obfuscation.filter.";
    public static final String ARMOR_REWRITE_GET_AS_SEARCH = "armor.rewrite_get_as_search";
    public static final String ARMOR_SCROLL_CLEAR_ALLOW_ALL = "armor.scroll_clear.allow_all";
    public static final String ARMOR_INDEX_TEMPLATE_FILTER_ENABLED = "armor.index_template.filter.enabled";
    public static final String ARMOR_INDEX_TEMPLATE_FILTER_ALLOWED_SETTINGS = "armor.index_template.filter.allowed_settings";
    public static final String ARMOR_SSL_TRANSPORT_HTTP_ENABLED = "armor.ssl.transport.http.enabled";
    public static final String ARMOR_SSL_TRANSPORT_HTTP_ENFORCE_CLIENTAUTH = "armor.ssl.transport.http.enforce_clientauth";
    public static final String ARMOR_SSL_TRANSPORT_HTTP_KEEP_ALIVE_ENABLED = "armor.ssl.transport.http.keep_alive_enabled";
    public static final String ARMOR_SSL_TRANSPORT_HTTP_KEYSTORE_FILEPATH = "armor.ssl.transport.http.keystore_filepath";
    public static final String ARMOR_SSL_TRANSPORT_HTTP_KEYSTORE_PASSWORD = "armor.ssl.transport.http.keystore_password";
    public static final String ARMOR_SSL_TRANSPORT_HTTP_KEYSTORE_TYPE = "armor.ssl.transport.http.keystore_type";
    public static final String ARMOR_SSL_TRANSPORT_HTTP_TRUSTSTORE_FILEPATH = "armor.ssl.transport.http.truststore_filepath";
    public static final String ARMOR_SSL_TRANSPORT_HTTP_TRUSTSTORE_PASSWORD = "armor.ssl.transport.http.truststore_password";
    public static final String ARMOR_SSL_TRANSPORT_HTTP_TRUSTSTORE_TYPE = "armor.ssl.transport.http.truststore_type";
    public static final String ARMOR_SSL_TRANSPORT_NODE_ENABLED = "armor.ssl.transport.node.enabled";
    public static final String ARMOR_SSL_TRANSPORT_NODE_ENFORCE_HOSTNAME_VERIFICATION = "armor.ssl.transport.node.enforce_hostname_verification";
    public static final String ARMOR_SSL_TRANSPORT_NODE_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME = "armor.ssl.transport.node.enforce_hostname_verification.resolve_host_name";
    public static final String ARMOR_SSL_TRANSPORT_NODE_ENFORCE_CLIENTAUTH = "armor.ssl.transport.node.enforce_clientauth";
    public static final String ARMOR_SSL_TRANSPORT_NODE_KEYSTORE_FILEPATH = "armor.ssl.transport.node.keystore_filepath";
    public static final String ARMOR_SSL_TRANSPORT_NODE_KEYSTORE_PASSWORD = "armor.ssl.transport.node.keystore_password";
    public static final String ARMOR_SSL_TRANSPORT_NODE_KEYSTORE_TYPE = "armor.ssl.transport.node.keystore_type";
    public static final String ARMOR_SSL_TRANSPORT_NODE_TRUSTSTORE_FILEPATH = "armor.ssl.transport.node.truststore_filepath";
    public static final String ARMOR_SSL_TRANSPORT_NODE_TRUSTSTORE_PASSWORD = "armor.ssl.transport.node.truststore_password";
    public static final String ARMOR_SSL_TRANSPORT_NODE_TRUSTSTORE_TYPE = "armor.ssl.transport.node.truststore_type";
    public static final String ARMOR_WAFFLE_WINDOWS_AUTH_PROVIDER_IMPL = "armor.waffle.windows_auth_provider_impl";

    private ConfigConstants() {
    }
}

