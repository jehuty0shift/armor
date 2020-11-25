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
package com.petalmd.armor;

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.petalmd.armor.util.ConfigConstants;
import org.apache.http.Header;
import org.apache.http.message.BasicHeader;
import org.elasticsearch.ElasticsearchStatusException;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthRequest;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.client.Request;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.ResponseException;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.client.indices.PutMappingRequest;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.index.reindex.BulkByScrollResponse;
import org.elasticsearch.index.reindex.ReindexRequest;
import org.elasticsearch.rest.RestStatus;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@RunWith(RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class MiscTest extends AbstractArmorTest {

    @Test
    public void unauthenticatedTest() throws Exception {

        final Settings settings = Settings
                .builder()
                .putList("armor.actionrequestfilter.names", "allow_all")
                .putList("armor.actionrequestfilter.allow_all.allowed_actions", "*")
                .put("armor.authentication.http_authenticator.impl",
                        "com.petalmd.armor.authentication.http.HTTPUnauthenticatedAuthenticator")
                .put("armor.authentication.authentication_backend.impl",
                        "com.petalmd.armor.authentication.backend.simple.AlwaysSucceedAuthenticationBackend")
                .build();

        startES(settings);

        username = null;
        password = null;

        setupTestData("ac_rules_3.json");
        final SearchResponse sResp = executeSearch("ac_query_matchall.json", new String[]{"internal"}, true,
                false);

        log.debug(sResp.toString());

    }

    @Test
    public void testClusterMonitorDisable() throws Exception {

        final Settings settings = Settings
                .builder()
                .putList("armor.actionrequestfilter.names", "allowHealth")
                .putList("armor.actionrequestfilter.allowHealth.allowed_actions", "cluster:monitor/health")
                .put("armor.allow_kibana_actions", false)
                .putList("armor.authentication.settingsdb.usercreds", "jacksonm@root:secret")
                .put("armor.authentication.authorizer.impl",
                        "com.petalmd.armor.authorization.simple.SettingsBasedAuthorizator")
                .put("armor.authentication.authorizer.cache.enable", "true")
                .put("armor.authentication.authentication_backend.impl",
                        "com.petalmd.armor.authentication.backend.simple.SettingsBasedAuthenticationBackend")
                .put("armor.authentication.authentication_backend.cache.enable", "true")
                .build();

        startES(settings);

        username = "jacksonm";
        password = "secret";

        setupTestData("ac_rules_execute_all.json");

        final RestHighLevelClient client = getRestClient(false, username, password);


        ResponseException nodesFailure = expectThrows(ResponseException.class, () -> client.getLowLevelClient().performRequest(new Request("GET", "_nodes")));


        Assert.assertEquals(403, nodesFailure.getResponse().getStatusLine().getStatusCode());
        Assert.assertTrue(new String(nodesFailure.getResponse().getEntity().getContent().readAllBytes()).contains("cluster:monitor/nodes"));

    }

    @Test
    public void testArmorIndexAttack() throws Exception {

        final Settings settings = Settings
                .builder()
                .put("armor.authentication.authorizer.impl",
                        "com.petalmd.armor.authorization.simple.SettingsBasedAuthorizator")
                .putList("armor.authentication.settingsdb.usercreds", "jacksonm@root:secret")
                .put("armor.authentication.authorizer.cache.enable", "true")
                .put("armor.authentication.authentication_backend.impl",
                        "com.petalmd.armor.authentication.backend.simple.SettingsBasedAuthenticationBackend")
                .put("armor.authentication.authentication_backend.cache.enable", "true")
                .putList("armor.actionrequestfilter.names", "readonly")
                .putList("armor.actionrequestfilter.readonly.allowed_actions", "indices:/data/read/search").build();

        startES(settings);
        username = "jacksonm";
        password = "secret";
        setupTestData("ac_rules_1.json");
        expectThrows(ElasticsearchStatusException.class, () -> executeIndex("ac_rules_1.json", "armor", "ac", false, false));
        executeIndex("ac_rules_1.json", "armor", "ac", true, true);
        expectThrows(ElasticsearchStatusException.class, () -> executeIndex("ac_rules_1.json", "armor", "xx", false, false));

        final RestHighLevelClient client = getRestClient(false, username, password);

        ElasticsearchStatusException failure = expectThrows(ElasticsearchStatusException.class, () -> client.indices().putMapping(new PutMappingRequest("_all").source("{" + "\"properties\" : {"
                + "\"rules\" : {\"type\" : \"keyword\", \"store\" : true }" + "}" + "}", XContentType.JSON), RequestOptions.DEFAULT));

        Assert.assertTrue(failure.status().equals(RestStatus.FORBIDDEN));
        log.debug(failure.getDetailedMessage());

    }


    @Test
    public void clusterHealth() throws Exception {
        final Settings settings = Settings
                .builder()
                .put("armor.authentication.authorizer.impl",
                        "com.petalmd.armor.authorization.simple.SettingsBasedAuthorizator")
                .putList("armor.authentication.settingsdb.usercreds", "jacksonm@root:secret")
                .put("armor.authentication.authorizer.cache.enable", "true")
                .put("armor.authentication.authentication_backend.impl",
                        "com.petalmd.armor.authentication.backend.simple.SettingsBasedAuthenticationBackend")
                .put("armor.authentication.authentication_backend.cache.enable", "true")
                .putList("armor.actionrequestfilter.names", "readonly")
                .putList("armor.actionrequestfilter.readonly.allowed_actions", "cluster:monitor*")
                .put("armor.aggregation_filter.enabled", true)
                .put("armor.action.cache.filter.enabled", true)
                .putList("armor.action.cache.filter.actions", "cluster:monitor/nodes/info*")
                .put("armor.allow_kibana_actions", false)
                .put("armor.obfuscation.filter.enabled", true)
                .putList("armor.obfuscation.filter.getindexresponse.remove", "aliases", "settings.index.routing.allocation.require.new_box_type", "settings.index.merge.scheduler.max_thread_count", "settings.index.merge.scheduler.max_merge_count")
                .put("armor.action.wildcard.expansion.enabled", true)
                .put("armor.indices.updatesettingsfilter.enabled", true)
                .putList("armor.indices.updatesettingsfilter.allowed_settings", "analysis", "index.refresh_interval")
                .build();

        startES(settings);
        username = "jacksonm";
        password = "secret";
        setupTestData("ac_rules_19.json");

        final RestHighLevelClient client = getRestClient(false, username, password);

        ClusterHealthResponse healthResp = client.cluster().health(new ClusterHealthRequest().timeout(TimeValue.timeValueSeconds(10)), RequestOptions.DEFAULT);

        Assert.assertFalse(healthResp.isTimedOut());
    }

    @Test
    public void clusterHealthNoIndices() throws Exception {
        final Settings settings = Settings
                .builder()
                .put("armor.authentication.authorizer.impl",
                        "com.petalmd.armor.authorization.simple.SettingsBasedAuthorizator")
                .putList("armor.authentication.settingsdb.usercreds", "jacksonm@root:secret")
                .put("armor.authentication.authorizer.cache.enable", "true")
                .put("armor.authentication.authentication_backend.impl",
                        "com.petalmd.armor.authentication.backend.simple.SettingsBasedAuthenticationBackend")
                .put("armor.authentication.authentication_backend.cache.enable", "true")
                .putList("armor.actionrequestfilter.names", "readonly")
                .putList("armor.actionrequestfilter.readonly.allowed_actions",
                        "cluster:monitor/main",
                        "cluster:monitor/state",
                        "cluster:monitor/health",
                        "cluster:monitor/nodes/info")
                .putList("armor.actionrequestfilter.readonly.forbidden_actions",
                        "cluster:admin*",
                        "cluster:monitor/nodes",
                        "cluster:monitor/nodes/hot_threads",
                        "cluster:monitor/nodes/liveness",
                        "cluster:monitor/nodes/stats",
                        "cluster:monitor/stats",
                        "cluster:monitor/task")
                .put("armor.aggregation_filter.enabled", true)
                .put("armor.action.cache.filter.enabled", true)
                .putList("armor.action.cache.filter.actions", "cluster:monitor/nodes/info*")
                .put("armor.allow_kibana_actions", false)
                .put("armor.obfuscation.filter.enabled", true)
                .putList("armor.obfuscation.filter.getindexresponse.remove", "aliases", "settings.index.routing.allocation.require.new_box_type", "settings.index.merge.scheduler.max_thread_count", "settings.index.merge.scheduler.max_merge_count")
                .put("armor.action.wildcard.expansion.enabled", true)
                .put("armor.indices.updatesettingsfilter.enabled", true)
                .putList("armor.indices.updatesettingsfilter.allowed_settings", "analysis", "index.refresh_interval")
                .build();

        startES(settings);
        username = "jacksonm";
        password = "secret";
        setupTestData("ac_rules_execute_all.json");

        final RestHighLevelClient client = getRestClient(false, username, password);

        ClusterHealthResponse healthResp = client.cluster().health(new ClusterHealthRequest().timeout(TimeValue.timeValueSeconds(10)), RequestOptions.DEFAULT);

        Assert.assertFalse(healthResp.isTimedOut());
    }

    @Test
    public void reindexTest() throws Exception {

        final boolean wrongPassword = false;
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");


        final Settings settings = Settings.builder()
                .putList("armor.actionrequestfilter.names", "reindex", "forbidden")
                .putList("armor.actionrequestfilter.reindex.allowed_actions",
                        "indices:data/read/*",
                        //"indices:admin/create",
                        "indices:data/write/reindex", //main action
                        "indices:data/write/bulk*", //bulk is needed due to reindex client
                        "indices:admin/mapping/put") //mapping is needed to update mapping to ES 5.6 new mapping
                .putList("armor.actionrequestfilter.forbidden.allowed_actions", "indices:data/read/scroll*")
                .put(ConfigConstants.ARMOR_ACTION_WILDCARD_EXPANSION_ENABLED, true)
                .put(authSettings).build();

        startES(settings);

        setupTestData("ac_rules_11.json");
        String source = "marketing";
        String dest = "marketing_backup";
        final RestHighLevelClient client = getRestClient(false, username, password);

        final BulkByScrollResponse reindexResponse = client.reindex(new ReindexRequest().setSourceIndices(source).setDestIndex(dest), RequestOptions.DEFAULT);

        Assert.assertTrue(reindexResponse.getBulkFailures().isEmpty());
        Assert.assertTrue(reindexResponse.getCreated() > 0);

    }


    @Test
    public void additionalRightsTest() throws Exception {

        final boolean wrongPassword = false;
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");


        final Settings settings = Settings.builder()
                .put(ConfigConstants.ARMOR_HTTP_ADDITIONAL_RIGHTS_HEADER + "kibana", "myreallyawesomekibanaheadervalue")
                .putList("armor.actionrequestfilter.names", "special", "forbidden")
                .putList("armor.actionrequestfilter.special.allowed_actions",
                        "indices:data/read/*",
                        "kibana:indices:data/write*", //this right is needed to write
                        "kibana:indices:admin/mapping/put",
                        "kibana:indices:admin/mapping/auto_put"
                        ) //mapping is needed to update mapping to ES 5.6 new mapping
                .putList("armor.actionrequestfilter.forbidden.allowed_actions", "indices:data/read/scroll*")
                .put(ConfigConstants.ARMOR_ACTION_WILDCARD_EXPANSION_ENABLED, true)
                .put(authSettings).build();

        startES(settings);

        setupTestData("ac_rules_20.json");
        //without the magic header the call must failed
        final RestHighLevelClient client = getRestClient(false, username, password);

        ElasticsearchStatusException iFail1 = expectThrows(ElasticsearchStatusException.class, () -> client.index( new IndexRequest().index("marketing").id("tp_id6").source("{\"test_user\":\"toto\"}",XContentType.JSON),RequestOptions.DEFAULT));

        Assert.assertTrue(iFail1.status().equals(RestStatus.FORBIDDEN));

        //with the magic header now it should be allowed
        List<Header> headerList = new ArrayList<>(Arrays.asList(headers));

        headerList.add(new BasicHeader("kibana","myreallyawesomekibanaheadervalue"));

        headers = headerList.toArray(new Header[headerList.size()]);

        final RestHighLevelClient client2 = getRestClient(false, username, password);
        IndexResponse iresp = client2.index( new IndexRequest().index("marketing").id("tp_id6").source("{\"test_user\":\"toto\"}",XContentType.JSON),RequestOptions.DEFAULT);
        Assert.assertTrue(iresp.status().equals(RestStatus.CREATED));

    }


}
