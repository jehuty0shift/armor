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
import com.google.common.collect.ImmutableMap;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.petalmd.armor.util.ConfigConstants;
import io.searchbox.client.JestClient;
import io.searchbox.client.JestResult;
import io.searchbox.cluster.Health;
import io.searchbox.cluster.NodesStats;
import io.searchbox.core.Index;
import io.searchbox.indices.mapping.PutMapping;
import io.searchbox.indices.reindex.Reindex;
import org.apache.http.HttpResponse;
import org.apache.http.entity.ContentType;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Map;

@RunWith(RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class MiscTest extends AbstractUnitTest {

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
        final Tuple<JestResult, HttpResponse> resulttu = executeSearch("ac_query_matchall.json", new String[]{"internal"}, null, true,
                false);

        final JestResult result = resulttu.v1();

        final Gson gson = new GsonBuilder().setPrettyPrinting().create();
        final Map json = gson.fromJson(result.getJsonString(), Map.class);
        log.debug(gson.toJson(json));

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
        executeIndex("ac_rules_execute_all.json", "armor", "ac", "ac", true, true);

        final JestClient client = getJestClient(getServerUri(false), username, password);

        final JestResult jr = client.execute(new NodesStats.Builder().setHeader(headers).build());

        log.debug(jr.getErrorMessage());
        Assert.assertNotNull(jr.getErrorMessage());
        Assert.assertTrue(jr.getErrorMessage().contains("cluster:monitor"));

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
        executeIndex("ac_rules_1.json", "armor", "ac", "ac", false, false);
        executeIndex("ac_rules_1.json", "armor", "ac", "ac", true, true);
        executeIndex("ac_rules_1.json", "armor", "xx", "xx", false, false);

        final JestClient client = getJestClient(getServerUri(false), username, password);


        headers.put("Content-Type", ContentType.APPLICATION_JSON);
        final JestResult jr = client.execute(new PutMapping.Builder("_all", "ac", "{" + "\"properties\" : {"
                + "\"rules\" : {\"type\" : \"keyword\", \"store\" : true }" + "}" + "}"
        ).setHeader(headers).build());

        Assert.assertTrue(!jr.isSucceeded());
        Assert.assertNotNull(jr.getErrorMessage());
        log.debug(jr.getErrorMessage());

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

        final JestClient client = getJestClient(getServerUri(false), username, password);

        Tuple<JestResult, HttpResponse> jResult = ((HeaderAwareJestHttpClient) client).executeE(new Health.Builder().timeout(10).build());

        Assert.assertEquals(jResult.v2().getStatusLine().getStatusCode(), 200);
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

        final JestClient client = getJestClient(getServerUri(false), username, password);

        Tuple<JestResult, HttpResponse> jResult = ((HeaderAwareJestHttpClient) client).executeE(new Health.Builder().timeout(10).build());

        Assert.assertEquals(jResult.v2().getStatusLine().getStatusCode(), 200);
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
                        "indices:data/write/reindex", //main action
                        "indices:data/write/bulk*", //bulk is needed due to reindex client
                        "indices:admin/mapping/put") //mapping is needed to update mapping to ES 5.6 new mapping
                .putList("armor.actionrequestfilter.forbidden.allowed_actions", "indices:data/read/scroll*")
                .put(ConfigConstants.ARMOR_ACTION_WILDCARD_EXPANSION_ENABLED, true)
                .put(authSettings).build();

        startES(settings);

        setupTestData("ac_rules_11.json");
        ImmutableMap<String, String> source = ImmutableMap.of("index", "marketing");
        ImmutableMap<String, String> dest = ImmutableMap.of("index", "marketing_backup");
        final JestClient client = getJestClient(getServerUri(false), username, password);

        Reindex reindex = new Reindex.Builder(source, dest).refresh(false).setHeader("Content-Type", ContentType.APPLICATION_JSON).build();
        final JestResult jr = client.execute(reindex);

        Assert.assertTrue(jr.isSucceeded());

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
                        "kibana:indices:admin/mapping/put") //mapping is needed to update mapping to ES 5.6 new mapping
                .putList("armor.actionrequestfilter.forbidden.allowed_actions", "indices:data/read/scroll*")
                .put(ConfigConstants.ARMOR_ACTION_WILDCARD_EXPANSION_ENABLED, true)
                .put(authSettings).build();

        startES(settings);

        setupTestData("ac_rules_20.json");
        //without the magic header the call must failed
        final JestClient client = getJestClient(getServerUri(false), username, password);


        final JestResult jr = client.execute(new Index.Builder("{\"test_user\":\"toto\"}").index("marketing").type("flyer").id("tp_id6").setHeader("Content-Type", ContentType.APPLICATION_JSON).build());

        Assert.assertTrue(!jr.isSucceeded());
        Assert.assertTrue(jr.getResponseCode() == 403);

        //with the magic header now it should be allowed
        final JestResult jr2 = client.execute(new Index.Builder("{\"test_user\":\"toto\"}").index("marketing").type("flyer").id("tp_id6").setHeader("Content-Type", ContentType.APPLICATION_JSON).setHeader("kibana", "myreallyawesomekibanaheadervalue").build());

        Assert.assertTrue(jr2.isSucceeded());
        Assert.assertTrue(jr2.getResponseCode() == 201);

    }


}
