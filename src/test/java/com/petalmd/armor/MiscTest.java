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

import com.google.common.collect.ImmutableMap;
import com.petalmd.armor.util.ConfigConstants;
import io.searchbox.client.JestClient;
import io.searchbox.client.JestResult;
import io.searchbox.indices.mapping.PutMapping;

import java.util.Map;

import io.searchbox.indices.reindex.Reindex;
import org.apache.http.HttpResponse;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import io.searchbox.cluster.NodesStats;

public class MiscTest extends AbstractUnitTest {

    @Test
    public void checkDLSFLS() throws Exception {
        Assert.assertTrue(ArmorPlugin.DLS_SUPPORTED);
    }

    @Test
    public void unauthenticatedTest() throws Exception {

        final Settings settings = Settings
                .builder()
                .putArray("armor.restactionfilter.names", "readonly")
                .putArray("armor.restactionfilter.readonly.allowed_actions", "*")
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
                .putArray("armor.actionrequestfilter.names", "allowHealth")
                .putArray("armor.actionrequestfilter.allowHealth.allowed_actions", "cluster:monitor/health")
                .put("armor.allow_kibana_actions", false)
                .putArray("armor.authentication.settingsdb.usercreds", "jacksonm@root:secret")
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
                .putArray("armor.authentication.settingsdb.usercreds", "jacksonm@root:secret")
                .put("armor.authentication.authorizer.cache.enable", "true")
                .put("armor.authentication.authentication_backend.impl",
                        "com.petalmd.armor.authentication.backend.simple.SettingsBasedAuthenticationBackend")
                .put("armor.authentication.authentication_backend.cache.enable", "true")
                .putArray("armor.actionrequestfilter.names", "readonly")
                .putArray("armor.actionrequestfilter.readonly.allowed_actions", "indices:/data/read/search").build();

        startES(settings);
        username = "jacksonm";
        password = "secret";
        setupTestData("ac_rules_1.json");
        executeIndex("ac_rules_1.json", "armor", "ac", "ac", false, false);
        executeIndex("ac_rules_1.json", "armor", "ac", "ac", true, true);
        executeIndex("ac_rules_1.json", "armor", "xx", "xx", false, false);

        final JestClient client = getJestClient(getServerUri(false), username, password);

        final JestResult jr = client.execute(new PutMapping.Builder("_all", "ac", "{" + "\"properties\" : {"
                + "\"rules\" : {\"type\" : \"string\", \"store\" : true }" + "}" + "}"
        ).setHeader(headers).build());

        Assert.assertNotNull(jr.getErrorMessage());
        log.debug(jr.getErrorMessage());
        Assert.assertTrue(jr.getErrorMessage().contains("to _all indices"));

    }


    @Test
    public void reindexTest() throws Exception{

        final boolean wrongPassword = false;
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false,"ceo" );


        final Settings settings = Settings.builder()
                .putArray("armor.actionrequestfilter.names", "reindex","forbidden")
                .putArray("armor.actionrequestfilter.reindex.allowed_actions", "indices:data/read/*", "indices:data/write/reindex", "indices:data/write/bulk*")
                .putArray("armor.actionrequestfilter.forbidden.allowed_actions","indices:data/read/scroll*")
                .put(ConfigConstants.ARMOR_ACTION_WILDCARD_EXPANSION_ENABLED,true)
                .put(authSettings).build();

        startES(settings);

        setupTestData("ac_rules_11.json");
        ImmutableMap<String, String> source = ImmutableMap.of("index", "marketing");
        ImmutableMap<String, String> dest = ImmutableMap.of("index", "financial");
        final JestClient client = getJestClient(getServerUri(false), username, password);

        Reindex reindex = new Reindex.Builder(source,dest).refresh(false).build();
        final JestResult jr = client.execute(reindex);

        Assert.assertTrue(jr.getErrorMessage(),jr.isSucceeded());

    }
}
