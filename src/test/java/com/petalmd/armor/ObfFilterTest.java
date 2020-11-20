/*
 * Copyright 2017 PetalMD.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.petalmd.armor;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.petalmd.armor.util.ConfigConstants;
import io.searchbox.action.AbstractAction;
import io.searchbox.action.GenericResultAbstractAction;
import io.searchbox.client.JestResult;
import io.searchbox.client.config.ElasticsearchVersion;
import io.searchbox.cluster.NodesInfo;
import org.apache.http.HttpResponse;
import org.elasticsearch.client.*;
import org.elasticsearch.client.indices.GetIndexRequest;
import org.elasticsearch.client.indices.GetIndexResponse;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;
import java.util.Map;

/**
 * Created by jehuty0shift on 13/03/17.
 * @author jehuty0shift
 */
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class ObfFilterTest extends AbstractArmorTest {

    @Test
    public void nodesInfoFilterTest() throws Exception {

        final boolean wrongPassword = false;
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false,"ceo" );

        final Settings settings =  Settings.builder().putList("armor.actionrequestfilter.names", "monitoronly")
                .putList("armor.actionrequestfilter.monitoronly.allowed_actions", "cluster:monitor*")
                .put(ConfigConstants.ARMOR_OBFUSCATION_FILTER_ENABLED,true)
                .put(ConfigConstants.ARMOR_ALLOW_KIBANA_ACTIONS,false)
                .put(authSettings).build();

        startES(settings);
        setupTestData("ac_rules_2.json");

        RestHighLevelClient client = getRestClient(false, username, password);

        Response nodesResp = client.getLowLevelClient().performRequest(new Request("GET", "_nodes"));

        String nodesRespStr = new String(nodesResp.getEntity().getContent().readAllBytes());

        ObjectMapper objMapper = new ObjectMapper();

        JsonNode nInfosJson = objMapper.reader().readTree(nodesRespStr);

        for(JsonNode nodeElem : nInfosJson.get("nodes")) {
            nodeElem.get("transport_address").asText().startsWith("172.16");
            nodeElem.get("host").asText().startsWith("172.16");
            nodeElem.get("ip").asText().startsWith("172.16");
        }

    }

    @Test
    public void GetIndexFilterTest() throws Exception {

        final boolean wrongPassword = false;
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false,"ceo" );

        final Settings settings =  Settings.builder().putList("armor.actionrequestfilter.names", "indicesadmin")
                .putList("armor.actionrequestfilter.indicesadmin.allowed_actions", "indices:admin*")
                .putList("armor.obfuscation.filter.getindexresponse.remove","mappings.post_date","indices.ceo","aliases")
                .put(ConfigConstants.ARMOR_OBFUSCATION_FILTER_ENABLED,true)
                .put(ConfigConstants.ARMOR_ALLOW_KIBANA_ACTIONS,false)
                .put(authSettings).build();

        startES(settings);
        setupTestData("ac_rules_2.json");

        RestHighLevelClient client = getRestClient(false, username, password);


        GetIndexResponse getIndexResp = client.indices().get(new GetIndexRequest("internal"), RequestOptions.DEFAULT);

        //verify that the mapping is not present
        Assert.assertTrue(getIndexResp.getMappings().entrySet().stream().noneMatch(k -> k.getValue().source().uncompressed().utf8ToString().contains("post_date")));
        //assert that the indice ceo is not present
        Assert.assertTrue(Arrays.stream(getIndexResp.getIndices()).sequential().noneMatch(s -> s.equals("ceo")));
        //assert that the aliases are empty.
        Assert.assertTrue(getIndexResp.getAliases().entrySet().stream().allMatch(e -> e.getValue().isEmpty()));

    }


    @Test
    public void GetIndexFilterWithAllowedAliasesTest() throws Exception {

        final boolean wrongPassword = false;
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false,"ceo" );

        final Settings settings =  Settings.builder().putList("armor.actionrequestfilter.names", "indicesadmin")
                .putList("armor.actionrequestfilter.indicesadmin.allowed_actions", "indices:admin*")
                .putList("armor.obfuscation.filter.getindexresponse.remove","mappings.post_date","indices.ceo")
                .put(ConfigConstants.ARMOR_OBFUSCATION_FILTER_ENABLED,true)
                .put(ConfigConstants.ARMOR_ALLOW_KIBANA_ACTIONS,false)
                .put(authSettings).build();

        startES(settings);
        setupTestData("ac_rules_22.json");

        RestHighLevelClient client = getRestClient(false, username, password);


        GetIndexResponse getIndexResp = client.indices().get(new GetIndexRequest("internal"), RequestOptions.DEFAULT);

        //verify that the mapping is not present
        Assert.assertTrue(getIndexResp.getMappings().entrySet().stream().noneMatch(k -> k.getValue().source().uncompressed().utf8ToString().contains("post_date")));
        //assert that the indice ceo is not present
        Assert.assertTrue(Arrays.stream(getIndexResp.getIndices()).sequential().noneMatch(s -> s.equals("ceo")));
        //assert that the alias crucial and cxo are not present, when internal is.
        Assert.assertTrue(getIndexResp.getAliases().entrySet().stream().flatMap(e -> e.getValue().stream())
                .noneMatch(a -> a.alias().equals("crucial")));
        Assert.assertTrue(getIndexResp.getAliases().entrySet().stream().flatMap(e -> e.getValue().stream())
                .noneMatch(a -> a.alias().equals("cxo")));
        Assert.assertTrue(getIndexResp.getAliases().entrySet().stream().flatMap(e -> e.getValue().stream())
                .anyMatch(a -> a.alias().equals("internal")));

    }



    @Test
    public void GetClusterStateTest() throws Exception {

        final boolean wrongPassword = false;
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false,"ceo" );

        final Settings settings =  Settings.builder().putList("armor.actionrequestfilter.names", "clusterstate")
                .putList("armor.actionrequestfilter.clusterstate.allowed_actions", "cluster:monitor/state")
                .put(ConfigConstants.ARMOR_OBFUSCATION_FILTER_ENABLED,true)
                .put(ConfigConstants.ARMOR_ALLOW_KIBANA_ACTIONS,false)
                .put(authSettings).build();

        startES(settings);
        setupTestData("ac_rules_2.json");

        RestHighLevelClient client = getRestClient(false, username, password);

        Response stateResp = client.getLowLevelClient().performRequest(new Request("GET","_cluster/state"));

        ObjectMapper objReader = new ObjectMapper();

        JsonNode state = objReader.readTree(new String(stateResp.getEntity().getContent().readAllBytes()));

        Assert.assertTrue(state.get("nodes").isEmpty());
        Assert.assertTrue(state.get("blocks").isEmpty());
        Assert.assertTrue(state.get("routing_table").get("indices").isEmpty());
    }

}
