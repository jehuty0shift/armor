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

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.petalmd.armor.util.ConfigConstants;
import io.searchbox.action.Action;
import io.searchbox.action.GenericResultAbstractAction;
import io.searchbox.client.JestResult;
import io.searchbox.cluster.NodesInfo;
import io.searchbox.core.Get;
import io.searchbox.core.Index;
import org.apache.http.HttpResponse;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.junit.Test;

import java.util.Map;
import java.util.Set;

/**
 * Created by jehuty0shift on 13/03/17.
 * @author jehuty0shift
 */
public class ObfFilterTest extends AbstractScenarioTest {

    @Test
    public void nodesInfoFilterTest() throws Exception {

        final boolean wrongPassword = false;
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false,"ceo" );

        final Settings settings =  Settings.settingsBuilder().putArray("armor.actionrequestfilter.names", "monitoronly")
                .putArray("armor.actionrequestfilter.monitoronly.allowed_actions", "cluster:monitor*")
                .put(ConfigConstants.ARMOR_OBFUSCATION_FILTER_ENABLED,true)
                .put(ConfigConstants.ARMOR_ALLOW_KIBANA_ACTIONS,false)
                .put(authSettings).build();

        startES(settings);
        setupTestData("ac_rules_2.json");

        HeaderAwareJestHttpClient client = getJestClient(getServerUri(false), username, password);

        final Tuple<JestResult, HttpResponse> restu = client.executeE(new NodesInfo.Builder().build());

        assert(restu.v1().isSucceeded());
        JsonObject nodesObj = restu.v1().getJsonObject().getAsJsonObject("nodes");
        for (Map.Entry<String,JsonElement> nodeElem : nodesObj.entrySet()) {
            JsonObject nodeObj = nodeElem.getValue().getAsJsonObject();
            assert(nodeObj.get("transport_address").getAsString().startsWith("172.16"));
            assert(nodeObj.get("host").getAsString().startsWith("172.16"));
            assert(nodeObj.get("ip").getAsString().startsWith("172.16"));
        }
        System.out.println(restu.v1().getJsonString());
    }

    @Test
    public void GetIndexFilterTest() throws Exception {

        final boolean wrongPassword = false;
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false,"ceo" );

        final Settings settings =  Settings.settingsBuilder().putArray("armor.actionrequestfilter.names", "indicesadmin")
                .putArray("armor.actionrequestfilter.indicesadmin.allowed_actions", "indices:admin*")
                .putArray("armor.obfuscation.filter.getindexresponse.remove","mappings.post_date","indices.ceo","aliases")
                .put(ConfigConstants.ARMOR_OBFUSCATION_FILTER_ENABLED,true)
                .put(ConfigConstants.ARMOR_ALLOW_KIBANA_ACTIONS,false)
                .put(authSettings).build();

        startES(settings);
        setupTestData("ac_rules_2.json");

        HeaderAwareJestHttpClient client = getJestClient(getServerUri(false), username, password);

        final Tuple<JestResult, HttpResponse> restu = client.executeE(new GenericResultAbstractAction() {
            @Override
            public String getRestMethodName() {
                return "GET";
            }

            @Override
            public String getURI() {
                return "/internal";
            }

        });

        assert(restu.v1().isSucceeded());
        //verify that the mapping is not present
        assert(!restu.v1().getJsonString().contains("post_date"));
        //assert that the indice ceo is not present
        assert(!restu.v1().getJsonString().contains("ceo"));
        //assert that the aliases are empty.
        for (Map.Entry<String,JsonElement> element : restu.v1().getJsonObject().entrySet()) {
            if (element.getValue().getAsJsonObject() != null) {
                JsonObject jObj = element.getValue().getAsJsonObject();
                assert(jObj.get("aliases").getAsJsonObject().toString().equals("{}"));
            }
        }
        System.out.println(restu.v1().getJsonString());
    }


}
