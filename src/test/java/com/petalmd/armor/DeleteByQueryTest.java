package com.petalmd.armor;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.google.gson.JsonObject;
import com.petalmd.armor.tests.DeleteByQueryNew;
import com.petalmd.armor.util.ConfigConstants;
import io.searchbox.client.JestClient;
import io.searchbox.client.JestResult;
import io.searchbox.core.DeleteByQuery;
import org.apache.http.HttpResponse;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

/**
 * Created by jehuty0shift on 21/11/18.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class DeleteByQueryTest extends AbstractScenarioTest {

    @Test
    public void testDeleteByQuery() throws Exception {
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final String index = "internal";

        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "deletebyquery","forbidden")
                .putList("armor.actionrequestfilter.deletebyquery.allowed_actions", "indices:data/write/delete/byquery")
                .putList("armor.actionrequestfilter.forbidden.forbidden_actions", "cluster:admin*")
                .put(ConfigConstants.ARMOR_KIBANA_HELPER_ENABLED, true)
                .put(authSettings).build();

        startES(settings);

        setupTestDataWithFilteredAlias("ac_rules_16.json");

        JestClient client = getJestClient(getServerUri(false), username, password);

        DeleteByQuery dbq = new DeleteByQuery.Builder("{\"query\" : {\"match_all\" : {} } }").addIndex(index).setParameter("wait_for_completion",true).build();

        final Tuple<JestResult, HttpResponse> resulttu = ((HeaderAwareJestHttpClient) client).executeE(dbq);

        Assert.assertTrue(resulttu.v1().isSucceeded());

        JsonObject resultObject = resulttu.v1().getJsonObject();

        Assert.assertTrue(resultObject.get("total").getAsInt() == resultObject.get("deleted").getAsInt());

        log.info("result is {}", resulttu.v1().getJsonString());

    }

}