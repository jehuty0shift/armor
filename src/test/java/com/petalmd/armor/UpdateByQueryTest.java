package com.petalmd.armor;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.google.gson.JsonObject;
import com.petalmd.armor.tests.DeleteByQueryNew;
import com.petalmd.armor.tests.UpdateByQueryNew;
import com.petalmd.armor.util.ConfigConstants;
import io.searchbox.client.JestClient;
import io.searchbox.client.JestResult;
import org.apache.http.HttpResponse;
import org.elasticsearch.action.search.SearchAction;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.index.reindex.UpdateByQueryAction;
import org.junit.Assert;
import org.junit.Test;

/**
 * Created by jehuty0shift on 21/11/18.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class UpdateByQueryTest extends AbstractScenarioTest {

    @Test
    public void testUpdateByQuery() throws Exception {
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final String index = "dev";

        final Settings settings = Settings.builder().putArray("armor.actionrequestfilter.names", "updatebyquery","forbidden")
                .putArray("armor.actionrequestfilter.updatebyquery.allowed_actions", UpdateByQueryAction.NAME)
                .putArray("armor.actionrequestfilter.forbidden.forbidden_actions", "cluster:admin*")
                .put(ConfigConstants.ARMOR_KIBANA_HELPER_ENABLED, true)
                .put(authSettings).build();

        startES(settings);

        setupTestDataWithFilteredAlias("ac_rules_17.json");

        JestClient client = getJestClient(getServerUri(false), username, password);

        UpdateByQueryNew ubq = new UpdateByQueryNew.Builder("{\"script\" : " +
                " { \"source\": \"ctx._source.message = 'message changed'\",\n" +
                "    \"lang\": \"painless\" }," +
                "\"query\": {\n" +
                "    \"term\": {\n" +
                "      \"user\": \"ronaldihno\"\n" +
                "    }\n" +
                "  }" +
                "}").addIndex(index).setParameter("wait_for_completion",true).build();

        final Tuple<JestResult, HttpResponse> resulttu = ((HeaderAwareJestHttpClient) client).executeE(ubq);

        Assert.assertTrue(resulttu.v1().isSucceeded());

        JsonObject resultObject = resulttu.v1().getJsonObject();

        Assert.assertTrue(resultObject.get("total").getAsInt() == resultObject.get("updated").getAsInt());

        log.info("result is {}", resulttu.v1().getJsonString());

        UpdateByQueryNew ubq2 = new UpdateByQueryNew.Builder("{\"script\" : " +
                " { \"source\": \"ctx._source.message = 'message changed'\",\n" +
                "    \"lang\": \"painless\" }," +
                "\"query\": {\n" +
                "    \"term\": {\n" +
                "      \"user\": \"zeus\"\n" +
                "    }\n" +
                "  }" +
                "}").addIndex("financial").setParameter("wait_for_completion",true).build();

        final Tuple<JestResult, HttpResponse> resulttu2 = ((HeaderAwareJestHttpClient) client).executeE(ubq2);

        Assert.assertTrue(!resulttu2.v1().isSucceeded());

        Assert.assertEquals(resulttu2.v2().getStatusLine().getStatusCode(),403);



    }

}
