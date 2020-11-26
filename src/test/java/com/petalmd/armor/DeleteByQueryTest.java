package com.petalmd.armor;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.google.gson.JsonObject;
import com.petalmd.armor.tests.DeleteByQueryNew;
import com.petalmd.armor.util.ConfigConstants;
import io.searchbox.client.JestClient;
import io.searchbox.client.JestResult;
import io.searchbox.core.DeleteByQuery;
import org.apache.http.HttpResponse;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.index.query.MatchAllQueryBuilder;
import org.elasticsearch.index.reindex.BulkByScrollResponse;
import org.elasticsearch.index.reindex.DeleteByQueryRequest;
import org.junit.Assert;
import org.junit.Test;

/**
 * Created by jehuty0shift on 21/11/18.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class DeleteByQueryTest extends AbstractArmorTest {

    @Test
    public void testDeleteByQuery() throws Exception {
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final String index = "internal";

        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "deletebyquery", "forbidden")
                .putList("armor.actionrequestfilter.deletebyquery.allowed_actions", "indices:data/write/delete/byquery")
                .putList("armor.actionrequestfilter.forbidden.forbidden_actions", "cluster:admin*")
                .put(ConfigConstants.ARMOR_KIBANA_HELPER_ENABLED, true)
                .put(authSettings).build();

        startES(settings);

        setupTestDataWithFilteredAlias("ac_rules_16.json");

        RestHighLevelClient client = getRestClient(false, username, password);

        BulkByScrollResponse delResp = client.deleteByQuery(new DeleteByQueryRequest(index).setQuery(new MatchAllQueryBuilder()), RequestOptions.DEFAULT);

        Assert.assertTrue(delResp.getBulkFailures().isEmpty());
        Assert.assertEquals(delResp.getDeleted(), delResp.getTotal());

        log.info("result is {}", delResp.toString());

    }

}
