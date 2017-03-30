package com.petalmd.armor;

import com.google.gson.internal.LinkedTreeMap;
import com.petalmd.armor.util.ConfigConstants;
import io.searchbox.client.JestResult;
import org.apache.http.HttpResponse;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by bdiasse on 20/02/17.
 */
public class SearchTests extends AbstractScenarioTest {



    @Test
    public void searchAggregationWithMinDocsCount() throws Exception{
        final boolean wrongPassword = false;
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false,"ceo" );

        final String[] indices = new String[] { "filtered" };

        final Settings settings = Settings.settingsBuilder().putArray("armor.actionrequestfilter.names", "readonly")
                .putArray("armor.actionrequestfilter.readonly.allowed_actions", "indices:data/read/search")
                .put(ConfigConstants.ARMOR_AGGREGATION_FILTER_ENABLED,true)
        .put(authSettings).build();

        startES(settings);

        setupTestDataWithFilteredAlias("ac_rules_8.json");

        final Tuple<JestResult, HttpResponse> resulttu = executeSearch("ac_query_aggs_terms_mincount.json", indices, null,
                true, false);

        final JestResult result = resulttu.v1();
        final Map json = prettyGson.fromJson(result.getJsonString(), Map.class);
        int aggs1ResSize = result.getJsonObject().getAsJsonObject("aggregations").getAsJsonObject("1").getAsJsonArray("buckets").size();

        int aggs2ResSize = result.getJsonObject().getAsJsonObject("aggregations").getAsJsonObject("2").getAsJsonArray("buckets").get(0).getAsJsonObject().getAsJsonObject("3").getAsJsonArray("buckets").size();

        Assert.assertEquals(1,aggs1ResSize);
        Assert.assertEquals(1,aggs2ResSize);

    }

    @Test
    public void scroll() throws Exception {
        final boolean wrongPassword = false;
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false,"ceo" );

        final String[] indices = new String[] { "internal" };

        final Settings settings = Settings.settingsBuilder().putArray("armor.actionrequestfilter.names", "scroll")
                .putArray("armor.actionrequestfilter.scroll.allowed_actions", "indices:data/read/scroll", "indices:data/read/search")
                .put(ConfigConstants.ARMOR_AGGREGATION_FILTER_ENABLED,true)
                .put(authSettings).build();

        startES(settings);

        setupTestData("ac_rules_9.json");

        Map <String, String> scrollParameters = new HashMap<>();
        scrollParameters.put("scroll","1m");
        scrollParameters.put("size","3");

        final Tuple<JestResult, HttpResponse> resulttu = executeSearchWithScroll("ac_query_matchall.json", indices, null,
                true, false,scrollParameters);

        final JestResult result = resulttu.v1();

        final Map json = prettyGson.fromJson(result.getJsonString(), Map.class);


    }

}
