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

        int resultCount = result.getJsonObject().getAsJsonObject("hits").getAsJsonArray("hits").size();

        Assert.assertEquals(3, resultCount);
    }



    @Test
    public void searchAliasWildcard() throws Exception {
        final boolean wrongPassword = false;
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false,"ceo" );


        final Settings settings = Settings.settingsBuilder()
                .putArray("armor.actionrequestfilter.names", "wild","forbidden")
                .putArray("armor.actionrequestfilter.wild.allowed_actions", "indices:data/read/search")
                .putArray("armor.actionrequestfilter.forbidden.forbidden_actions", "indices:*")
                .put(ConfigConstants.ARMOR_ACTION_WILDCARD_EXPANSION_ENABLED,true)
                .put(authSettings).build();

        startES(settings);

        setupTestData("ac_rules_10.json");


        //test on indice inter* (part of wildcard)
        final String[] indices1 = new String[] { "inter*" };
        final Tuple<JestResult, HttpResponse> resulttu1 = executeSearch("ac_query_matchall.json", indices1, null,
                true, false);
        JestResult result = resulttu1.v1();
        Map json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 200);

        //test on indice financial
        final String[] indices2 = new String[] { "financial" };
        final Tuple<JestResult, HttpResponse> resulttu2 = executeSearch("ac_query_matchall.json", indices2, null,
                false, false);
        result = resulttu2.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 403);

        //test on all
        final String[] indices3 = new String[] { "_all" };
        final Tuple<JestResult, HttpResponse> resulttu3 = executeSearch("ac_query_matchall.json", indices3, null,
                true, false);
        result = resulttu3.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 200);

        //test on wildcard *
        final String[] indices4 = new String[] {};
        final Tuple<JestResult, HttpResponse> resulttu4 = executeSearch("ac_query_matchall.json", indices4, null,
                true, false);
        result = resulttu4.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 200);

        //test on wildcard interna*
        final String[] indices5 = new String[] {"interna*"};
        final Tuple<JestResult, HttpResponse> resulttu5 = executeSearch("ac_query_matchall.json", indices5, null,
                true, false);
        result = resulttu5.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 200);

        //test on wildcard finan
        final String[] indices6 = new String[] {"finan*"};
        final Tuple<JestResult, HttpResponse> resulttu6 = executeSearch("ac_query_matchall.json", indices6, null,
                false, false);
        result = resulttu6.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 403);


    }
}
