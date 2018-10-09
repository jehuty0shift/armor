package com.petalmd.armor;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.petalmd.armor.util.ConfigConstants;
import io.searchbox.client.JestResult;
import io.searchbox.client.http.JestHttpClient;
import io.searchbox.indices.settings.UpdateSettings;
import org.apache.http.HttpResponse;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by bdiasse on 20/02/17.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class SearchTests extends AbstractScenarioTest {


    @Test
    public void searchAggregationWithMinDocsCount() throws Exception {
        final boolean wrongPassword = false;
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final String[] indices = new String[]{"filtered"};

        final Settings settings = Settings.builder().putArray("armor.actionrequestfilter.names", "readonly")
                .putArray("armor.actionrequestfilter.readonly.allowed_actions", "indices:data/read/search")
                .put(ConfigConstants.ARMOR_AGGREGATION_FILTER_ENABLED, true)
                .put(authSettings).build();

        startES(settings);

        setupTestDataWithFilteredAlias("ac_rules_8.json");

        final Tuple<JestResult, HttpResponse> resulttu = executeSearch("ac_query_aggs_terms_mincount.json", indices, null,
                true, false);

        final JestResult result = resulttu.v1();
        final Map json = prettyGson.fromJson(result.getJsonString(), Map.class);
        int aggs1ResSize = result.getJsonObject().getAsJsonObject("aggregations").getAsJsonObject("1").getAsJsonArray("buckets").size();

        int aggs2ResSize = result.getJsonObject().getAsJsonObject("aggregations").getAsJsonObject("2").getAsJsonArray("buckets").get(0).getAsJsonObject().getAsJsonObject("3").getAsJsonArray("buckets").size();

        Assert.assertEquals(1, aggs1ResSize);
        Assert.assertEquals(1, aggs2ResSize);

    }

    @Test
    public void scroll() throws Exception {
        final boolean wrongPassword = false;
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final String[] indices = new String[]{"internal"};

        final Settings settings = Settings.builder().putArray("armor.actionrequestfilter.names", "scroll")
                .putArray("armor.actionrequestfilter.scroll.allowed_actions", "indices:data/read/scroll", "indices:data/read/search")
                .put(ConfigConstants.ARMOR_AGGREGATION_FILTER_ENABLED, true)
                .put(authSettings).build();

        startES(settings);

        setupTestData("ac_rules_9.json");

        Map<String, String> scrollParameters = new HashMap<>();
        scrollParameters.put("scroll", "1m");
        scrollParameters.put("size", "3");

        final Tuple<JestResult, HttpResponse> resulttu = executeSearchWithScroll("ac_query_matchall.json", indices, null,
                true, false, scrollParameters);

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
        Settings authSettings = getAuthSettings(false, "ceo");


        final Settings settings = Settings.builder()
                .putArray("armor.actionrequestfilter.names", "wild", "forbidden")
                .putArray("armor.actionrequestfilter.wild.allowed_actions", "indices:data/read/search")
                .putArray("armor.actionrequestfilter.forbidden.forbidden_actions", "indices:*")
                .put(ConfigConstants.ARMOR_ACTION_WILDCARD_EXPANSION_ENABLED, true)
                .put(authSettings).build();

        startES(settings);

        setupTestData("ac_rules_10.json");


        //test on indice inter* (part of wildcard)
        final String[] indices1 = new String[]{"inter*"};
        final Tuple<JestResult, HttpResponse> resulttu1 = executeSearch("ac_query_matchall.json", indices1, null,
                true, false);
        JestResult result = resulttu1.v1();
        Map json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 200);

        //test on indice financial
        final String[] indices2 = new String[]{"financial"};
        final Tuple<JestResult, HttpResponse> resulttu2 = executeSearch("ac_query_matchall.json", indices2, null,
                false, false);
        result = resulttu2.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 403);

        //test on all
        final String[] indices3 = new String[]{"_all"};
        final Tuple<JestResult, HttpResponse> resulttu3 = executeSearch("ac_query_matchall.json", indices3, null,
                true, false);
        result = resulttu3.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 200);

        //test on wildcard *
        final String[] indices4 = new String[]{};
        final Tuple<JestResult, HttpResponse> resulttu4 = executeSearch("ac_query_matchall.json", indices4, null,
                true, false);
        result = resulttu4.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 200);

        //test on wildcard interna*
        final String[] indices5 = new String[]{"interna*"};
        final Tuple<JestResult, HttpResponse> resulttu5 = executeSearch("ac_query_matchall.json", indices5, null,
                true, false);
        result = resulttu5.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 200);

        //test on wildcard finan
        final String[] indices6 = new String[]{"finan*"};
        final Tuple<JestResult, HttpResponse> resulttu6 = executeSearch("ac_query_matchall.json", indices6, null,
                false, false);
        result = resulttu6.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 403);


    }


    @Test
    public void searchWildcardMultiIndicesSingleFilter() throws Exception {
        final boolean wrongPassword = false;
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");


        final Settings settings = Settings.builder()
                .putArray("armor.actionrequestfilter.names", "wild", "forbidden")
                .putArray("armor.actionrequestfilter.wild.allowed_actions", "indices:data/read/search")
                .putArray("armor.actionrequestfilter.forbidden.forbidden_actions", "indices:*")
                .put(ConfigConstants.ARMOR_ACTION_WILDCARD_EXPANSION_ENABLED, true)
                .put(authSettings).build();

        startES(settings);

        setupTestData("ac_rules_13.json");

        //test on allowed alias inter* (part of wildcard) + forbidden indice
        final String[] indices1 = new String[]{"inter*", "cto"};
        final Tuple<JestResult, HttpResponse> resulttu1 = executeSearch("ac_query_matchall.json", indices1, null,
                false, false);
        JestResult result = resulttu1.v1();
        Map json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 403);


        //test on  forbidden indice + allowed alias
        final String[] indices2 = new String[]{"cto", "cxo"};
        final Tuple<JestResult, HttpResponse> resulttu2 = executeSearch("ac_query_matchall.json", indices2, null,
                false, false);
        result = resulttu2.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 403);


        //test on forbidden indice + allowed indice
        final String[] indices3 = new String[]{"ceo", "financial"};
        final Tuple<JestResult, HttpResponse> resulttu3 = executeSearch("ac_query_matchall.json", indices3, null,
                false, false);
        result = resulttu3.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 403);


        //test on *
        final String[] indices4 = new String[]{"*"};
        final Tuple<JestResult, HttpResponse> resulttu4 = executeSearch("ac_query_matchall.json", indices4, null,
                true, false);
        result = resulttu4.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 200);


        //test on allowed alias + allowed index
        final String[] indices5 = new String[]{"financial", "cxo"};
        final Tuple<JestResult, HttpResponse> resulttu5 = executeSearch("ac_query_matchall.json", indices5, null,
                true, false);
        result = resulttu5.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 200);


        //test on allowed alias + allowed index with wildcard
        final String[] indices6 = new String[]{"financial", "cx*"};
        final Tuple<JestResult, HttpResponse> resulttu6 = executeSearch("ac_query_matchall.json", indices6, null,
                true, false);
        result = resulttu6.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 200);


        //test on allowed indice + allowed index with wildcard
        final String[] indices7 = new String[]{"marketing", "fin*"};
        final Tuple<JestResult, HttpResponse> resulttu7 = executeSearch("ac_query_matchall.json", indices7, null,
                true, false);
        result = resulttu7.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 200);


        //test on allowed alias + allowed alias with wildcard
        final String[] indices8 = new String[]{"internal", "c*"};
        final Tuple<JestResult, HttpResponse> resulttu8 = executeSearch("ac_query_matchall.json", indices8, null,
                true, false);
        result = resulttu8.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 200);


        //test on forbidden indice
        final String[] indices9 = new String[]{"ceo"};
        final Tuple<JestResult, HttpResponse> resulttu9 = executeSearch("ac_query_matchall.json", indices9, null,
                false, false);
        result = resulttu9.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 403);


        //test on forbidden alias
        final String[] indices10 = new String[]{"crucial"};
        final Tuple<JestResult, HttpResponse> resulttu10 = executeSearch("ac_query_matchall.json", indices10, null,
                false, false);
        result = resulttu10.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 403);
    }

    @Test
    public void searchWildcardMultiIndicesMultiRules() throws Exception {
        final boolean wrongPassword = false;
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");


        final Settings settings = Settings.builder()
                .putArray("armor.actionrequestfilter.names", "reader", "writer", "forbidden")
                .putArray("armor.actionrequestfilter.reader.allowed_actions", "indices:data/read/search")
                .putArray("armor.actionrequestfilter.reader.forbidden_actions", "indices:data/write*")
                .putArray("armor.actionrequestfilter.writer.allowed_actions", "indices:data/read/search", "indices:data/read/write", "indices:admin/settings/update")
                .putArray("armor.actionrequestfilter.forbidden.forbidden_actions", "indices:*")
                .put(ConfigConstants.ARMOR_ACTION_WILDCARD_EXPANSION_ENABLED, true)
                .put(authSettings).build();

        startES(settings);

        setupTestData("ac_rules_14.json");

        //test on allowed alias inter* (part of wildcard) + forbidden indice
        final String[] indices1 = new String[]{"inter*", "cto"};
        final Tuple<JestResult, HttpResponse> resulttu1 = executeSearch("ac_query_matchall.json", indices1, null,
                false, false);
        JestResult result = resulttu1.v1();
        Map json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 403);


        //test on  forbidden indice + allowed alias
        final String[] indices2 = new String[]{"cto", "cxo"};
        final Tuple<JestResult, HttpResponse> resulttu2 = executeSearch("ac_query_matchall.json", indices2, null,
                false, false);
        result = resulttu2.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 403);


        //test on forbidden indice + allowed indice
        final String[] indices3 = new String[]{"ceo", "financial"};
        final Tuple<JestResult, HttpResponse> resulttu3 = executeSearch("ac_query_matchall.json", indices3, null,
                false, false);
        result = resulttu3.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 403);


        //test on *
        final String[] indices4 = new String[]{"*"};
        final Tuple<JestResult, HttpResponse> resulttu4 = executeSearch("ac_query_matchall.json", indices4, null,
                true, false);
        result = resulttu4.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 200);


        //test on allowed alias + allowed index
        final String[] indices5 = new String[]{"financial", "cxo"};
        final Tuple<JestResult, HttpResponse> resulttu5 = executeSearch("ac_query_matchall.json", indices5, null,
                true, false);
        result = resulttu5.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 200);


        //test on allowed alias + allowed index with wildcard
        final String[] indices6 = new String[]{"financial", "cx*"};
        final Tuple<JestResult, HttpResponse> resulttu6 = executeSearch("ac_query_matchall.json", indices6, null,
                true, false);
        result = resulttu6.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 200);


        //test on allowed indice + allowed index with wildcard
        final String[] indices7 = new String[]{"marketing", "fin*"};
        final Tuple<JestResult, HttpResponse> resulttu7 = executeSearch("ac_query_matchall.json", indices7, null,
                true, false);
        result = resulttu7.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 200);


        //test on allowed alias + allowed alias with wildcard
        final String[] indices8 = new String[]{"internal", "c*"};
        final Tuple<JestResult, HttpResponse> resulttu8 = executeSearch("ac_query_matchall.json", indices8, null,
                true, false);
        result = resulttu8.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 200);


        //test on forbidden indice
        final String[] indices9 = new String[]{"ceo"};
        final Tuple<JestResult, HttpResponse> resulttu9 = executeSearch("ac_query_matchall.json", indices9, null,
                false, false);
        result = resulttu9.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 403);


        //test on forbidden alias
        final String[] indices10 = new String[]{"crucial"};
        final Tuple<JestResult, HttpResponse> resulttu10 = executeSearch("ac_query_matchall.json", indices10, null,
                false, false);
        result = resulttu10.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 403);

        //test write on forbidden alias with allowed alias
        final String[] indices11 = new String[]{"internal", "c*"};
        HeaderAwareJestHttpClient client = getJestClient(getServerUri(false), username, password);
        final String settingSource = "{\"index.refresh_interval\" : \"5s\" }";
        final Tuple<JestResult, HttpResponse> resulttu11 = client.executeE(new UpdateSettings.Builder(settingSource).addIndex(Arrays.asList(indices11)).build());
        result = resulttu11.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 403);

        //test write on forbidden alias with allowed indice
        final String[] indices12 = new String[]{"financial", "internal"};
        client = getJestClient(getServerUri(false), username, password);
        final String settingSource2 = "{\"index.refresh_interval\" : \"5s\" }";
        final Tuple<JestResult, HttpResponse> resulttu12 = client.executeE(new UpdateSettings.Builder(settingSource).addIndex(Arrays.asList(indices12)).build());
        result = resulttu12.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 403);

        final String[] indices13 = new String[]{"financial", "marketing"};
        client = getJestClient(getServerUri(false), username, password);
        final String settingSource3 = "{\"index.refresh_interval\" : \"5s\" }";
        final Tuple<JestResult, HttpResponse> resulttu13 = client.executeE(new UpdateSettings.Builder(settingSource).addIndex(Arrays.asList(indices13)).build());
        result = resulttu13.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 200);

    }

    @Test
    public void searchWildcardMultiIndicesMultiRulesNoWildCardExpansion() throws Exception {
        final boolean wrongPassword = false;
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");


        final Settings settings = Settings.builder()
                .putArray("armor.actionrequestfilter.names", "reader", "writer", "forbidden")
                .putArray("armor.actionrequestfilter.reader.allowed_actions", "indices:data/read/search")
                .putArray("armor.actionrequestfilter.reader.forbidden_actions", "indices:data/write*,indices:admin/settings/update*")
                .putArray("armor.actionrequestfilter.writer.allowed_actions", "indices:data/read/search", "indices:data/read/write", "indices:admin/settings/update")
                .putArray("armor.actionrequestfilter.forbidden.forbidden_actions", "indices:*")
                .put(ConfigConstants.ARMOR_ACTION_WILDCARD_EXPANSION_ENABLED, false)
                .put(authSettings).build();

        startES(settings);

        setupTestData("ac_rules_14.json");


        //test on allowed alias inter* (part of wildcard) + forbidden indice
        final String[] indices1 = new String[]{"inter*", "cto"};
        final Tuple<JestResult, HttpResponse> resulttu1 = executeSearch("ac_query_matchall.json", indices1, null,
                false, false);
        JestResult result = resulttu1.v1();
        Map json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 403);


        //test on  forbidden indice + allowed alias
        final String[] indices2 = new String[]{"cto", "cxo"};
        final Tuple<JestResult, HttpResponse> resulttu2 = executeSearch("ac_query_matchall.json", indices2, null,
                false, false);
        result = resulttu2.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 403);


        //test on forbidden indice + allowed indice
        final String[] indices3 = new String[]{"ceo", "financial"};
        final Tuple<JestResult, HttpResponse> resulttu3 = executeSearch("ac_query_matchall.json", indices3, null,
                false, false);
        result = resulttu3.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 403);


        //test on *
        final String[] indices4 = new String[]{"*"};
        final Tuple<JestResult, HttpResponse> resulttu4 = executeSearch("ac_query_matchall.json", indices4, null,
                false, false);
        result = resulttu4.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 403);

    }


}
