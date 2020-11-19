package com.petalmd.armor;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.petalmd.armor.tests.ClearScroll;
import com.petalmd.armor.util.ConfigConstants;
import io.searchbox.action.Action;
import io.searchbox.client.JestResult;
import io.searchbox.client.config.ElasticsearchVersion;
import io.searchbox.core.MultiSearch;
import io.searchbox.core.Search;
import io.searchbox.indices.settings.UpdateSettings;
import org.apache.http.HttpResponse;
import org.apache.http.entity.ContentType;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import java.util.*;

/**
 * Created by bdiasse on 20/02/17.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class SearchTests extends AbstractUnitTest {


    @Test
    public void searchAggregationWithMinDocsCount() throws Exception {
        final boolean wrongPassword = false;
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final String[] indices = new String[]{"filtered"};

        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "readonly")
                .putList("armor.actionrequestfilter.readonly.allowed_actions", "indices:data/read/search")
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
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final String[] indices = new String[]{"internal"};

        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "scroll")
                .putList("armor.actionrequestfilter.scroll.allowed_actions", "indices:data/read/scroll", "indices:data/read/search")
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
    public void scrollClear() throws Exception {
        final boolean wrongPassword = false;
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final String[] indices = new String[]{"internal"};

        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "scroll", "forbidden")
                .putList("armor.actionrequestfilter.scroll.allowed_actions", "indices:data/read/scroll", "indices:data/read/scroll/clear", "indices:data/read/search")
                .putList("armor.actionrequestfilter.forbidden.allowed_actions", "indices:data/read/scroll", "indices:data/read/scroll/clear")
                .put(ConfigConstants.ARMOR_AGGREGATION_FILTER_ENABLED, true)
                .put(authSettings).build();

        startES(settings);

        setupTestData("ac_rules_23.json");

        Map<String, String> scrollParameters = new HashMap<>();
        scrollParameters.put("scroll", "1m");
        scrollParameters.put("size", "1");

        final Tuple<JestResult, HttpResponse> resulttu = executeSearchWithScroll("ac_query_matchall.json", indices, null,
                true, false, scrollParameters);

        final JestResult result = resulttu.v1();

        final Map json = prettyGson.fromJson(result.getJsonString(), Map.class);

        int resultCount = result.getJsonObject().getAsJsonObject("hits").getAsJsonArray("hits").size();

        Assert.assertEquals(1, resultCount);
        final String scrollId = result.getJsonObject().get("_scroll_id").getAsString();

        //Try to delete all scroll
        HeaderAwareJestHttpClient client = getJestClient(getServerUri(false), username, password);

        final Tuple<JestResult, HttpResponse> resulttu2 = client.executeE( (new ClearScroll.Builder("_all")).build());
        Assert.assertFalse(resulttu2.v1().isSucceeded());
        Assert.assertTrue(resulttu2.v1().getResponseCode() == 403);

        //Try to delete one scrollId

        final Tuple<JestResult, HttpResponse> resulttu3 = client.executeE( (new ClearScroll.Builder(scrollId)).build());
        Assert.assertTrue(resulttu3.v1().isSucceeded());
        Assert.assertTrue(resulttu3.v1().getResponseCode() == 200);

    }

    @Test
    public void searchAliasWildcard() throws Exception {
        final boolean wrongPassword = false;
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");


        final Settings settings = Settings.builder()
                .putList("armor.actionrequestfilter.names", "wild", "forbidden")
                .putList("armor.actionrequestfilter.wild.allowed_actions", "indices:data/read/search")
                .putList("armor.actionrequestfilter.forbidden.forbidden_actions", "indices:*")
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
    public void mSearchAliasWildcard() throws Exception {
        final boolean wrongPassword = false;
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final Settings settings = Settings.builder()
                .putList("armor.actionrequestfilter.names", "wild", "forbidden")
                .putList("armor.actionrequestfilter.wild.allowed_actions", "indices:data/read/search", "indices:data/read/msearch")
                .putList("armor.actionrequestfilter.forbidden.forbidden_actions", "indices:*")
                .put(ConfigConstants.ARMOR_ACTION_WILDCARD_EXPANSION_ENABLED, true)
                .put(authSettings).build();

        startES(settings);

        setupTestData("ac_rules_10.json");

        HeaderAwareJestHttpClient client = getJestClient(getServerUri(false), username, password);

        //test on indice inter* (part of wildcard) but only one request
        final String[] indices1 = new String[]{"inter*"};
        MultiSearch mSearch1 = new MultiSearch.Builder(new ArrayList<>())
                .addSearch(new Search.Builder(loadFile("ac_query_matchall_line.json"))
                        .addIndex(indices1[0]).build())
                //.setHeader("Content-Type", ContentType.APPLICATION_JSON)
                .build();
        final Tuple<JestResult, HttpResponse> resulttu1 = client.executeE(mSearch1);
        JestResult result = resulttu1.v1();
        Map json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 200);

        //test on indice financial
        final String[] indices2 = new String[]{"financial"};
        MultiSearch mSearch2 = new MultiSearch.Builder(new ArrayList<>())
                .addSearch(new Search.Builder(loadFile("ac_query_matchall_line.json"))
                        .addIndex(indices2[0]).build())
                //.setHeader("Content-Type", ContentType.APPLICATION_JSON)
                .build();
        final Tuple<JestResult, HttpResponse> resulttu2 = client.executeE(mSearch2);
        result = resulttu2.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 403);

        //test on all
        final String[] indices3 = new String[]{"_all"};
        MultiSearch mSearch3 = new MultiSearch.Builder(new ArrayList<>())
                .addSearch(new Search.Builder(loadFile("ac_query_matchall_line.json"))
                        .addIndex(indices3[0]).build())
                //.setHeader("Content-Type", ContentType.APPLICATION_JSON)
                .build();
        final Tuple<JestResult, HttpResponse> resulttu3 = client.executeE(mSearch3);
        result = resulttu3.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 200);

        //test on wildcard *
        final String[] indices4 = new String[]{"*"};
        MultiSearch mSearch4 = new MultiSearch.Builder(new ArrayList<>())
                .addSearch(new Search.Builder(loadFile("ac_query_matchall_line.json"))
                        .addIndex(indices4[0]).build())
                .build();
        final Tuple<JestResult, HttpResponse> resulttu4 = client.executeE(mSearch4);
        result = resulttu4.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        //TODO : put Assert equals 8
        Assert.assertTrue(result.getResponseCode() == 200);

        //test on wildcard interna*
        final String[] indices5 = new String[]{"interna*"};
        MultiSearch mSearch5 = new MultiSearch.Builder(new ArrayList<>())
                .addSearch(new Search.Builder(loadFile("ac_query_matchall_line.json"))
                        .addIndex(indices5[0]).build())
                .build();
        final Tuple<JestResult, HttpResponse> resulttu5 = client.executeE(mSearch5);
        result = resulttu5.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 200);

        //test on wildcard finan
        final String[] indices6 = new String[]{"finan*"};
        MultiSearch mSearch6 = new MultiSearch.Builder(new ArrayList<>())
                .addSearch(new Search.Builder(loadFile("ac_query_matchall_line.json"))
                        .addIndex(indices6[0]).build())
                .build();
        final Tuple<JestResult, HttpResponse> resulttu6 = client.executeE(mSearch6);
        result = resulttu6.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 403);

        //test allowed (internal) alias and denied index
        final String[] indices7 = new String[]{"inter*", "finan*"};
        MultiSearch mSearch7 = new MultiSearch.Builder(new ArrayList<>())
                .addSearch(new Search.Builder(loadFile("ac_query_matchall_line.json"))
                        .addIndex(indices7[0]).build())
                .addSearch(new Search.Builder(loadFile("ac_query_matchall_line.json"))
                        .addIndex(indices7[1]).build())
                .build();
        final Tuple<JestResult, HttpResponse> resulttu7 = client.executeE(mSearch7);
        result = resulttu7.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 200);
        JsonArray responsesArray7 = result.getJsonObject().get("responses").getAsJsonArray();
        Assert.assertTrue(responsesArray7.size() == 2);
        Assert.assertTrue(responsesArray7.get(0).getAsJsonObject().get("status").getAsInt() == 200);
        Assert.assertTrue(responsesArray7.get(0).getAsJsonObject().get("hits").getAsJsonObject().get("total").getAsInt() == 7);
        Assert.assertTrue(responsesArray7.get(1).getAsJsonObject().get("status").getAsInt() == 403);

        //test allowed (internal) alias and allowed index (cto)
        final String[] indices8 = new String[]{"inter*", "c*"};
        MultiSearch mSearch8 = new MultiSearch.Builder(new ArrayList<>())
                .addSearch(new Search.Builder(loadFile("ac_query_matchall_line.json"))
                        .addIndex(indices8[0]).build())
                .addSearch(new Search.Builder(loadFile("ac_query_matchall_line.json"))
                        .addIndex(indices8[1]).build())
                .build();
        final Tuple<JestResult, HttpResponse> resulttu8 = client.executeE(mSearch8);
        result = resulttu8.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 200);
        JsonArray responsesArray8 = result.getJsonObject().get("responses").getAsJsonArray();
        Assert.assertTrue(responsesArray8.size() == 2);
        Assert.assertTrue(responsesArray8.get(0).getAsJsonObject().get("status").getAsInt() == 200);
        Assert.assertTrue(responsesArray8.get(0).getAsJsonObject().get("hits").getAsJsonObject().get("total").getAsInt() == 7);
        Assert.assertTrue(responsesArray8.get(1).getAsJsonObject().get("status").getAsInt() == 200);

    }


    @Test
    public void searchWildcardMultiIndicesSingleFilter() throws Exception {
        final boolean wrongPassword = false;
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");


        final Settings settings = Settings.builder()
                .putList("armor.actionrequestfilter.names", "wild", "forbidden")
                .putList("armor.actionrequestfilter.wild.allowed_actions", "indices:data/read/search")
                .putList("armor.actionrequestfilter.forbidden.forbidden_actions", "indices:*")
                .put(ConfigConstants.ARMOR_ACTION_WILDCARD_EXPANSION_ENABLED, true)
                .put(authSettings).build();

        startES(settings);

        setupTestData("ac_rules_13.json");

        HashSet<String> allowedIndices = new HashSet<>();
        allowedIndices.addAll(Arrays.asList("financial", "marketing", "cto", "ceo"));

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
        List<Map> hits = (List) ((Map) json.get("hits")).get("hits");
        for (Map<String, Object> hit : hits) {
            Assert.assertTrue(allowedIndices.contains(hit.get("_index")));
        }

        //test on allowed alias + allowed index
        final String[] indices5 = new String[]{"financial", "cxo"};
        final Tuple<JestResult, HttpResponse> resulttu5 = executeSearch("ac_query_matchall.json", indices5, null,
                true, false);
        result = resulttu5.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 200);
        hits = (List) ((Map) json.get("hits")).get("hits");
        for (Map<String, Object> hit : hits) {
            Assert.assertTrue(allowedIndices.contains(hit.get("_index")));
        }

        //test on allowed alias + allowed index with wildcard
        final String[] indices6 = new String[]{"financial", "cx*"};
        final Tuple<JestResult, HttpResponse> resulttu6 = executeSearch("ac_query_matchall.json", indices6, null,
                true, false);
        result = resulttu6.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 200);
        hits = (List) ((Map) json.get("hits")).get("hits");
        for (Map<String, Object> hit : hits) {
            Assert.assertTrue(allowedIndices.contains(hit.get("_index")));
        }

        //test on allowed indice + allowed index with wildcard
        final String[] indices7 = new String[]{"marketing", "fin*"};
        final Tuple<JestResult, HttpResponse> resulttu7 = executeSearch("ac_query_matchall.json", indices7, null,
                true, false);
        result = resulttu7.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 200);
        hits = (List) ((Map) json.get("hits")).get("hits");
        for (Map<String, Object> hit : hits) {
            Assert.assertTrue(allowedIndices.contains(hit.get("_index")));
        }

        //test on allowed alias + allowed alias with wildcard
        final String[] indices8 = new String[]{"internal", "c*"};
        final Tuple<JestResult, HttpResponse> resulttu8 = executeSearch("ac_query_matchall.json", indices8, null,
                true, false);
        result = resulttu8.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 200);
        hits = (List) ((Map) json.get("hits")).get("hits");
        for (Map<String, Object> hit : hits) {
            Assert.assertTrue(allowedIndices.contains(hit.get("_index")));
        }

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
                .putList("armor.actionrequestfilter.names", "reader", "writer", "forbidden")
                .putList("armor.actionrequestfilter.reader.allowed_actions", "indices:data/read/search")
                .putList("armor.actionrequestfilter.reader.forbidden_actions", "indices:data/write*")
                .putList("armor.actionrequestfilter.writer.allowed_actions", "indices:data/read/search", "indices:data/read/write", "indices:admin/settings/update")
                .putList("armor.actionrequestfilter.forbidden.forbidden_actions", "indices:*")
                .put(ConfigConstants.ARMOR_ACTION_WILDCARD_EXPANSION_ENABLED, true)
                .put(authSettings).build();

        startES(settings);

        setupTestData("ac_rules_14.json");

        Set<String> allowedIndices = new HashSet<>();
        allowedIndices.addAll(Arrays.asList("financial", "marketing", "cto", "ceo"));

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
        List<Map> hits = (List) ((Map) json.get("hits")).get("hits");
        for (Map<String, Object> hit : hits) {
            Assert.assertTrue(allowedIndices.contains(hit.get("_index")));
        }


        //test on allowed alias + allowed index
        final String[] indices5 = new String[]{"financial", "cxo"};
        final Tuple<JestResult, HttpResponse> resulttu5 = executeSearch("ac_query_matchall.json", indices5, null,
                true, false);
        result = resulttu5.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 200);
        hits = (List) ((Map) json.get("hits")).get("hits");
        for (Map<String, Object> hit : hits) {
            Assert.assertTrue(allowedIndices.contains(hit.get("_index")));
        }


        //test on allowed alias + allowed index with wildcard
        final String[] indices6 = new String[]{"financial", "cx*"};
        final Tuple<JestResult, HttpResponse> resulttu6 = executeSearch("ac_query_matchall.json", indices6, null,
                true, false);
        result = resulttu6.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 200);
        hits = (List) ((Map) json.get("hits")).get("hits");
        for (Map<String, Object> hit : hits) {
            Assert.assertTrue(allowedIndices.contains(hit.get("_index")));
        }


        //test on allowed indice + allowed index with wildcard
        final String[] indices7 = new String[]{"marketing", "fin*"};
        final Tuple<JestResult, HttpResponse> resulttu7 = executeSearch("ac_query_matchall.json", indices7, null,
                true, false);
        result = resulttu7.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 200);
        hits = (List) ((Map) json.get("hits")).get("hits");
        for (Map<String, Object> hit : hits) {
            Assert.assertTrue(allowedIndices.contains(hit.get("_index")));
        }


        //test on allowed alias + allowed alias with wildcard
        final String[] indices8 = new String[]{"internal", "c*"};
        final Tuple<JestResult, HttpResponse> resulttu8 = executeSearch("ac_query_matchall.json", indices8, null,
                true, false);
        result = resulttu8.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 200);
        hits = (List) ((Map) json.get("hits")).get("hits");
        for (Map<String, Object> hit : hits) {
            Assert.assertTrue(allowedIndices.contains(hit.get("_index")));
        }


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
        final List<String> indices11 = Arrays.asList("internal", "c*");
        HeaderAwareJestHttpClient client = getJestClient(getServerUri(false), username, password);
        final String settingSource = "{\"index.refresh_interval\" : \"5s\" }";
        final Tuple<JestResult, HttpResponse> resulttu11 = client.executeE(new UpdateSettings.Builder(settingSource).addIndices(indices11).build());
        result = resulttu11.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 403);

        //test write on forbidden alias with allowed indice
        final List<String> indices12 = Arrays.asList("financial", "internal");
        client = getJestClient(getServerUri(false), username, password);
        final String settingSource2 = "{\"index.refresh_interval\" : \"5s\" }";
        final Tuple<JestResult, HttpResponse> resulttu12 = client.executeE(new UpdateSettings.Builder(settingSource2).addIndices(indices12).build());
        result = resulttu12.v1();
        json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 403);

        final List<String> indices13 = Arrays.asList("financial", "marketing");
        client = getJestClient(getServerUri(false), username, password);
        final String settingSource3 = "{\"index.refresh_interval\" : \"5s\" }";
        final Tuple<JestResult, HttpResponse> resulttu13 = client.executeE(new UpdateSettings.Builder(settingSource3).addIndices(indices13).build());
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
                .putList("armor.actionrequestfilter.names", "reader", "writer", "forbidden")
                .putList("armor.actionrequestfilter.reader.allowed_actions", "indices:data/read/search")
                .putList("armor.actionrequestfilter.reader.forbidden_actions", "indices:data/write*,indices:admin/settings/update*")
                .putList("armor.actionrequestfilter.writer.allowed_actions", "indices:data/read/search", "indices:data/read/write", "indices:admin/settings/update")
                .putList("armor.actionrequestfilter.forbidden.forbidden_actions", "indices:*")
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


    @Test
    public void searchAnIndiceWhichResolvesToAnAlias() throws Exception {
        final boolean wrongPassword = false;
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");


        final Settings settings = Settings.builder()
                .putList("armor.actionrequestfilter.names", "reader","forbidden")
                .putList("armor.actionrequestfilter.reader.allowed_actions", "indices:data/read/search")
                .putList("armor.actionrequestfilter.reader.forbidden_actions", "indices:data/write*,indices:admin/settings/update*")
                .putList("armor.actionrequestfilter.forbidden.forbidden_actions", "indices:*")
                .put(ConfigConstants.ARMOR_ACTION_WILDCARD_EXPANSION_ENABLED, false)
                .put(authSettings).build();

        startES(settings);

        setupTestData("ac_rules_21.json");

        //search on a alias which is mapped to an indice in the rules
        String[] indices1 = {"internal"};
        final Tuple<JestResult, HttpResponse> resulttu1 = executeSearch("ac_query_matchall.json", indices1, null,
                true, false);
        JestResult result = resulttu1.v1();
        Map json = prettyGson.fromJson(result.getJsonString(), Map.class);
        Assert.assertTrue(result.getResponseCode() == 200);

    }
}
