package com.petalmd.armor;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.petalmd.armor.util.ConfigConstants;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ElasticsearchStatusException;
import org.elasticsearch.action.admin.indices.settings.put.UpdateSettingsRequest;
import org.elasticsearch.action.search.*;
import org.elasticsearch.action.support.master.AcknowledgedResponse;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.common.xcontent.LoggingDeprecationHandler;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.search.SearchModule;
import org.elasticsearch.search.aggregations.bucket.terms.Terms;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Created by bdiasse on 20/02/17.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class SearchTests extends AbstractArmorTest {


    @Test
    public void searchAggregationWithMinDocsCount() throws Exception {
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

        final SearchResponse sResp = executeSearch("ac_query_aggs_terms_mincount.json", indices,
                true, false);

        Terms tAggs1 = sResp.getAggregations().get("1");
        int aggs1ResSize = tAggs1.getBuckets().size();

        Terms tAggs2 = sResp.getAggregations().get("2");
        int aggs2ResSize = tAggs2.getBuckets().size();

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


        final SearchResponse sResp = executeSearchWithScroll("ac_query_matchall.json", indices, true, false, TimeValue.timeValueMinutes(1), 3);

        long resultCount = sResp.getHits().getHits().length;

        Assert.assertEquals(3, resultCount);
    }


    @Test
    public void scrollClear() throws Exception {
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


        final SearchResponse sResp1 = executeSearchWithScroll("ac_query_matchall.json", indices, true, false, TimeValue.timeValueMinutes(1), 1);

        long resultCount = sResp1.getHits().getHits().length;

        Assert.assertEquals(1, resultCount);
        final String scrollId = sResp1.getScrollId();

        //Try to delete all scroll
        RestHighLevelClient client = getRestClient(false, username, password);

        ClearScrollRequest csr = new ClearScrollRequest();
        csr.addScrollId("_all");
        ElasticsearchStatusException csFail = expectThrows(ElasticsearchStatusException.class, () -> client.clearScroll(csr, RequestOptions.DEFAULT));
        Assert.assertTrue(csFail.status().equals(RestStatus.FORBIDDEN));

        //Try to delete one scrollId
        ClearScrollRequest csr2 = new ClearScrollRequest();
        csr2.addScrollId(sResp1.getScrollId());
        ClearScrollResponse csResp = client.clearScroll(csr2, RequestOptions.DEFAULT);
        Assert.assertTrue(csResp.isSucceeded());

    }

    @Test
    public void searchAliasWildcard() throws Exception {
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
        final SearchResponse sResp1 = executeSearch("ac_query_matchall.json", indices1, true, false);
        Assert.assertTrue(sResp1.status().equals(RestStatus.OK));

        //test on indice financial
        final String[] indices2 = new String[]{"financial"};
        ElasticsearchStatusException sFailure1 = expectThrows(ElasticsearchStatusException.class, () -> executeSearch("ac_query_matchall.json", indices2, false, false));
        Assert.assertTrue(sFailure1.status().equals(RestStatus.FORBIDDEN));

        //test on all
        final String[] indices3 = new String[]{"_all"};
        final SearchResponse sResp3 = executeSearch("ac_query_matchall.json", indices3, true, false);
        Assert.assertTrue(sResp3.status().equals(RestStatus.OK));


        //test on wildcard *
        final String[] indices4 = new String[]{};
        final SearchResponse sResp4 = executeSearch("ac_query_matchall.json", indices4, true, false);
        Assert.assertTrue(sResp4.status().equals(RestStatus.OK));

        //test on wildcard interna*
        final String[] indices5 = new String[]{"interna*"};
        final SearchResponse sResp5 = executeSearch("ac_query_matchall.json", indices5, true, false);
        Assert.assertTrue(sResp5.status().equals(RestStatus.OK));

        //test on wildcard finan
        final String[] indices6 = new String[]{"finan*"};
        ElasticsearchStatusException sFailure2 = expectThrows(ElasticsearchStatusException.class, () -> executeSearch("ac_query_matchall.json", indices6, false, false));
        Assert.assertTrue(sFailure2.status().equals(RestStatus.FORBIDDEN));

    }

    @Test
    public void mSearchAliasWildcard() throws Exception {
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

        RestHighLevelClient client = getRestClient(false, username, password);

        //test on indice inter* (part of wildcard) but only one request
        final String index1 = "inter*";
        MultiSearchResponse msResp1 = client.msearch(new MultiSearchRequest().add(createSearchRequest(index1, loadFile("ac_query_matchall_line.json"))), RequestOptions.DEFAULT);
        Assert.assertTrue(Arrays.stream(msResp1.getResponses()).allMatch((s -> s.getResponse().status().equals(RestStatus.OK))));

        //test on indice financial
        final String index2 = "financial";
        ElasticsearchStatusException forbid1 = expectThrows(ElasticsearchStatusException.class, () -> client.msearch(new MultiSearchRequest().add(createSearchRequest(index2, loadFile("ac_query_matchall_line.json"))), RequestOptions.DEFAULT));
        Assert.assertTrue(forbid1.status().equals(RestStatus.FORBIDDEN));


        //test on all
        final String index3 = "_all";
        MultiSearchResponse msResp3 = client.msearch(new MultiSearchRequest().add(createSearchRequest(index3, loadFile("ac_query_matchall_line.json"))), RequestOptions.DEFAULT);
        Assert.assertTrue(Arrays.stream(msResp3.getResponses()).noneMatch(s -> s.isFailure()));
        Assert.assertEquals(8, Arrays.stream(msResp3.getResponses())
                .flatMap(s -> Arrays.stream(s.getResponse().getHits().getHits())).count());

        //test on wildcard *
        final String index4 = "*";
        //TODO : put Assert equals 8
        MultiSearchResponse msResp4 = client.msearch(new MultiSearchRequest().add(createSearchRequest(index4, loadFile("ac_query_matchall_line.json"))), RequestOptions.DEFAULT);
        Assert.assertTrue(Arrays.stream(msResp4.getResponses()).allMatch((s -> s.getResponse().status().equals(RestStatus.OK))));
        Assert.assertEquals(8, Arrays.stream(msResp3.getResponses())
                .flatMap(s -> Arrays.stream(s.getResponse().getHits().getHits())).count());


        //test on wildcard interna*
        final String index5 = "interna*";
        MultiSearchResponse msResp5 = client.msearch(new MultiSearchRequest().add(createSearchRequest(index5, loadFile("ac_query_matchall_line.json"))), RequestOptions.DEFAULT);
        Assert.assertTrue(Arrays.stream(msResp5.getResponses()).allMatch((s -> s.getResponse().status().equals(RestStatus.OK))));


        //test on wildcard finan
        final String index6 = "finan*";
        ElasticsearchStatusException forbid2 = expectThrows(ElasticsearchStatusException.class, () -> client.msearch(new MultiSearchRequest().add(createSearchRequest(index6, loadFile("ac_query_matchall_line.json"))), RequestOptions.DEFAULT));
        Assert.assertTrue(forbid2.status().equals(RestStatus.FORBIDDEN));

        //test allowed (internal) alias and denied index
        final String index7_1 = "inter*";
        final String index7_2 = "finan*";
        MultiSearchResponse msResp7 = client.msearch(new MultiSearchRequest()
                        .add(createSearchRequest(index7_1, loadFile("ac_query_matchall_line.json")))
                        .add(createSearchRequest(index7_2, loadFile("ac_query_matchall_line.json")))
                , RequestOptions.DEFAULT);
        MultiSearchResponse.Item sr71 = msResp7.getResponses()[0];
        Assert.assertTrue(sr71.getResponse().status().equals(RestStatus.OK));
        Assert.assertEquals(7, sr71.getResponse().getHits().getTotalHits().value);
        MultiSearchResponse.Item sr72 = msResp7.getResponses()[1];
        Assert.assertTrue(sr72.isFailure());
        ElasticsearchException sr72fail = (ElasticsearchException) sr72.getFailure();
        Assert.assertTrue(sr72fail.getDetailedMessage().contains("forbidden_exception"));
        Assert.assertTrue(sr72fail.getDetailedMessage().contains("indices:data/read/search"));

        //test allowed (internal) alias and allowed index (cto)
        final String index8_1 = "inter*";
        final String index8_2 = "c*";

        MultiSearchResponse msResp8 = client.msearch(new MultiSearchRequest()
                        .add(createSearchRequest(index8_1, loadFile("ac_query_matchall_line.json")))
                        .add(createSearchRequest(index8_2, loadFile("ac_query_matchall_line.json")))
                , RequestOptions.DEFAULT);
        MultiSearchResponse.Item sr81 = msResp8.getResponses()[0];
        Assert.assertTrue(sr81.getResponse().status().equals(RestStatus.OK));
        Assert.assertEquals(7, sr81.getResponse().getHits().getTotalHits().value);
        MultiSearchResponse.Item sr82 = msResp8.getResponses()[1];
        Assert.assertTrue(sr82.getResponse().status().equals(RestStatus.OK));

    }


    @Test
    public void searchWildcardMultiIndicesSingleFilter() throws Exception {
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
        final ElasticsearchException sFail1 = expectThrows(ElasticsearchException.class, () -> executeSearch("ac_query_matchall.json", indices1, false, false));
        Assert.assertEquals(RestStatus.FORBIDDEN, sFail1.status());

        //test on  forbidden indice + allowed alias
        final String[] indices2 = new String[]{"cto", "cxo"};
        final ElasticsearchException sFail2 = expectThrows(ElasticsearchException.class, () -> executeSearch("ac_query_matchall.json", indices2, false, false));
        Assert.assertEquals(RestStatus.FORBIDDEN, sFail2.status());


        //test on forbidden indice + allowed indice
        final String[] indices3 = new String[]{"ceo", "financial"};
        final ElasticsearchException sFail3 = expectThrows(ElasticsearchException.class, () -> executeSearch("ac_query_matchall.json", indices3, false, false));
        Assert.assertTrue(sFail3.status().equals(RestStatus.FORBIDDEN));


        //test on *
        final String[] indices4 = new String[]{"*"};
        final SearchResponse sResp4 = executeSearch("ac_query_matchall.json", indices4, true, false);
        Assert.assertTrue(Arrays.stream(sResp4.getHits().getHits()).allMatch(h -> allowedIndices.contains(h.getIndex())));

        //test on allowed alias + allowed index
        final String[] indices5 = new String[]{"financial", "cxo"};
        final SearchResponse sResp5 = executeSearch("ac_query_matchall.json", indices5, true, false);
        Assert.assertTrue(Arrays.stream(sResp5.getHits().getHits()).allMatch(h -> allowedIndices.contains(h.getIndex())));

        //test on allowed alias + allowed index with wildcard
        final String[] indices6 = new String[]{"financial", "cx*"};
        final SearchResponse sResp6 = executeSearch("ac_query_matchall.json", indices6, true, false);
        Assert.assertTrue(Arrays.stream(sResp6.getHits().getHits()).allMatch(h -> allowedIndices.contains(h.getIndex())));

        //test on allowed indice + allowed index with wildcard
        final String[] indices7 = new String[]{"marketing", "fin*"};
        final SearchResponse sResp7 = executeSearch("ac_query_matchall.json", indices7, true, false);
        Assert.assertTrue(Arrays.stream(sResp7.getHits().getHits()).allMatch(h -> allowedIndices.contains(h.getIndex())));

        //test on allowed alias + allowed alias with wildcard
        final String[] indices8 = new String[]{"internal", "c*"};
        final SearchResponse sResp8 = executeSearch("ac_query_matchall.json", indices8, true, false);
        Assert.assertTrue(Arrays.stream(sResp8.getHits().getHits()).allMatch(h -> allowedIndices.contains(h.getIndex())));

        //test on forbidden indice
        final String[] indices9 = new String[]{"ceo"};
        final ElasticsearchException sFail9 = expectThrows(ElasticsearchException.class, () -> executeSearch("ac_query_matchall.json", indices9, false, false));
        Assert.assertTrue(sFail9.status().equals(RestStatus.FORBIDDEN));

        //test on forbidden alias
        final String[] indices10 = new String[]{"crucial"};
        final ElasticsearchException sFail10 = expectThrows(ElasticsearchException.class, () -> executeSearch("ac_query_matchall.json", indices10, false, false));
        Assert.assertTrue(sFail10.status().equals(RestStatus.FORBIDDEN));
    }

    @Test
    public void searchWildcardMultiIndicesMultiRules() throws Exception {
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
        ElasticsearchStatusException sFail1 = expectThrows(ElasticsearchStatusException.class, () -> executeSearch("ac_query_matchall.json", indices1, false, false));
        Assert.assertTrue(sFail1.status().equals(RestStatus.FORBIDDEN));

        //test on  forbidden indice + allowed alias
        final String[] indices2 = new String[]{"cto", "cxo"};
        ElasticsearchStatusException sFail2 = expectThrows(ElasticsearchStatusException.class, () -> executeSearch("ac_query_matchall.json", indices2, false, false));
        Assert.assertTrue(sFail2.status().equals(RestStatus.FORBIDDEN));


        //test on forbidden indice + allowed indice
        final String[] indices3 = new String[]{"ceo", "financial"};
        ElasticsearchStatusException sFail3 = expectThrows(ElasticsearchStatusException.class, () -> executeSearch("ac_query_matchall.json", indices3, false, false));
        Assert.assertTrue(sFail3.status().equals(RestStatus.FORBIDDEN));


        //test on *
        final String[] indices4 = new String[]{"*"};
        final SearchResponse sResp4 = executeSearch("ac_query_matchall.json", indices4, true, false);
        Assert.assertTrue(Arrays.stream(sResp4.getHits().getHits()).allMatch(h -> allowedIndices.contains(h.getIndex())));


        //test on allowed alias + allowed index
        final String[] indices5 = new String[]{"financial", "cxo"};
        final SearchResponse sResp5 = executeSearch("ac_query_matchall.json", indices5, true, false);
        Assert.assertTrue(Arrays.stream(sResp5.getHits().getHits()).allMatch(h -> allowedIndices.contains(h.getIndex())));

        //test on allowed alias + allowed index with wildcard
        final String[] indices6 = new String[]{"financial", "cx*"};
        final SearchResponse sResp6 = executeSearch("ac_query_matchall.json", indices6, true, false);
        Assert.assertTrue(Arrays.stream(sResp6.getHits().getHits()).allMatch(h -> allowedIndices.contains(h.getIndex())));


        //test on allowed indice + allowed index with wildcard
        final String[] indices7 = new String[]{"marketing", "fin*"};
        final SearchResponse sResp7 = executeSearch("ac_query_matchall.json", indices7, true, false);
        Assert.assertTrue(Arrays.stream(sResp7.getHits().getHits()).allMatch(h -> allowedIndices.contains(h.getIndex())));


        //test on allowed alias + allowed alias with wildcard
        final String[] indices8 = new String[]{"internal", "c*"};
        final SearchResponse sResp8 = executeSearch("ac_query_matchall.json", indices8, true, false);
        Assert.assertTrue(Arrays.stream(sResp8.getHits().getHits()).allMatch(h -> allowedIndices.contains(h.getIndex())));


        //test on forbidden indice
        final String[] indices9 = new String[]{"ceo"};
        ElasticsearchStatusException sFail9 = expectThrows(ElasticsearchStatusException.class, () -> executeSearch("ac_query_matchall.json", indices3, false, false));
        Assert.assertTrue(sFail9.status().equals(RestStatus.FORBIDDEN));


        //test on forbidden alias
        final String[] indices10 = new String[]{"crucial"};
        ElasticsearchStatusException sFail10 = expectThrows(ElasticsearchStatusException.class, () -> executeSearch("ac_query_matchall.json", indices3, false, false));
        Assert.assertTrue(sFail10.status().equals(RestStatus.FORBIDDEN));


        //test write on forbidden alias with allowed alias
        final String[] indices11 = new String[] {"internal", "c*"};
        final RestHighLevelClient client = getRestClient(false, username, password);
        final Settings settings11 = Settings.builder().put("index.refresh_interval","5s").build();
        ElasticsearchStatusException sFail11 = expectThrows(ElasticsearchStatusException.class, () -> client.indices().putSettings(new UpdateSettingsRequest(indices11).settings(settings11),RequestOptions.DEFAULT));
        Assert.assertTrue(sFail11.status().equals(RestStatus.FORBIDDEN));

        //test write on forbidden alias with allowed indice
        final String[] indices12 = new String[]{"financial", "internal"};
        final Settings settings12 = Settings.builder().put("index.refresh_interval","5s").build();
        ElasticsearchStatusException sFail12 = expectThrows(ElasticsearchStatusException.class, () -> client.indices().putSettings(new UpdateSettingsRequest(indices12).settings(settings12),RequestOptions.DEFAULT));
        Assert.assertTrue(sFail12.status().equals(RestStatus.FORBIDDEN));

        final String[] indices13 = new String[]{"financial", "marketing"};
        final Settings settings13 = Settings.builder().put("index.refresh_interval","5s").build();
        AcknowledgedResponse upResp = client.indices().putSettings(new UpdateSettingsRequest(indices13).settings(settings13),RequestOptions.DEFAULT);
        Assert.assertTrue(upResp.isAcknowledged());
    }

    @Test
    public void searchWildcardMultiIndicesMultiRulesNoWildCardExpansion() throws Exception {
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
        ElasticsearchStatusException sFail1 = expectThrows(ElasticsearchStatusException.class, () -> executeSearch("ac_query_matchall.json", indices1, false, false));
        Assert.assertTrue(sFail1.status().equals(RestStatus.FORBIDDEN));

        //test on  forbidden indice + allowed alias
        final String[] indices2 = new String[]{"cto", "cxo"};
        ElasticsearchStatusException sFail2 = expectThrows(ElasticsearchStatusException.class, () -> executeSearch("ac_query_matchall.json", indices2, false, false));
        Assert.assertTrue(sFail2.status().equals(RestStatus.FORBIDDEN));

        //test on forbidden indice + allowed indice
        final String[] indices3 = new String[]{"ceo", "financial"};
        ElasticsearchStatusException sFail3 = expectThrows(ElasticsearchStatusException.class, () -> executeSearch("ac_query_matchall.json", indices3, false, false));
        Assert.assertTrue(sFail3.status().equals(RestStatus.FORBIDDEN));

        //test on *
        final String[] indices4 = new String[]{"*"};
        ElasticsearchStatusException sFail4 = expectThrows(ElasticsearchStatusException.class, () -> executeSearch("ac_query_matchall.json", indices4, false, false));
        Assert.assertTrue(sFail4.status().equals(RestStatus.FORBIDDEN));

    }


    @Test
    public void searchAnIndiceWhichResolvesToAnAlias() throws Exception {
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");


        final Settings settings = Settings.builder()
                .putList("armor.actionrequestfilter.names", "reader", "forbidden")
                .putList("armor.actionrequestfilter.reader.allowed_actions", "indices:data/read/search")
                .putList("armor.actionrequestfilter.reader.forbidden_actions", "indices:data/write*,indices:admin/settings/update*")
                .putList("armor.actionrequestfilter.forbidden.forbidden_actions", "indices:*")
                .put(ConfigConstants.ARMOR_ACTION_WILDCARD_EXPANSION_ENABLED, false)
                .put(authSettings).build();

        startES(settings);

        setupTestData("ac_rules_21.json");

        //search on a alias which is mapped to an indice in the rules
        String[] indices1 = {"internal"};
        final SearchResponse sResp = executeSearch("ac_query_matchall.json", indices1, true, false);
        Assert.assertTrue(sResp.status().equals(RestStatus.OK));

    }

    private SearchRequest createSearchRequest(String index, String jsonQuery) throws IOException {

        SearchModule searchModule = new SearchModule(Settings.EMPTY, false, Collections.emptyList());

        SearchRequest sr = new SearchRequest(index)
                .source(SearchSourceBuilder.fromXContent(
                        XContentFactory.xContent(XContentType.JSON)
                                .createParser(new NamedXContentRegistry(searchModule.getNamedXContents()), LoggingDeprecationHandler.INSTANCE, jsonQuery)));

        return sr;
    }
}
