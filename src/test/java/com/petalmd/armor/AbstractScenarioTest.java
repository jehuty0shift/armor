package com.petalmd.armor;

import org.elasticsearch.ElasticsearchStatusException;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestStatus;
import org.junit.Assert;
import org.junit.runner.RunWith;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
public abstract class AbstractScenarioTest extends AbstractArmorTest {

    protected SearchResponse baseQuery(final Settings settings, final String acRulesFile, final String queryFile, final int expectedCount,
                                       final String[] indices, final String[] types) throws Exception {
        startES(settings);
        setupTestData(acRulesFile);
        log.debug("------------------------------------------------------------------------------------------------------------------------------------------------------------------------");
        final SearchResponse sResp = executeSearch(queryFile, indices, true, false);
        Assert.assertEquals(sResp.getHits().getTotalHits().value, expectedCount);
        return sResp;
    }

    protected SearchResponse baseQuery(final Settings settings, final String acRulesFile, final String queryFile, final int expectedCount)
            throws Exception {
        return baseQuery(settings, acRulesFile, queryFile, expectedCount, null, null);
    }

    protected SearchResponse baseQuery(final Settings settings, final String acRulesFile, final String queryFile, final int expectedCount,
                                       final String[] indices) throws Exception {
        return baseQuery(settings, acRulesFile, queryFile, expectedCount, indices, null);
    }

    protected void simpleDlsScenario(final Settings additionalSettings) throws Exception {

        final Settings settings = Settings.builder().putList("armor.dlsfilter.names", "dummy2-only")
                .putList("armor.actionrequestfilter.names", "readonly")
                .putList("armor.actionrequestfilter.readonly.allowed_actions", "indices:data/read/search")
                .putList("armor.dlsfilter.dummy2-only", "term", "user", "umberto", "true")
                .put(additionalSettings == null ? Settings.EMPTY : additionalSettings).build();

        baseQuery(settings, "ac_rules_execute_all.json", "ac_query_matchall.json", 2, new String[]{"ceo", "future"});
    }

    protected void simpleFlsScenarioExclude(final Settings additionalSettings) throws Exception {

        final Settings settings = Settings
                .builder()
                .putList("armor.actionrequestfilter.names", "readonly")
                .putList("armor.actionrequestfilter.readonly.allowed_actions", "indices:data/read/search")
                .putList("armor.dlsfilter.names", "dummy2-only")
                .putList("armor.dlsfilter.dummy2-only", "term", "user", "umberto", "false")
                .putList("armor.flsfilter.names", "special-fields-only")
                .putList("armor.flsfilter.special-fields-only", "special-fields-only")
                .putList("armor.flsfilter.special-fields-only.source_excludes", "structure.thearray", "structure.thesubobject2",
                        "message").putList("armor.flsfilter.special-fields-only.source_includes", "*") //same as "" or null
                .put(additionalSettings == null ? Settings.EMPTY : additionalSettings).build();

        final SearchResponse sResp = baseQuery(settings, "ac_rules_execute_all.json", "ac_query_matchall.json", 1, new String[]{"ceo", "future"});

        String jsonResp = sResp.toString();
        log.debug(jsonResp);

        Assert.assertTrue(!jsonResp.contains("message"));
        Assert.assertTrue(!jsonResp.contains("thearray"));
        Assert.assertTrue(!jsonResp.contains("thesubobject2"));
        Assert.assertTrue(!jsonResp.contains("so2subkey4"));
        Assert.assertTrue(jsonResp.contains("thesubobject"));
        Assert.assertTrue(jsonResp.contains("user"));

        Assert.assertTrue(jsonResp.contains("_source"));
        Assert.assertTrue(!jsonResp.contains("\"_source\":{}"));

    }

    protected void simpleFlsScenarioInclude(final Settings additionalSettings) throws Exception {

        final Settings settings = Settings.builder()
                .putList("armor.actionrequestfilter.names", "readonly")
                .putList("armor.actionrequestfilter.readonly.allowed_actions", "indices:data/read/search")
                .putList("armor.dlsfilter.names", "dummy2-only")
                .putList("armor.dlsfilter.dummy2-only", "term", "user", "umberto", "false")
                .putList("armor.flsfilter.names", "special-fields-only")
                .putList("armor.flsfilter.special-fields-only", "special-fields-only")
                .putList("armor.flsfilter.special-fields-only.source_excludes", "")
                //same as null
                .putList("armor.flsfilter.special-fields-only.source_includes", "message")
                .put(additionalSettings == null ? Settings.EMPTY : additionalSettings).build();

        final SearchResponse sResp = baseQuery(settings, "ac_rules_execute_all.json", "ac_query_matchall.json", 1, new String[]{"ceo", "future"});

        String jsonResp = sResp.toString();
        log.debug(jsonResp);

        Assert.assertTrue(jsonResp.contains("message"));
        Assert.assertTrue(!jsonResp.contains("thearray"));
        Assert.assertTrue(!jsonResp.contains("thesubobject2"));
        Assert.assertTrue(!jsonResp.contains("so2subkey4"));
        Assert.assertTrue(!jsonResp.contains("thesubobject"));
        Assert.assertTrue(!jsonResp.contains("user"));
        Assert.assertTrue(!jsonResp.contains("structure"));

        Assert.assertTrue(jsonResp.contains("_source"));
        Assert.assertTrue(!jsonResp.contains("\"_source\":{}"));

    }

    protected void simpleFlsScenarioFields(final Settings additionalSettings) throws Exception {

        //without dls filter
        /*
         * "hits": [
        {
        "_index": "ceo",
        "_type": "internal",
        "_id": "tp_1",
        "_score": 1.0,
        "_source": {
          "structure.thesubfield2": [
            "yepp"
          ],
          "user": [
            "umberto"
          ]
        }
        }
         */

        //test will use source filtering
        final Settings settings = Settings.builder().putList("armor.dlsfilter.names", "dummy2-only")
                .putList("armor.actionrequestfilter.names", "readonly")
                .putList("armor.actionrequestfilter.readonly.allowed_actions", "indices:data/read/search")
                .putList("armor.dlsfilter.dummy2-only", "term", "user", "umberto", "false")
                .putList("armor.flsfilter.names", "special-fields-only")
                .putList("armor.flsfilter.special-fields-only", "special-fields-only")
                .putList("armor.flsfilter.special-fields-only.source_excludes", "structure.the*field2")
                .putList("armor.flsfilter.special-fields-only.source_includes", "message") //does have not effect because to a "field"
                .put(additionalSettings == null ? Settings.EMPTY : additionalSettings).build();

        final SearchResponse sResp = baseQuery(settings, "ac_rules_execute_all.json", "ac_query_matchall_twofields.json", 1, new String[]{"ceo",
                "future"});

        String jsonResp = sResp.toString();
        log.debug(jsonResp);

        Assert.assertTrue(!jsonResp.contains("message"));
        Assert.assertTrue(!jsonResp.contains("thearray"));
        Assert.assertTrue(!jsonResp.contains("thesubfield2"));
        Assert.assertTrue(!jsonResp.contains("structure"));
        Assert.assertTrue(jsonResp.contains("user"));

    }

    protected void searchOnlyAllowed(final Settings additionalSettings, final boolean wrongPwd) throws Exception {
        final String[] indices = new String[]{"internal"};

        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "readonly")
                .putList("armor.actionrequestfilter.readonly.allowed_actions", "indices:data/read/search")
                .put(additionalSettings == null ? Settings.EMPTY : additionalSettings).build();

        startES(settings);

        setupTestData("ac_rules_1.json");

        log.debug("searchOnlyAllowed() ------------------------------------------------------------------------------------------------------------------------------------------------------------------------");

        if (!wrongPwd) {
            SearchResponse sResp = executeSearch("ac_query_matchall.json", indices, true, false);
            Assert.assertEquals(7, sResp.getHits().getTotalHits().value);

            ElasticsearchStatusException failure = expectThrows(ElasticsearchStatusException.class, () -> executeGet(indices[0],  "dummy", false, false));
//            assertJestResultError(result, "ForbiddenException[Forbidden action RestGetAction . Allowed actions: [RestSearchAction]]");
            failure.getDetailedMessage().equals("{\"root_cause\":[{\"type\":\"forbidden_exception\",\"reason\":\"Action 'indices:data/read/get' is forbidden due to [DEFAULT]\"}],\"type\":\"forbidden_exception\",\"reason\":\"Action 'indices:data/read/get' is forbidden due to [DEFAULT]\"}");
            ElasticsearchStatusException failure2 = expectThrows(ElasticsearchStatusException.class, () -> executeIndexAsString("{}", indices[0], "id1", false, false));
//            assertJestResultError(result, "ForbiddenException[Forbidden action RestIndexAction . Allowed actions: [RestSearchAction]]");
            failure2.getDetailedMessage().equals("{\"root_cause\":[{\"type\":\"forbidden_exception\",\"reason\":\"Action 'indices:data/write/index' is forbidden due to [DEFAULT]\"}],\"type\":\"forbidden_exception\",\"reason\":\"Action 'indices:data/write/index' is forbidden due to [DEFAULT]\"}");

        } else {

            ElasticsearchStatusException failure1 = expectThrows(ElasticsearchStatusException.class, () -> executeSearch("ac_query_matchall.json", indices, false, false));
            failure1.getDetailedMessage().contains("Cannot authenticate user");
            failure1.getDetailedMessage().contains("Unauthorized");
            failure1.getDetailedMessage().contains("No user");

            ElasticsearchStatusException failure2 = expectThrows(ElasticsearchStatusException.class, () -> executeGet(indices[0],  "dummy", false, false));
            failure2.getDetailedMessage().contains("Cannot authenticate user");
            failure2.getDetailedMessage().contains("Unauthorized");
            failure2.getDetailedMessage().contains("No user");

            ElasticsearchStatusException failure3 = expectThrows(ElasticsearchStatusException.class, () -> executeIndexAsString("{}", indices[0], "idDummy", false, false));
            failure3.getDetailedMessage().contains("Cannot authenticate user");
            failure3.getDetailedMessage().contains("Unauthorized");
            failure3.getDetailedMessage().contains("No user");

        }
    }

    protected void searchOnlyAllowedMoreFilters(final Settings additionalSettings, final boolean wrongPwd) throws Exception {
        final Settings settings = Settings.builder()
                .putList("armor.actionrequestfilter.names", "readonly", "no-ne")
                .putList("armor.actionrequestfilter.readonly.allowed_actions", "indices:data/read/search")
                .putList("armor.actionrequestfilter.no-ne.allowed_actions", "indices:data/read/search")
                .put(additionalSettings == null ? Settings.EMPTY : additionalSettings).build();

        searchOnlyAllowed(settings, wrongPwd);
    }

    protected void searchOnlyAllowedAction(final Settings additionalSettings, final boolean wrongPwd) throws Exception {
        final String[] indices = new String[]{"internal"};

        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "readonly")
                .putList("armor.actionrequestfilter.readonly.allowed_actions", "indices:data/read/search")
                .put(additionalSettings == null ? Settings.EMPTY : additionalSettings).build();

        startES(settings);

        setupTestData("ac_rules_1.json");

        log.debug("searchOnlyAllowed() ------------------------------------------------------------------------------------------------------------------------------------------------------------------------");

        if (!wrongPwd) {
            SearchResponse sResp = executeSearch("ac_query_matchall.json", indices, true, false);
            Assert.assertEquals(7, sResp.getHits().getTotalHits().value);

            ElasticsearchStatusException failure = expectThrows(ElasticsearchStatusException.class, () -> executeGet(indices[0], "dummy", false, false));
            Assert.assertTrue(failure.status().equals(RestStatus.FORBIDDEN));
            Assert.assertTrue(failure.getDetailedMessage().contains("is forbidden"));

            ElasticsearchStatusException failure2 = expectThrows(ElasticsearchStatusException.class, () -> executeIndexAsString("{}", indices[0], null, false, false));
            Assert.assertTrue(failure2.getDetailedMessage().contains("is forbidden"));

        } else {

            ElasticsearchStatusException failure1 = expectThrows(ElasticsearchStatusException.class, () -> executeSearch("ac_query_matchall.json", indices, false, false));
            Assert.assertTrue(failure1.status().equals(RestStatus.FORBIDDEN));
            Assert.assertTrue(failure1.getDetailedMessage().contains("No user"));
            log.info("Cannot authenticate user {} as expected",username);


            ElasticsearchStatusException failure2 = expectThrows(ElasticsearchStatusException.class, () -> executeGet(indices[0], "0", false, false));
            Assert.assertTrue(failure2.status().equals(RestStatus.FORBIDDEN));
            Assert.assertTrue(failure2.getDetailedMessage().contains("No user"));
            log.info("Cannot authenticate user {} as expected",username);

            ElasticsearchStatusException failure3 = expectThrows(ElasticsearchStatusException.class, () -> executeIndexAsString("{}", indices[0], null, false, false));
            Assert.assertTrue(failure3.status().equals(RestStatus.FORBIDDEN));
            Assert.assertTrue(failure3.getDetailedMessage().contains("No user"));
            log.info("Cannot authenticate user {} as expected",username);
        }
    }

    //TODO test get rewrite

    protected void dlsLdapUserAttribute(final Settings additionalSettings) throws Exception {

        final Settings settings = Settings.builder()

                .putList("armor.dlsfilter.names", "a")
                .putList("armor.dlsfilter.a", "ldap_user_attribute", "user", "cn", "true")

                .putList("armor.flsfilter.names", "messageonly")
                .putList("armor.flsfilter.messageonly.source_includes", "message", "userrr")
                .putList("armor.flsfilter.messageonly.source_excludes", "*")

                .putList("armor.actionrequestfilter.names", "readonly", "noget")
                .putList("armor.actionrequestfilter.readonly.allowed_actions", "indices:data/read/*", "*monitor*")
                .putList("armor.actionrequestfilter.readonly.forbidden_actions", "cluster:*", "indices:admin*")
                .putList("armor.actionrequestfilter.noget.allowed_actions", "*monitor*")
                .putList("armor.actionrequestfilter.noget.forbidden_actions", "indices:data/read/get", "indices:admin*")
                .put(additionalSettings == null ? Settings.EMPTY : additionalSettings).build();

        username = "jacksonm";
        password = "secret";

        startES(settings);

        setupTestData("ac_rules_2.json");

        log.info("- 6 ------------------------------------------------------------------------------------------------------------------------------------------------------------------------");

        SearchResponse sResp = executeSearch("ac_query_matchall_fields.json", new String[]{"internal"}, true, false);

        String sRespString = sResp.toString();
        Assert.assertTrue(sResp.status().equals(RestStatus.OK));
        log.debug("Result: " + sRespString);

    }
}
