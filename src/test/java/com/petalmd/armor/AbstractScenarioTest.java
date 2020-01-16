package com.petalmd.armor;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import io.searchbox.client.JestResult;
import org.apache.http.HttpResponse;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.runner.RunWith;

import java.util.Map;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
public abstract class AbstractScenarioTest extends AbstractUnitTest {

    protected String baseQuery(final Settings settings, final String acRulesFile, final String queryFile, final int expectedCount,
                               final String[] indices, final String[] types) throws Exception {
        startES(settings);
        setupTestData(acRulesFile);
        log.debug("------------------------------------------------------------------------------------------------------------------------------------------------------------------------");
        final JestResult result = executeSearch(queryFile, indices, types, true, false).v1();
        assertJestResultCount(result, expectedCount);
        final String json = result.getJsonString();
        Assert.assertNotNull(json);
        Assert.assertTrue(json.length() > 1);
        return json;
    }

    protected String baseQuery(final Settings settings, final String acRulesFile, final String queryFile, final int expectedCount)
            throws Exception {
        return baseQuery(settings, acRulesFile, queryFile, expectedCount, null, null);
    }

    protected String baseQuery(final Settings settings, final String acRulesFile, final String queryFile, final int expectedCount,
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

        final String json = baseQuery(settings, "ac_rules_execute_all.json", "ac_query_matchall.json", 1, new String[]{"ceo", "future"});

        log.debug(toPrettyJson(json));

        Assert.assertTrue(!json.contains("message"));
        Assert.assertTrue(!json.contains("thearray"));
        Assert.assertTrue(!json.contains("thesubobject2"));
        Assert.assertTrue(!json.contains("so2subkey4"));
        Assert.assertTrue(json.contains("thesubobject"));
        Assert.assertTrue(json.contains("user"));

        Assert.assertTrue(json.contains("_source"));
        Assert.assertTrue(!json.contains("\"_source\":{}"));

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

        final String json = baseQuery(settings, "ac_rules_execute_all.json", "ac_query_matchall.json", 1, new String[]{"ceo", "future"});

        log.debug(toPrettyJson(json));

        Assert.assertTrue(json.contains("message"));
        Assert.assertTrue(!json.contains("thearray"));
        Assert.assertTrue(!json.contains("thesubobject2"));
        Assert.assertTrue(!json.contains("so2subkey4"));
        Assert.assertTrue(!json.contains("thesubobject"));
        Assert.assertTrue(!json.contains("user"));
        Assert.assertTrue(!json.contains("structure"));

        Assert.assertTrue(json.contains("_source"));
        Assert.assertTrue(!json.contains("\"_source\":{}"));

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

        final String json = baseQuery(settings, "ac_rules_execute_all.json", "ac_query_matchall_twofields.json", 1, new String[]{"ceo",
                "future"});

        log.debug(toPrettyJson(json));

        Assert.assertTrue(!json.contains("message"));
        Assert.assertTrue(!json.contains("thearray"));
        Assert.assertTrue(!json.contains("thesubfield2"));
        Assert.assertTrue(!json.contains("structure"));
        Assert.assertTrue(json.contains("user"));

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
            JestResult result = executeSearch("ac_query_matchall.json", indices, null, true, false).v1();
            assertJestResultCount(result, 7);

            result = executeGet(indices[0], "test", "dummy", false, false).v1();
//            assertJestResultError(result, "ForbiddenException[Forbidden action RestGetAction . Allowed actions: [RestSearchAction]]");
            assertJestResultError(result, "{\"root_cause\":[{\"type\":\"forbidden_exception\",\"reason\":\"Action 'indices:data/read/get' is forbidden due to [DEFAULT]\"}],\"type\":\"forbidden_exception\",\"reason\":\"Action 'indices:data/read/get' is forbidden due to [DEFAULT]\"}");
            result = executeIndexAsString("{}", indices[0], "test", null, false, false).v1();
//            assertJestResultError(result, "ForbiddenException[Forbidden action RestIndexAction . Allowed actions: [RestSearchAction]]");
            assertJestResultError(result, "{\"root_cause\":[{\"type\":\"forbidden_exception\",\"reason\":\"Action 'indices:data/write/index' is forbidden due to [DEFAULT]\"}],\"type\":\"forbidden_exception\",\"reason\":\"Action 'indices:data/write/index' is forbidden due to [DEFAULT]\"}");
        } else {

            JestResult result = executeSearch("ac_query_matchall.json", indices, null, false, false).v1();
            assertJestResultError(result, "Cannot authenticate user", "Unauthorized", "No user");

            result = executeGet(indices[0], null, null, false, false).v1();
            assertJestResultError(result, "Cannot authenticate user", "Unauthorized", "No user");

            result = executeIndexAsString("{}", indices[0], "test", null, false, false).v1();
            assertJestResultError(result, "Cannot authenticate user", "Unauthorized", "No user");
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
            JestResult result = executeSearch("ac_query_matchall.json", indices, null, true, false).v1();
            assertJestResultCount(result, 7);

            result = executeGet(indices[0], "test", "dummy", false, false).v1();
            assertJestResultError(result, "is forbidden");

            result = executeIndexAsString("{}", indices[0], "test", null, false, false).v1();
            assertJestResultError(result, "is forbidden");
        } else {

            JestResult result = executeSearch("ac_query_matchall.json", indices, null, false, false).v1();
            assertJestResultError(result, "Cannot authenticate user", "Unauthorized", "No user");

            result = executeGet(indices[0], "_doc", "0", false, false).v1();
            assertJestResultError(result, "Cannot authenticate user", "Unauthorized", "No user");

            result = executeIndexAsString("{}", indices[0], "test", null, false, false).v1();
            assertJestResultError(result, "Cannot authenticate user", "Unauthorized", "No user");
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

        final Gson gson = new GsonBuilder().setPrettyPrinting().create();

        final Tuple<JestResult, HttpResponse> resulttu = executeSearch("ac_query_matchall_fields.json", new String[]{"internal"}, null,
                true, false);

        final JestResult result = resulttu.v1();
        final Map json = gson.fromJson(result.getJsonString(), Map.class);
        log.debug("Result: " + gson.toJson(json));

    }
}
