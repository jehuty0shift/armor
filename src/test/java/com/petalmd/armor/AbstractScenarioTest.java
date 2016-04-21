package com.petalmd.armor;

import io.searchbox.client.JestResult;

import java.util.Map;

import org.apache.http.HttpResponse;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.ImmutableSettings;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import io.searchbox.action.Action;
import io.searchbox.client.JestClient;
import io.searchbox.core.Search;
import io.searchbox.indices.template.PutTemplate;

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

        final Settings settings = ImmutableSettings.settingsBuilder().putArray("armor.dlsfilter.names", "dummy2-only")
                .putArray("armor.dlsfilter.dummy2-only", "term", "user", "umberto", "true")
                .put(additionalSettings == null ? ImmutableSettings.EMPTY : additionalSettings).build();

        baseQuery(settings, "ac_rules_execute_all.json", "ac_query_matchall.json", 2, new String[]{"ceo", "future"});
    }

    protected void simpleFlsScenarioExclude(final Settings additionalSettings) throws Exception {

        final Settings settings = ImmutableSettings
                .settingsBuilder()
                .putArray("armor.dlsfilter.names", "dummy2-only")
                .putArray("armor.dlsfilter.dummy2-only", "term", "user", "umberto", "false")
                .putArray("armor.flsfilter.names", "special-fields-only")
                .putArray("armor.flsfilter.special-fields-only", "special-fields-only")
                .putArray("armor.flsfilter.special-fields-only.source_excludes", "structure.thearray", "structure.thesubobject2",
                        "message").putArray("armor.flsfilter.special-fields-only.source_includes", "") //same as "" or null
                .put(additionalSettings == null ? ImmutableSettings.EMPTY : additionalSettings).build();

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

        final Settings settings = ImmutableSettings.settingsBuilder().putArray("armor.dlsfilter.names", "dummy2-only")
                .putArray("armor.dlsfilter.dummy2-only", "term", "user", "umberto", "false")
                .putArray("armor.flsfilter.names", "special-fields-only")
                .putArray("armor.flsfilter.special-fields-only", "special-fields-only")
                .putArray("armor.flsfilter.special-fields-only.source_excludes", "")
                //same as null
                .putArray("armor.flsfilter.special-fields-only.source_includes", "message")
                .put(additionalSettings == null ? ImmutableSettings.EMPTY : additionalSettings).build();

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
        "fields": {
          "structure.thesubfield2": [
            "yepp"
          ],
          "user": [
            "umberto"
          ]
        }
        }
         */
        final Settings settings = ImmutableSettings.settingsBuilder().putArray("armor.dlsfilter.names", "dummy2-only")
                .putArray("armor.dlsfilter.dummy2-only", "term", "user", "umberto", "false")
                .putArray("armor.flsfilter.names", "special-fields-only")
                .putArray("armor.flsfilter.special-fields-only", "special-fields-only")
                .putArray("armor.flsfilter.special-fields-only.source_excludes", "structure.the*field2")
                .putArray("armor.flsfilter.special-fields-only.source_includes", "message") //does have not effect because to a "field"
                .put(additionalSettings == null ? ImmutableSettings.EMPTY : additionalSettings).build();

        final String json = baseQuery(settings, "ac_rules_execute_all.json", "ac_query_matchall_twofields.json", 1, new String[]{"ceo",
            "future"});

        log.debug(toPrettyJson(json));

        Assert.assertTrue(!json.contains("message"));
        Assert.assertTrue(!json.contains("thearray"));
        Assert.assertTrue(!json.contains("thesubfield2"));
        Assert.assertTrue(!json.contains("structure"));
        Assert.assertTrue(json.contains("user"));
        Assert.assertTrue(!json.contains("_source"));

    }

    protected void simpleFlsScenarioPartialFields(final Settings additionalSettings) throws Exception {

        //without dls filter
        /*
         * "hits": [
        {
        "_index": "ceo",
        "_type": "internal",
        "_id": "tp_1",
        "_score": 1.0,
        "fields": {
          "partial1": [
            {
              "structure": {
                "thesubfield2": "yepp"
              },
              "user": "umberto"
            }
          ]
        }
        }
         */
        final Settings settings = ImmutableSettings.settingsBuilder().putArray("armor.dlsfilter.names", "dummy2-only")
                .putArray("armor.dlsfilter.dummy2-only", "term", "user", "umberto", "false")
                .putArray("armor.flsfilter.names", "special-fields-only")
                .putArray("armor.flsfilter.special-fields-only", "special-fields-only")
                .putArray("armor.flsfilter.special-fields-only.source_excludes", "structure.the*field2")
                .putArray("armor.flsfilter.special-fields-only.source_includes", "message") //does have not effect because to a "field"
                .put(additionalSettings == null ? ImmutableSettings.EMPTY : additionalSettings).build();

        final String json = baseQuery(settings, "ac_rules_execute_all.json", "ac_query_matchall_twofieldspartial.json", 1, new String[]{
            "ceo", "future"});

        log.debug(toPrettyJson(json));

        Assert.assertTrue(!json.contains("message"));
        Assert.assertTrue(!json.contains("thearray"));
        Assert.assertTrue(!json.contains("thesubfield2"));
        Assert.assertTrue(!json.contains("structure"));
        Assert.assertTrue(!json.contains("user"));
        Assert.assertTrue(!json.contains("partial"));
        Assert.assertTrue(!json.contains("_source"));

    }

    protected void searchOnlyAllowed(final Settings additionalSettings, final boolean wrongPwd) throws Exception {
        final String[] indices = new String[]{"internal"};

        final Settings settings = ImmutableSettings.settingsBuilder().putArray("armor.restactionfilter.names", "readonly")
                .putArray("armor.restactionfilter.readonly.allowed_actions", "RestSearchAction")
                .put(additionalSettings == null ? ImmutableSettings.EMPTY : additionalSettings).build();

        startES(settings);

        setupTestData("ac_rules_1.json");

        log.debug("searchOnlyAllowed() ------------------------------------------------------------------------------------------------------------------------------------------------------------------------");

        if (!wrongPwd) {
            JestResult result = executeSearch("ac_query_matchall.json", indices, null, true, false).v1();
            assertJestResultCount(result, 7);

            result = executeGet(indices[0], "test", "dummy", false, false).v1();
            assertJestResultError(result, "ForbiddenException[Forbidden action RestGetAction . Allowed actions: [RestSearchAction]]");

            result = executeIndexAsString("{}", indices[0], "test", null, false, false).v1();
            assertJestResultError(result, "ForbiddenException[Forbidden action RestIndexAction . Allowed actions: [RestSearchAction]]");
        } else {

            JestResult result = executeSearch("ac_query_matchall.json", indices, null, false, false).v1();
            assertJestResultError(result, "Cannot authenticate user", "Unauthorized", "No user");

            result = executeGet(indices[0], "test", null, false, false).v1();
            assertJestResultError(result, "Cannot authenticate user", "Unauthorized", "No user");

            result = executeIndexAsString("{}", indices[0], "test", null, false, false).v1();
            assertJestResultError(result, "Cannot authenticate user", "Unauthorized", "No user");
        }
    }

    protected void searchOnlyAllowedMoreFilters(final Settings additionalSettings, final boolean wrongPwd) throws Exception {
        final Settings settings = ImmutableSettings.settingsBuilder()
                .putArray("armor.restactionfilter.names", "readonly", "al_l", "no-ne")
                .putArray("armor.restactionfilter.readonly.allowed_actions", "RestSearchAction")
                .putArray("armor.restactionfilter.al_l.allowed_actions", "*")
                .putArray("armor.restactionfilter.no-ne.allowed_actions", "RestSearchAction")
                .put(additionalSettings == null ? ImmutableSettings.EMPTY : additionalSettings).build();

        searchOnlyAllowed(settings, wrongPwd);
    }

    protected void searchOnlyAllowedAction(final Settings additionalSettings, final boolean wrongPwd) throws Exception {
        final String[] indices = new String[]{"internal"};

        final Settings settings = ImmutableSettings.settingsBuilder().putArray("armor.actionrequestfilter.names", "readonly")
                .putArray("armor.actionrequestfilter.readonly.allowed_actions", "indices:data/read/search")
                .put(additionalSettings == null ? ImmutableSettings.EMPTY : additionalSettings).build();

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

            result = executeGet(indices[0], "test", null, false, false).v1();
            assertJestResultError(result, "Cannot authenticate user", "Unauthorized", "No user");

            result = executeIndexAsString("{}", indices[0], "test", null, false, false).v1();
            assertJestResultError(result, "Cannot authenticate user", "Unauthorized", "No user");
        }
    }

    //TODO test get rewrite
    protected void dlsLdapUserAttribute(final Settings additionalSettings) throws Exception {

        final Settings settings = ImmutableSettings.settingsBuilder().putArray("armor.restactionfilter.names", "readonly", "noget")
                .putArray("armor.restactionfilter.readonly.allowed_actions", "RestSearchAction")
                .putArray("armor.restactionfilter.noget.forbidden_actions", "RestGetAction")
                .putArray("armor.restactionfilter.noget.allowed_actions", "*")
                .putArray("armor.dlsfilter.names", "a")
                .putArray("armor.dlsfilter.a", "ldap_user_attribute", "user", "cn", "true")
                .putArray("armor.flsfilter.names", "messageonly")
                .putArray("armor.flsfilter.messageonly.source_includes", "message", "userrr")
                .putArray("armor.flsfilter.messageonly.source_excludes", "*")
                //wins

                .putArray("armor.actionrequestfilter.names", "readonly")
                .putArray("armor.actionrequestfilter.readonly.allowed_actions", "indices:data/read/*", "*monitor*")
                .putArray("armor.actionrequestfilter.readonly.forbidden_actions", "cluster:*", "indices:admin*")
                .put(additionalSettings == null ? ImmutableSettings.EMPTY : additionalSettings).build();

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

    protected void searchIndexInQuery(Settings additionalSettings) throws Exception {
        final Settings settings = ImmutableSettings
                .settingsBuilder()
                .put("logger.armor", "DEBUG")
                .putArray("armor.actionrequestfilter.names", "allowSearch", "denyRead")
                .putArray("armor.actionrequestfilter.allowSearch.allowed_actions", "indices:data/read*")
                .putArray("armor.actionrequestfilter.denyRead.forbidden_actions", "indices:data/read*")
                .put("armor.authentication.settingsdb.user.jacksonm", "secret")
                .put(additionalSettings == null ? ImmutableSettings.EMPTY : additionalSettings).build();

        startES(settings);

        username = "jacksonm";
        password = "secret";
           
        //enable _index field. 
        PutTemplate template = new PutTemplate.Builder("enable_index", "{ \"order\" : 0, \"template\" : \"*\", \"mappings\" : { \"_default_\" : { \"_index\" : {  \"enabled\" : true } } } }").build();
        getJestClient(getServerUri(true), username, password).execute(template);

        final JestClient client = getJestClient(getServerUri(false), username, password);

        setupTestData("ac_rules_allowIndexRead.json");
        executeIndex("dummy_content.json", "domain", "public", "dc1", true, true);

        final Action action = new Search.Builder("").setParameter("q", "_index:domain OR (user:umberto AND _index:public)").build();

        final JestResult jr = client.execute(action);

        assertJestResultError(jr, null);
        log.debug(jr.getErrorMessage());

        final Action action2 = new Search.Builder("").setParameter("q", "user:umberto OR _index:domain").build();
        final JestResult jr2 = client.execute(action2);

        assertJestResultError(jr2, null);
        log.debug(jr2.getErrorMessage());

        final Action action3 = new Search.Builder("").setParameter("q", "user:umberto AND _index:domain").build();
        final JestResult jr3 = client.execute(action3);

        assertJestResultCount(jr3, 1);
        log.debug(toPrettyJson(jr3.getJsonString()));

    }
}
