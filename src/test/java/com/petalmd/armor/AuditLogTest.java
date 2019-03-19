package com.petalmd.armor;

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.petalmd.armor.util.ConfigConstants;
import io.searchbox.client.JestResult;
import org.elasticsearch.common.settings.Settings;
import org.junit.Test;
import org.junit.runner.RunWith;

@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class AuditLogTest extends AbstractScenarioTest {

    @Test
    public void testSearchOnlyAllowedAction() throws Exception {

        username = "jacksonm";
        password = "secret";

        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "readonly")
                .putList("armor.actionrequestfilter.readonly.allowed_actions", "indices:data/read/search")
                .put(getAuthSettings(false, "ceo")).build();

        startES(settings);
        setupTestData("ac_rules_execute_all.json");
        executeIndexAsString("{}", "audittest", "audittesttype", "x1", false, false);

        Thread.sleep(3000);

        final JestResult result = executeSearch("ac_query_matchall.json", new String[] { ConfigConstants.DEFAULT_SECURITY_CONFIG_INDEX + "_audit" },
                new String[] { "records" }, true, true).v1();
        log.debug(toPrettyJson(result.getJsonString()));
        assertJestResultCount(result, 1);
    }

}
