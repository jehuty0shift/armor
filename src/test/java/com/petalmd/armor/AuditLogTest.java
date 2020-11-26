package com.petalmd.armor;

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.petalmd.armor.util.ConfigConstants;
import io.searchbox.client.JestResult;
import org.elasticsearch.ElasticsearchStatusException;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestStatus;
import org.junit.Assert;
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
        ElasticsearchStatusException indexFail1 = expectThrows(ElasticsearchStatusException.class,
                () -> executeIndexAsString("{ \"user\" : \"goku\"}", "audittest", "x1", false, false));

        Assert.assertTrue(indexFail1.status().equals(RestStatus.FORBIDDEN));

        Thread.sleep(3000);
        long  totalHits = 0;
        while (totalHits == 0) {
            try {
                SearchResponse sResp = executeSearch("ac_query_matchall.json", new String[]{ConfigConstants.DEFAULT_SECURITY_CONFIG_INDEX + "_audit"}, true, true);


                totalHits = sResp.getHits().getTotalHits().value;
                if (totalHits != 0) {
                    Thread.sleep(3000);
                }
                log.debug(sResp.toString());
            } catch (Exception ex) {
                log.error("audit index not ready", ex);
                Thread.sleep( 3000);
            }
        }

        Assert.assertTrue(totalHits == 1);
    }

}
