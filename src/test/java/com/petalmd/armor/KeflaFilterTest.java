package com.petalmd.armor;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.petalmd.armor.tests.GetFieldCapsAction;
import com.petalmd.armor.util.ConfigConstants;
import io.searchbox.client.JestClient;
import io.searchbox.client.JestResult;
import org.apache.http.HttpResponse;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

/**
 * Created by jehuty0shift on 11/10/19.
 */

@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class KeflaFilterTest extends AbstractScenarioTest {


    @Test
    public void getMappingForAlias() throws Exception {
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final String indices = "filtered";

        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "reader","forbidden")
                .putList("armor.actionrequestfilter.reader.allowed_actions", "indices:data/read/field_caps", "indices:data/read/mapping*")
                .putList("armor.actionrequestfilter.forbidden.forbidden_actions", "indices:data*")
                .put(ConfigConstants.ARMOR_KIBANA_HELPER_ENABLED, true)
                .put(ConfigConstants.ARMOR_KEFLA_FILTER_ENABLED, true)
                .put(authSettings).build();

        startES(settings);

        setupTestDataWithFilteredAliasWithStreams("ac_rules_24.json");

        JestClient client = getJestClient(getServerUri(false), username, password);

        final Tuple<JestResult, HttpResponse> resulttu = ((HeaderAwareJestHttpClient) client).executeE((new GetFieldCapsAction.Builder())
                .addIndex(indices)
                .setAllFields().build());

        Assert.assertTrue(resulttu.v2().getStatusLine().getStatusCode() == 200);
        Assert.assertTrue(resulttu.v1().isSucceeded());
        Assert.assertTrue(resulttu.v1().getJsonObject().getAsJsonObject("fields").has("user"));
        Assert.assertFalse(resulttu.v1().getJsonObject().getAsJsonObject("fields").has("previous_club"));


    }

}
