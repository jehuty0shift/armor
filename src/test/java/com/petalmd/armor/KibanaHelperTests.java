package com.petalmd.armor;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.google.gson.Gson;
import com.petalmd.armor.AbstractUnitTest;
import com.petalmd.armor.tests.GetFieldCapsAction;
import com.petalmd.armor.util.ConfigConstants;
import io.searchbox.action.Action;
import io.searchbox.action.GenericResultAbstractAction;
import io.searchbox.client.JestClient;
import io.searchbox.client.JestResult;
import org.apache.http.HttpResponse;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;
import java.util.Map;

/**
 * Created by jehuty0shift on 26/10/18.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class KibanaHelperTests extends AbstractScenarioTest {

    @Test
    public void testReadFieldCaps() throws Exception {
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final String[] indices = new String[]{"internal"};

        final Settings settings = Settings.builder().putArray("armor.actionrequestfilter.names", "readcaps","forbidden")
                .putArray("armor.actionrequestfilter.readcaps.allowed_actions", "indices:data/read/field_caps")
                .putArray("armor.actionrequestfilter.forbidden.forbidden_actions", "indices:data*")
                .put(ConfigConstants.ARMOR_KIBANA_HELPER_ENABLED, true)
                .put(authSettings).build();

        startES(settings);

        setupTestDataWithFilteredAlias("ac_rules_15.json");

        JestClient client = getJestClient(getServerUri(false), username, password);

        final Tuple<JestResult, HttpResponse> resulttu = ((HeaderAwareJestHttpClient) client).executeE((new GetFieldCapsAction.Builder())
                .addIndex(Arrays.asList(indices))
                .setFields(Arrays.asList("@timestamp")).build());

        Assert.assertTrue(resulttu.v2().getStatusLine().getStatusCode() == 404);
        Assert.assertFalse(resulttu.v1().isSucceeded());
        Assert.assertTrue(resulttu.v1().getJsonObject().has("error"));


    }
}
