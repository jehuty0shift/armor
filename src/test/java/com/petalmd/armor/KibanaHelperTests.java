package com.petalmd.armor;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.petalmd.armor.tests.GetFieldCapsAction;
import com.petalmd.armor.util.ConfigConstants;
import io.searchbox.client.JestClient;
import io.searchbox.client.JestResult;
import io.searchbox.fields.FieldCapabilities;
import org.apache.http.HttpResponse;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;

/**
 * Created by jehuty0shift on 26/10/18.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class KibanaHelperTests extends AbstractScenarioTest {

    @Test
    public void readFieldCapsOnAliasDenied() throws Exception {
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final String indices = "internal";

        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "readcaps","forbidden")
                .putList("armor.actionrequestfilter.readcaps.allowed_actions", "indices:data/read/field_caps")
                .putList("armor.actionrequestfilter.forbidden.forbidden_actions", "indices:data*")
                .put(ConfigConstants.ARMOR_KIBANA_HELPER_ENABLED, true)
                .put(authSettings).build();

        startES(settings);

        setupTestDataWithFilteredAlias("ac_rules_15.json");

        JestClient client = getJestClient(getServerUri(false), username, password);

        final Tuple<JestResult, HttpResponse> resulttu = ((HeaderAwareJestHttpClient) client).executeE((new GetFieldCapsAction.Builder())
                .addIndex(indices)
                .setFields(Arrays.asList("@timestamp")).build());

        Assert.assertTrue(resulttu.v2().getStatusLine().getStatusCode() == 404);
        Assert.assertFalse(resulttu.v1().isSucceeded());
        Assert.assertTrue(resulttu.v1().getJsonObject().has("error"));


    }

    @Test
    public void readFieldCapsOnAliasAllowed() throws Exception {

        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final String indices = "filtered";

        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "readcaps","forbidden")
                .putList("armor.actionrequestfilter.readcaps.allowed_actions", "indices:data/read/field_caps")
                .putList("armor.actionrequestfilter.forbidden.forbidden_actions", "indices:data*")
                .put(ConfigConstants.ARMOR_KIBANA_HELPER_ENABLED, true)
                .put(authSettings).build();

        startES(settings);

        setupTestDataWithFilteredAlias("ac_rules_18.json");

        JestClient client = getJestClient(getServerUri(false), username, password);

        final Tuple<JestResult, HttpResponse> resulttu = ((HeaderAwareJestHttpClient) client).executeE((new GetFieldCapsAction.Builder())
                .addIndex(indices)
                .setAllFields().build());

        Assert.assertTrue(resulttu.v2().getStatusLine().getStatusCode() == 200);
        Assert.assertTrue(resulttu.v1().isSucceeded());
        Assert.assertTrue(resulttu.v1().getJsonObject().getAsJsonObject("fields").has("user"));

    }
}
