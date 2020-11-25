package com.petalmd.armor;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.petalmd.armor.util.ConfigConstants;
import org.elasticsearch.ElasticsearchStatusException;
import org.elasticsearch.action.fieldcaps.FieldCapabilitiesRequest;
import org.elasticsearch.action.fieldcaps.FieldCapabilitiesResponse;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestStatus;
import org.junit.Assert;
import org.junit.Test;

/**
 * Created by jehuty0shift on 26/10/18.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class KibanaHelperTests extends AbstractArmorTest {

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

        RestHighLevelClient client = getRestClient(false, username, password);

        ElasticsearchStatusException fail1 = expectThrows(ElasticsearchStatusException.class, () -> client.fieldCaps(new FieldCapabilitiesRequest().indices(indices).fields("@timestamp"), RequestOptions.DEFAULT));

        Assert.assertEquals(fail1.status(), RestStatus.NOT_FOUND);
        Assert.assertTrue(fail1.getDetailedMessage().contains("no such index"));


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


        RestHighLevelClient client = getRestClient(false, username, password);

      FieldCapabilitiesResponse fcResp =  client.fieldCaps(new FieldCapabilitiesRequest().indices(indices).fields("*"), RequestOptions.DEFAULT);
      Assert.assertTrue(fcResp.get().containsKey("user"));

    }
}
