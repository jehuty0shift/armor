package com.petalmd.armor;

import com.petalmd.armor.util.ConfigConstants;
import io.searchbox.client.JestResult;
import io.searchbox.cluster.Health;
import io.searchbox.cluster.NodesInfo;
import org.apache.http.HttpResponse;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.junit.Test;

/**
 * Created by bdiasse on 13/03/17.
 */
public class ObfFilterTest extends AbstractScenarioTest {

    @Test
    public void obfuscationFilterTest() throws Exception {

        final boolean wrongPassword = false;
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false,"ceo" );

        final Settings settings =  Settings.settingsBuilder().putArray("armor.actionrequestfilter.names", "monitoronly")
                .putArray("armor.actionrequestfilter.monitoronly.allowed_actions", "cluster:monitor*")
                .put(ConfigConstants.ARMOR_OBFUSCATION_FILTER_ENABLED,true)
                .put(ConfigConstants.ARMOR_ALLOW_KIBANA_ACTIONS,false)
                .put(authSettings).build();

        startES(settings);
        setupTestData("ac_rules_2.json");

        HeaderAwareJestHttpClient client = getJestClient(getServerUri(false), username, password);

        final Tuple<JestResult, HttpResponse> restu = client.executeE(new NodesInfo.Builder().build());


        System.out.println(restu.v1().getJsonString());
    }

}
