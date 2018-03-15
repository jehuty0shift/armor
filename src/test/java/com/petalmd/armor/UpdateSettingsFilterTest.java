package com.petalmd.armor;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.petalmd.armor.util.ConfigConstants;
import io.searchbox.client.JestResult;
import io.searchbox.indices.CloseIndex;
import io.searchbox.indices.OpenIndex;
import io.searchbox.indices.settings.GetSettings;
import io.searchbox.indices.settings.UpdateSettings;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

/**
 * Created by jehuty0shift on 15/03/18.
 */

@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class UpdateSettingsFilterTest extends AbstractScenarioTest {

    @Test
    public void UpdateSettingsPrefixTest() throws Exception {

        final boolean wrongPassword = false;
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final Settings settings = Settings.builder().putArray("armor.actionrequestfilter.names", "forbidden","updatesettings")
                .putArray("armor.actionrequestfilter.forbidden.allowed_actions", "indices:data/read/scroll*")
                .putArray("armor.actionrequestfilter.updatesettings.allowed_actions","indices:admin/get", "indices:admin/settings/update", "indices:admin/close", "indices:admin/open", "indices:monitor/settings/get")
                .put(ConfigConstants.ARMOR_INDICES_UPDATESETTINGSFILTER_ENABLED, true)
                .putArray(ConfigConstants.ARMOR_INDICES_UPDATESETTINGSFILTER_ALLOWED, "analysis", "index.refresh_interval")
                .put(authSettings)
                .build();

        //"indices:admin/settings/update"

        startES(settings);
        setupTestData("ac_rules_12.json");

        String analysisSetting = "{ " +
                "\"index.refresh_interval\" : \"1m\"," +
                "\"index.number_of_replicas\" : 3," +
                "\"analysis\": { " +
                "   \"filter\": {" +
                "       \"french_elision\": {   \"type\": \"elision\", \"articles_case\": true, " +
                "           \"articles\": [ " +
                "           \"l\", \"m\", \"t\", \"qu\", \"n\", \"s\"," +
                "           \"j\", \"d\", \"c\", \"jusqu\", \"quoiqu\"," +
                "           \"lorsqu\", \"puisqu\" ] }," +
                "       \"french_stop\": {" +
                "           \"type\": \"stop\"," +
                "           \"stopwords\": \"_french_\" }," +
                "       \"french_stemmer\": {" +
                "           \"type\": \"stemmer\"," +
                "           \"language\": \"light_french\" }" +
                "       }," +
                "   \"analyzer\": {" +
                "       \"french\": {" +
                "       \"tokenizer\": \"standard\"," +
                "       \"filter\": [" +
                "           \"lowercase\"," +
                "           \"asciifolding\"," +
                "           \"french_elision\"," +
                "           \"french_stop\"," +
                "           \"french_stemmer\"" +
                "]  } } } }";

        HeaderAwareJestHttpClient client = getJestClient(getServerUri(false), username, password);


        String indexName = "financial";

        UpdateSettings updateSettingRequest = new UpdateSettings.Builder(analysisSetting)
                .addIndex(indexName)
                .build();

        JestResult resultClose = client.execute(new CloseIndex.Builder(indexName).setParameter("timeout", "1m").build());

        Assert.assertTrue(resultClose.isSucceeded());

        JestResult result = client.execute(updateSettingRequest);

        Assert.assertTrue(result.isSucceeded());

        JestResult resultOpen = client.execute(new OpenIndex.Builder(indexName).setParameter("timeout", "1m").build());

        Assert.assertTrue(resultOpen.isSucceeded());

        JestResult resultGetSettings = client.execute(new GetSettings.Builder().addIndex(indexName).build());

        Assert.assertTrue(resultGetSettings.isSucceeded());

        final String resultGetSettingsString  = resultGetSettings.getJsonString();
        //The analysis must have been taken into account.
        Assert.assertTrue(resultGetSettingsString.contains("analysis"));
        //The refresh_interval must have changed
        Assert.assertTrue(resultGetSettingsString.contains("refresh_interval") && resultGetSettingsString.contains("1m"));
        //the number of replicas MUST not have been changed
        Assert.assertTrue(resultGetSettings
                .getJsonObject().getAsJsonObject("financial")
                .getAsJsonObject("settings")
                .getAsJsonObject("index")
                .get("number_of_replicas")
                .getAsInt() == 1);

    }

}
