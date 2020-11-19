package com.petalmd.armor;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.petalmd.armor.util.ConfigConstants;
import org.elasticsearch.action.admin.indices.open.OpenIndexRequest;
import org.elasticsearch.action.admin.indices.settings.get.GetSettingsRequest;
import org.elasticsearch.action.admin.indices.settings.get.GetSettingsResponse;
import org.elasticsearch.action.admin.indices.settings.put.UpdateSettingsRequest;
import org.elasticsearch.action.support.master.AcknowledgedResponse;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.client.indices.CloseIndexRequest;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.common.xcontent.XContentType;
import org.junit.Assert;
import org.junit.Test;

/**
 * Created by jehuty0shift on 15/03/18.
 */

@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class UpdateSettingsFilterTest extends AbstractArmorTest {

    @Test
    public void UpdateSettingsPrefixTest() throws Exception {

        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "forbidden", "updatesettings")
                .putList("armor.actionrequestfilter.forbidden.allowed_actions", "indices:data/read/scroll*")
                .putList("armor.actionrequestfilter.updatesettings.allowed_actions", "indices:admin/get", "indices:admin/settings/update", "indices:admin/close*", "indices:admin/open", "indices:admin/mapping/put", "indices:monitor/settings/get")
                .put(ConfigConstants.ARMOR_INDICES_UPDATESETTINGSFILTER_ENABLED, true)
                .putList(ConfigConstants.ARMOR_INDICES_UPDATESETTINGSFILTER_ALLOWED, "analysis", "index.refresh_interval")
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
                "       \"french_rebuilt\": {" +
                "       \"tokenizer\": \"standard\"," +
                "       \"filter\": [" +
                "           \"lowercase\"," +
                "           \"asciifolding\"," +
                "           \"french_elision\"," +
                "           \"french_stop\"," +
                "           \"french_stemmer\"" +
                "]  } } } }";

        RestHighLevelClient client = getRestClient(false, username, password);


        String indexName = "financial";


        UpdateSettingsRequest usr = new UpdateSettingsRequest(indexName).settings(analysisSetting, XContentType.JSON);

        AcknowledgedResponse respClose = client.indices().close(new CloseIndexRequest(indexName), RequestOptions.DEFAULT);


        Assert.assertTrue(respClose.isAcknowledged());

        AcknowledgedResponse resp = client.indices().putSettings(usr, RequestOptions.DEFAULT);

        Assert.assertTrue(resp.isAcknowledged());

        AcknowledgedResponse respOpen = client.indices().open(new OpenIndexRequest(indexName).timeout(TimeValue.timeValueMinutes(1)), RequestOptions.DEFAULT);

        Assert.assertTrue(respOpen.isAcknowledged());

        GetSettingsResponse getSettingsResp = client.indices().getSettings(new GetSettingsRequest().indices(indexName), RequestOptions.DEFAULT);

        Settings settingsResp = getSettingsResp.getIndexToSettings().get(indexName);

        //The analysis must have been taken into account.
        Assert.assertTrue(!settingsResp.hasValue("analysis"));

        //The refresh_interval must have changed
        Assert.assertEquals(TimeValue.timeValueMinutes(1), settingsResp.getAsTime("index.refresh_interval", TimeValue.ZERO));

        //the number of replicas MUST not have been changed
        Assert.assertEquals(1, settingsResp.getAsInt("index.number_of_replicas", 0).intValue());

    }

}
