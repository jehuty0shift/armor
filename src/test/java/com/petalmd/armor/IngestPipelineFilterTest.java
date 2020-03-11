package com.petalmd.armor;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.petalmd.armor.tests.GetPipeline;
import com.petalmd.armor.tests.PutPipeline;
import com.petalmd.armor.util.ConfigConstants;
import io.searchbox.client.JestResult;
import org.apache.http.HttpResponse;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

/**
 * Created by jehuty0shift on 11/03/2020.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class IngestPipelineFilterTest extends AbstractUnitTest {


    @Test
    public void tryPutAndGetPipelineRequest() throws Exception {

        username = "logs-xv-12345";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "forbidden")
                .putList("armor.actionrequestfilter.forbidden.allowed_actions",
                        "cluster:admin/ingest/pipeline/put",
                        "cluster:admin/ingest/pipeline/get",
                        "indices:admin/template/put",
                        "indices:admin/template/get",
                        "indices:admin/template/delete",
                        "indices:admin/aliases",
                        "indices:data/read/scroll",
                        "indices:data/read/scroll/clear")
                .put(ConfigConstants.ARMOR_INGEST_PIPELINE_FILTER_ENABLED, true)
                .put(authSettings).build();


        startES(settings);

        setupTestData("ac_rules_28.json");

        HeaderAwareJestHttpClient client = getJestClient(getServerUri(false), username, password);

        PutPipeline putPipeline = new PutPipeline.Builder("test").payload("{\n" +
                "  \"description\" : \"my first pipeline\",\n" +
                "  \"processors\": [\n" +
                "    {\n" +
                "      \"grok\": {\n" +
                "        \"field\": \"message\",\n" +
                "        \"patterns\": [\"%{IP:client} %{WORD:method} %{URIPATHPARAM:request} %{NUMBER:bytes} %{NUMBER:duration}\"]\n" +
                "      }\n" +
                "    }\n" +
                "  ]\n" +
                "}").build();

        Tuple<JestResult, HttpResponse> result = client.executeE(putPipeline);

        Assert.assertTrue(result.v1().isSucceeded());

        GetPipeline getPipeline = new GetPipeline.Builder("test").build();

        result = client.executeE(getPipeline);

        Assert.assertTrue(result.v1().isSucceeded());
        Assert.assertTrue(result.v1().getJsonString().contains("my first pipeline"));

        GetPipeline getPipeline2 = new GetPipeline.Builder(username + "-test").build();

        result = client.executeE(getPipeline2);

        Assert.assertTrue(result.v1().isSucceeded());
        Assert.assertTrue(result.v1().getJsonString().contains("my first pipeline"));



    }
}
