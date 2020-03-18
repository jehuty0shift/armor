package com.petalmd.armor;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.petalmd.armor.tests.DeletePipeline;
import com.petalmd.armor.tests.GetPipeline;
import com.petalmd.armor.tests.PutPipeline;
import com.petalmd.armor.tests.SimulatePipeline;
import com.petalmd.armor.util.ConfigConstants;
import io.searchbox.action.BulkableAction;
import io.searchbox.client.JestResult;
import io.searchbox.core.Bulk;
import io.searchbox.core.Get;
import io.searchbox.core.Index;
import org.apache.http.HttpResponse;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import java.util.regex.Pattern;

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


    @Test
    public void tryPutAndDeletePipelineRequest() throws Exception {

        username = "logs-xv-12345";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "forbidden")
                .putList("armor.actionrequestfilter.forbidden.allowed_actions",
                        "cluster:admin/ingest/pipeline/put",
                        "cluster:admin/ingest/pipeline/get",
                        "cluster:admin/ingest/pipeline/delete",
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

        DeletePipeline deletePipeline2 = new DeletePipeline.Builder("test").build();

        result = client.executeE(deletePipeline2);

        Assert.assertTrue(result.v1().isSucceeded());

    }

    @Test
    public void trySimulatePipelineRequest() throws Exception {

        username = "logs-xv-12345";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "forbidden")
                .putList("armor.actionrequestfilter.forbidden.allowed_actions",
                        "cluster:admin/ingest/pipeline/put",
                        "cluster:admin/ingest/pipeline/get",
                        "cluster:admin/ingest/pipeline/simulate",
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

        SimulatePipeline simulatePipeline = new SimulatePipeline.Builder().payload("{\n" +
                "  \"pipeline\" :\n" +
                "  {\n" +
                "    \"description\": \"_description\",\n" +
                "    \"processors\": [\n" +
                "      {\n" +
                "        \"set\" : {\n" +
                "          \"field\" : \"field2\",\n" +
                "          \"value\" : \"_value\"\n" +
                "        }\n" +
                "      }\n" +
                "    ]\n" +
                "  },\n" +
                "  \"docs\": [\n" +
                "    {\n" +
                "      \"_index\": \"index\",\n" +
                "      \"_type\": \"_doc\",\n" +
                "      \"_id\": \"id\",\n" +
                "      \"_source\": {\n" +
                "        \"foo\": \"bar\"\n" +
                "      }\n" +
                "    },\n" +
                "    {\n" +
                "      \"_index\": \"index\",\n" +
                "      \"_type\": \"_doc\",\n" +
                "      \"_id\": \"id\",\n" +
                "      \"_source\": {\n" +
                "        \"foo\": \"rab\"\n" +
                "      }\n" +
                "    }\n" +
                "  ]\n" +
                "}").build();

        Tuple<JestResult, HttpResponse> result = client.executeE(simulatePipeline);

        Assert.assertTrue(result.v1().isSucceeded());
        Assert.assertTrue(result.v1().getJsonString().contains("field2"));

    }


    @Test
    public void tryPutSimulatePipelineRequest() throws Exception {

        username = "logs-xv-12345";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "forbidden")
                .putList("armor.actionrequestfilter.forbidden.allowed_actions",
                        "cluster:admin/ingest/pipeline/put",
                        "cluster:admin/ingest/pipeline/get",
                        "cluster:admin/ingest/pipeline/simulate",
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

        PutPipeline putPipelineRequest = new PutPipeline.Builder("test").payload("{\n" +
                "    \"description\": \"_description\",\n" +
                "    \"processors\": [\n" +
                "      {\n" +
                "        \"set\" : {\n" +
                "          \"field\" : \"field2\",\n" +
                "          \"value\" : \"_value\"\n" +
                "        }\n" +
                "      }\n" +
                "   ]\n" +
                "}").build();

        Tuple<JestResult, HttpResponse> result = client.executeE(putPipelineRequest);

        Assert.assertTrue(result.v1().isSucceeded());


        SimulatePipeline simulPipelineRequest = new SimulatePipeline.Builder("test").payload("{\n" +
                "  \"docs\": [\n" +
                "    {\n" +
                "      \"_index\": \"index\",\n" +
                "      \"_type\": \"_doc\",\n" +
                "      \"_id\": \"id\",\n" +
                "      \"_source\": {\n" +
                "        \"foo\": \"bar\"\n" +
                "      }\n" +
                "    },\n" +
                "    {\n" +
                "      \"_index\": \"index\",\n" +
                "      \"_type\": \"_doc\",\n" +
                "      \"_id\": \"id\",\n" +
                "      \"_source\": {\n" +
                "        \"foo\": \"rab\"\n" +
                "      }\n" +
                "    }\n" +
                "  ]\n" +
                "}").build();

        result = client.executeE(simulPipelineRequest);
        Assert.assertTrue(result.v1().isSucceeded());
        Assert.assertTrue(result.v1().getJsonString().contains("field2"));

    }

    @Test
    public void denyHarmfulScript() throws Exception{

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

        //Source script is :
        //  "source": """
        //    ctx._index = 'my_index';
        //    ctx._type = '_doc';
        //  """
        PutPipeline putPipeline = new PutPipeline.Builder("test").payload("{\n" +
                "    \"description\": \"use index:my_index and type:_doc\",\n" +
                "    \"processors\": [\n" +
                "      {\n" +
                "        \"script\": {\n" +
                "          \"source\": \"ctx._index = \\u0027my_index\\u0027;\\nctx._type = \\u0027_doc\\u0027;\"\n" +
                "        }\n" +
                "      }\n" +
                "    ]\n" +
                "}").build();

        Tuple<JestResult, HttpResponse> result = client.executeE(putPipeline);

        Assert.assertFalse(result.v1().isSucceeded());
        Assert.assertEquals(403, result.v2().getStatusLine().getStatusCode());

    }


    @Test
    public void tryPutAndIndexPipelineRequest() throws Exception {

        username = "logs-xv-12345";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "forbidden","lifecycle_index")
                .putList("armor.actionrequestfilter.forbidden.allowed_actions",
                        "cluster:admin/ingest/pipeline/put",
                        "cluster:admin/ingest/pipeline/get",
                        "cluster:admin/ingest/pipeline/delete",
                        "indices:admin/template/put",
                        "indices:admin/template/get",
                        "indices:admin/template/delete",
                        "indices:admin/aliases",
                        "indices:data/read/scroll",
                        "indices:data/read/scroll/clear")
                .putList("armor.actionrequestfilter.lifecycle_index.allowed_actions",
                        "indices:admin/create",
                        "indices:data*")
                .put(ConfigConstants.ARMOR_INGEST_PIPELINE_FILTER_ENABLED, true)
                .put(authSettings).build();


        startES(settings);

        setupTestData("ac_rules_28.json");

        HeaderAwareJestHttpClient client = getJestClient(getServerUri(false), username, password);

        PutPipeline putPipelineRequest = new PutPipeline.Builder("test").payload("{\n" +
                "    \"description\": \"_description\",\n" +
                "    \"processors\": [\n" +
                "      {\n" +
                "        \"set\" : {\n" +
                "          \"field\" : \"field2\",\n" +
                "          \"value\" : \"_value\"\n" +
                "        }\n" +
                "      }\n" +
                "   ]\n" +
                "}").build();


        Tuple<JestResult, HttpResponse> result = client.executeE(putPipelineRequest);

        Assert.assertTrue(result.v1().isSucceeded());

        GetPipeline getPipeline = new GetPipeline.Builder("test").build();

        result = client.executeE(getPipeline);

        Assert.assertTrue(result.v1().isSucceeded());
        Assert.assertTrue(result.v1().getJsonString().contains("_description"));

        final String indexName = "logs-xv-12345-i-index";

        Index indexPipeline1 = new Index.Builder("{\"name\" : \"Gohan\" }").index(indexName).type("_doc").id("id1").setParameter("pipeline","test").build();

        result = client.executeE(indexPipeline1);

        Assert.assertTrue(result.v1().isSucceeded());

        Get getDocument = new Get.Builder(indexName, "id1").build();

        result = client.executeE(getDocument);

        Assert.assertTrue(result.v1().isSucceeded());
        Assert.assertTrue(result.v1().getJsonString().contains("field2"));


    }

    @Test
    public void tryPutAndBulkPipelineRequest() throws Exception {

        username = "logs-xv-12345";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "forbidden","lifecycle_index")
                .putList("armor.actionrequestfilter.forbidden.allowed_actions",
                        "cluster:admin/ingest/pipeline/put",
                        "cluster:admin/ingest/pipeline/get",
                        "cluster:admin/ingest/pipeline/delete",
                        "indices:admin/template/put",
                        "indices:admin/template/get",
                        "indices:admin/template/delete",
                        "indices:admin/aliases",
                        "indices:data/read/scroll",
                        "indices:data/read/scroll/clear")
                .putList("armor.actionrequestfilter.lifecycle_index.allowed_actions",
                        "indices:admin/create",
                        "indices:data*")
                .put(ConfigConstants.ARMOR_INGEST_PIPELINE_FILTER_ENABLED, true)
                .put(authSettings).build();


        startES(settings);

        setupTestData("ac_rules_28.json");

        HeaderAwareJestHttpClient client = getJestClient(getServerUri(false), username, password);

        PutPipeline putPipelineRequest = new PutPipeline.Builder("test").payload("{\n" +
                "    \"description\": \"_description\",\n" +
                "    \"processors\": [\n" +
                "      {\n" +
                "        \"set\" : {\n" +
                "          \"field\" : \"field2\",\n" +
                "          \"value\" : \"_value\"\n" +
                "        }\n" +
                "      }\n" +
                "   ]\n" +
                "}").build();


        Tuple<JestResult, HttpResponse> result = client.executeE(putPipelineRequest);

        Assert.assertTrue(result.v1().isSucceeded());

        GetPipeline getPipeline = new GetPipeline.Builder("test").build();

        result = client.executeE(getPipeline);

        Assert.assertTrue(result.v1().isSucceeded());
        Assert.assertTrue(result.v1().getJsonString().contains("_description"));

        final String indexName = "logs-xv-12345-i-index";

        Bulk bulkPipeline1 = new Bulk.Builder().addAction(new Index.Builder("{\"name\" : \"Gohan\" }").index(indexName).type("_doc").id("id1").build()).setParameter("pipeline","test").build();

        result = client.executeE(bulkPipeline1);

        Assert.assertTrue(result.v1().isSucceeded());

        Get getDocument = new Get.Builder(indexName, "id1").build();

        result = client.executeE(getDocument);

        Assert.assertTrue(result.v1().isSucceeded());
        Assert.assertTrue(result.v1().getJsonString().contains("field2"));

    }

    @Test
    public void testScriptPatterns() {

        String source1 = "toto\nctx._index = 'my_index'\ntoto";
        String source2 = "toto\nfield1 = ctx._index\ntoto";

        Pattern pattern = Pattern.compile(".*ctx\\._index\\s+=\\s+.*");

        Assert.assertTrue(pattern.matcher(source1).find());
        Assert.assertFalse(pattern.matcher(source2).find());



    }
}
