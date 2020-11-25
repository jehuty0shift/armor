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
import org.elasticsearch.ElasticsearchStatusException;
import org.elasticsearch.action.DocWriteRequest;
import org.elasticsearch.action.DocWriteResponse;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.bulk.BulkResponse;
import org.elasticsearch.action.get.GetRequest;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.action.ingest.*;
import org.elasticsearch.action.support.master.AcknowledgedResponse;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.client.indices.GetIndexResponse;
import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.rest.RestStatus;
import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;
import java.util.regex.Pattern;

/**
 * Created by jehuty0shift on 11/03/2020.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class IngestPipelineFilterTest extends AbstractArmorTest {


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
                .put(ConfigConstants.ARMOR_AUDITLOG_ENABLED, false)
                .put(ConfigConstants.ARMOR_INGEST_PIPELINE_FILTER_ENABLED, true)
                .put(authSettings).build();


        startES(settings);

        setupTestData("ac_rules_28.json");

        RestHighLevelClient client = getRestClient(false, username, password);

        String pipelineSource = "{\n" +
                "  \"description\" : \"my first pipeline\",\n" +
                "  \"processors\": [\n" +
                "    {\n" +
                "      \"grok\": {\n" +
                "        \"field\": \"message\",\n" +
                "        \"patterns\": [\"%{IP:client} %{WORD:method} %{URIPATHPARAM:request} %{NUMBER:bytes} %{NUMBER:duration}\"]\n" +
                "      }\n" +
                "    }\n" +
                "  ]\n" +
                "}";


        AcknowledgedResponse putResp = client.ingest().putPipeline(new PutPipelineRequest("test", new BytesArray(pipelineSource), XContentType.JSON), RequestOptions.DEFAULT);

        Assert.assertTrue(putResp.isAcknowledged());

        GetPipelineResponse getResp = client.ingest().getPipeline(new GetPipelineRequest("test"), RequestOptions.DEFAULT);

        Assert.assertTrue(getResp.pipelines().get(0).toString().contains("my first pipeline"));

        GetPipelineResponse getResp2 = client.ingest().getPipeline(new GetPipelineRequest(username + "-test"), RequestOptions.DEFAULT);

        Assert.assertTrue(getResp2.pipelines().get(0).toString().contains("my first pipeline"));

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
                .put(ConfigConstants.ARMOR_AUDITLOG_ENABLED, false)
                .put(ConfigConstants.ARMOR_INGEST_PIPELINE_FILTER_ENABLED, true)
                .put(authSettings).build();


        startES(settings);

        setupTestData("ac_rules_28.json");

        RestHighLevelClient client = getRestClient(false, username, password);

        final String pipelineSource = "{\n" +
                "  \"description\" : \"my first pipeline\",\n" +
                "  \"processors\": [\n" +
                "    {\n" +
                "      \"grok\": {\n" +
                "        \"field\": \"message\",\n" +
                "        \"patterns\": [\"%{IP:client} %{WORD:method} %{URIPATHPARAM:request} %{NUMBER:bytes} %{NUMBER:duration}\"]\n" +
                "      }\n" +
                "    }\n" +
                "  ]\n" +
                "}";

        AcknowledgedResponse putResp = client.ingest().putPipeline(new PutPipelineRequest("test", new BytesArray(pipelineSource), XContentType.JSON), RequestOptions.DEFAULT);

        Assert.assertTrue(putResp.isAcknowledged());

        GetPipelineResponse getResp = client.ingest().getPipeline(new GetPipelineRequest("test"), RequestOptions.DEFAULT);

        Assert.assertTrue(getResp.pipelines().get(0).toString().contains("my first pipeline"));

        AcknowledgedResponse delResp = client.ingest().deletePipeline(new DeletePipelineRequest("test"), RequestOptions.DEFAULT);

        Assert.assertTrue(delResp.isAcknowledged());

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
                .put(ConfigConstants.ARMOR_AUDITLOG_ENABLED, false)
                .put(ConfigConstants.ARMOR_INGEST_PIPELINE_FILTER_ENABLED, true)
                .put(authSettings).build();


        startES(settings);

        setupTestData("ac_rules_28.json");

        RestHighLevelClient client = getRestClient(false, username, password);

        final String simulatePayload = "{\n" +
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
                "}";

        SimulatePipelineResponse simResp = client.ingest().simulate(new SimulatePipelineRequest(new BytesArray(simulatePayload), XContentType.JSON), RequestOptions.DEFAULT);

        Assert.assertTrue(simResp.getResults().stream().allMatch(sd -> ((SimulateDocumentBaseResult) sd).getIngestDocument().hasField("field2")));

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
                .put(ConfigConstants.ARMOR_AUDITLOG_ENABLED, false)
                .put(ConfigConstants.ARMOR_INGEST_PIPELINE_FILTER_ENABLED, true)
                .put(authSettings).build();


        startES(settings);

        setupTestData("ac_rules_28.json");

        RestHighLevelClient client = getRestClient(false, username, password);

        final String pipeline1 = "{\n" +
                "    \"description\": \"_description\",\n" +
                "    \"processors\": [\n" +
                "      {\n" +
                "        \"set\" : {\n" +
                "          \"field\" : \"field2\",\n" +
                "          \"value\" : \"_value\"\n" +
                "        }\n" +
                "      }\n" +
                "   ]\n" +
                "}";

        AcknowledgedResponse putResp = client.ingest().putPipeline(new PutPipelineRequest("test", new BytesArray(pipeline1), XContentType.JSON), RequestOptions.DEFAULT);

        Assert.assertTrue(putResp.isAcknowledged());

        final String simulatePayload = "{\n" +
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
                "}";

        SimulatePipelineRequest spReq1 = new SimulatePipelineRequest(new BytesArray(simulatePayload), XContentType.JSON);
        spReq1.setId("test");

        SimulatePipelineResponse simResp = client.ingest().simulate(spReq1, RequestOptions.DEFAULT);

        Assert.assertTrue(simResp.getResults().stream().allMatch(sd -> ((SimulateDocumentBaseResult) sd).getIngestDocument().hasField("field2")));

    }

    @Test
    public void denyHarmfulScript() throws Exception {

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
                .put(ConfigConstants.ARMOR_AUDITLOG_ENABLED, false)
                .put(ConfigConstants.ARMOR_INGEST_PIPELINE_FILTER_ENABLED, true)
                .put(authSettings).build();


        startES(settings);

        setupTestData("ac_rules_28.json");

        RestHighLevelClient client = getRestClient(false, username, password);

        //Source script is :
        //  "source": """
        //    ctx._index = 'my_index';
        //    ctx._type = '_doc';
        //  """
        final String putPipeline1 = "{\n" +
                "    \"description\": \"use index:my_index and type:_doc\",\n" +
                "    \"processors\": [\n" +
                "      {\n" +
                "        \"script\": {\n" +
                "          \"source\": \"ctx._index = \\u0027my_index\\u0027;\\nctx._type = \\u0027_doc\\u0027;\"\n" +
                "        }\n" +
                "      }\n" +
                "    ]\n" +
                "}";


        ElasticsearchStatusException putFail = expectThrows(ElasticsearchStatusException.class,
                () -> client.ingest().putPipeline(new PutPipelineRequest("test", new BytesArray(putPipeline1), XContentType.JSON), RequestOptions.DEFAULT));

        Assert.assertEquals(putFail.status(), RestStatus.FORBIDDEN);

        //Source script is :
        //  "source": """
        //    ctx._index -= 'my_index';
        //    ctx._index += 'graylog2_125';
        //    ctx._type = '_doc';
        //  """
        final String putPipeline2 = "{\n" +
                "    \"description\": \"remplace index my_index with graylog2_125 and type:_doc\",\n" +
                "    \"processors\": [\n" +
                "      {\n" +
                "        \"script\": {\n" +
                "          \"source\": \"ctx._index -= \\u0027my_index\\u0027;\\nctx._index = \\u0027graylog_2125\\u0027\\nctx._type = \\u0027_doc\\u0027;\"\n" +
                "        }\n" +
                "      }\n" +
                "    ]\n" +
                "}";

        ElasticsearchStatusException putFail2 = expectThrows(ElasticsearchStatusException.class,
                () -> client.ingest().putPipeline(new PutPipelineRequest("test", new BytesArray(putPipeline2), XContentType.JSON), RequestOptions.DEFAULT));

        Assert.assertEquals(putFail2.status(), RestStatus.FORBIDDEN);

    }


    @Test
    public void tryPutAndIndexPipelineRequest() throws Exception {

        username = "logs-xv-12345";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "forbidden", "lifecycle_index")
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
                        "indices:admin/auto_create",
                        "indices:admin/create",
                        "indices:admin/mapping/auto_put",
                        "indices:admin/mapping/put",
                        "indices:data*")
                .put(ConfigConstants.ARMOR_AUDITLOG_ENABLED, false)
                .put(ConfigConstants.ARMOR_INGEST_PIPELINE_FILTER_ENABLED, true)
                .put(authSettings).build();


        startES(settings);

        setupTestData("ac_rules_28.json");

        RestHighLevelClient client = getRestClient(false, username, password);

        final String pipeline1 = "{\n" +
                "    \"description\": \"_description\",\n" +
                "    \"processors\": [\n" +
                "      {\n" +
                "        \"set\" : {\n" +
                "          \"field\" : \"field2\",\n" +
                "          \"value\" : \"_value\"\n" +
                "        }\n" +
                "      }\n" +
                "   ]\n" +
                "}";

        AcknowledgedResponse putResp = client.ingest().putPipeline(new PutPipelineRequest("test", new BytesArray(pipeline1), XContentType.JSON), RequestOptions.DEFAULT);

        Assert.assertTrue(putResp.isAcknowledged());

        GetPipelineResponse getPipelineResp = client.ingest().getPipeline(new GetPipelineRequest("test"), RequestOptions.DEFAULT);

        Assert.assertTrue(getPipelineResp.pipelines().get(0).toString().contains("_description"));

        final String indexName = "logs-xv-12345-i-index";

        IndexResponse iResp = client.index(new IndexRequest(indexName)
                .id("id1")
                .setPipeline("test")
                .source("{\"name\" : \"Gohan\" }", XContentType.JSON),
                RequestOptions.DEFAULT);

        Assert.assertTrue(iResp.getResult().equals(DocWriteResponse.Result.CREATED));

        GetResponse getResp1 = client.get(new GetRequest(indexName, "id1"), RequestOptions.DEFAULT);

        Assert.assertNotNull(getResp1.getSource().containsKey("field2"));

    }

    @Test
    public void tryPutAndBulkPipelineRequest() throws Exception {

        username = "logs-xv-12345";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "forbidden", "lifecycle_index")
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
                        "indices:admin/auto_create",
                        "indices:admin/create",
                        "indices:admin/mapping/auto_put",
                        "indices:admin/mapping/put",
                        "indices:data*")
                .put(ConfigConstants.ARMOR_AUDITLOG_ENABLED, false)
                .put(ConfigConstants.ARMOR_INGEST_PIPELINE_FILTER_ENABLED, true)
                .put(authSettings).build();


        startES(settings);

        setupTestData("ac_rules_28.json");

        RestHighLevelClient client = getRestClient(false, username, password);

        final String pipeline1 = "{\n" +
                "    \"description\": \"_description\",\n" +
                "    \"processors\": [\n" +
                "      {\n" +
                "        \"set\" : {\n" +
                "          \"field\" : \"field2\",\n" +
                "          \"value\" : \"_value\"\n" +
                "        }\n" +
                "      }\n" +
                "   ]\n" +
                "}";

        AcknowledgedResponse putResp = client.ingest().putPipeline(new PutPipelineRequest("test", new BytesArray(pipeline1), XContentType.JSON), RequestOptions.DEFAULT);

        Assert.assertTrue(putResp.isAcknowledged());

        GetPipelineResponse getPipelineResp = client.ingest().getPipeline(new GetPipelineRequest("test"), RequestOptions.DEFAULT);

        Assert.assertTrue(getPipelineResp.pipelines().get(0).toString().contains("_description"));

        final String indexName = "logs-xv-12345-i-index";

        BulkResponse bResp = client.bulk(new BulkRequest(indexName).add(
                new IndexRequest(indexName)
                        .id("id1")
                        .setPipeline("test")
                        .source("{\"name\" : \"Gohan\" }", XContentType.JSON))
                ,RequestOptions.DEFAULT);

        Assert.assertFalse(bResp.hasFailures());
        Assert.assertTrue(Arrays.stream(bResp.getItems()).allMatch(i -> i.getOpType().equals(DocWriteRequest.OpType.INDEX)));

        GetResponse gResp = client.get(new GetRequest(indexName, "id1"),RequestOptions.DEFAULT);

        Assert.assertNotNull(gResp.getSource().containsKey("field2"));

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
