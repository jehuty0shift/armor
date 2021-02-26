package com.petalmd.armor;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.petalmd.armor.common.KafkaOutputConsumer;
import com.petalmd.armor.common.LDPGelf;
import com.petalmd.armor.processor.kafka.KafkaOutputFactory;
import com.petalmd.armor.util.ConfigConstants;
import org.apache.http.entity.BasicHttpEntity;
import org.elasticsearch.ElasticsearchStatusException;
import org.elasticsearch.action.admin.indices.settings.put.UpdateSettingsRequest;
import org.elasticsearch.action.support.master.AcknowledgedResponse;
import org.elasticsearch.client.Request;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.Response;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.client.indices.CreateIndexRequest;
import org.elasticsearch.client.indices.CreateIndexResponse;
import org.elasticsearch.client.indices.GetMappingsRequest;
import org.elasticsearch.client.indices.PutMappingRequest;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentType;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class LDPIndexFilterTest extends AbstractArmorTest {


    @Test
    public void indexOnLDPIndex() throws Exception {

        username = "logs-xv-12345";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final String ldpIndex = "ldp-logs";
        final String ldpPipelineName = "ldpDefault";

        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "forbidden", "writer")
                .putList("armor.actionrequestfilter.forbidden.allowed_actions",
                        "indices:admin/template/put",
                        "indices:admin/template/get",
                        "indices:admin/template/delete",
                        "indices:admin/aliases",
                        "indices:data/read/scroll",
                        "indices:data/read/scroll/clear")
                .putList("armor.actionrequestfilter.writer.allowed_actions",
                        "indices:admin/create",
                        "indices:data*")
                .put(ConfigConstants.ARMOR_AUDITLOG_ENABLED, false)
                .put(ConfigConstants.ARMOR_LDP_INDEX, ldpIndex)
                .put(ConfigConstants.ARMOR_LDP_FILTER_ENABLED, true)
                .put(ConfigConstants.ARMOR_LDP_FILTER_LDP_PIPELINE_NAME, ldpPipelineName)
                .put(ConfigConstants.ARMOR_INGEST_PIPELINE_FILTER_ENABLED, true)
                .put(ConfigConstants.ARMOR_LDP_PROCESSOR_KAFKA_OUTPUT_USE_KAFKA_IMPL, false)
                .put(ConfigConstants.ARMOR_LDP_PROCESSOR_KAFKA_TOPIC, "log.test")
                .put(authSettings).build();

        final KafkaOutputConsumer kafkaConsumer = new KafkaOutputConsumer(null);
        KafkaOutputFactory.makeInstance(settings).setKafkaOutput(kafkaConsumer);

        startES(settings);

        setupTestData("ac_rules_30.json");

        RestHighLevelClient localHostClient = getRestClient(true, username, password);

        //create ldpIndex
        CreateIndexResponse cir = localHostClient.indices().create(new CreateIndexRequest(ldpIndex), RequestOptions.DEFAULT);
        Assert.assertTrue(cir.isAcknowledged());

        ObjectMapper objMapper = new ObjectMapper();
        int count = 600;
        while (count > 0) {
            try {
                Response resp = localHostClient.getLowLevelClient().performRequest(new Request("GET","_armor/ldp_index"));
                JsonNode ldpInfoNode = objMapper.reader().readTree(resp.getEntity().getContent().readAllBytes());
                if (ldpInfoNode.get("enabled").asBoolean()) {
                    log.info("{} has been enabled, breaking", ldpPipelineName);
                    break;
                }
                Thread.sleep(1000);
                count--;
            } catch (ElasticsearchStatusException ex) {
                log.info("{} has not been enabled yet, retrying", ldpPipelineName);
                count--;
            }
        }

        // Put the instance once the pipeline is created
        KafkaOutputFactory.getInstance().setKafkaOutput(kafkaConsumer);

        RestHighLevelClient client = getRestClient(false, username, password);

        //Configure base Consumer
        List<String> gelfStringList = new ArrayList<>();
        List<String> gelfIntList = new ArrayList<>();
        List<String> gelfDateList = new ArrayList<>();
        List<String> gelfNumList = new ArrayList<>();

        Consumer<LDPGelf> baseConsumer = (ldpGelf) -> {
            for (String strField : gelfStringList) {
                Assert.assertTrue(ldpGelf.getDocumentMap().containsKey("_" + strField));
            }
            for (String intField : gelfIntList) {
                Assert.assertTrue(ldpGelf.getDocumentMap().containsKey("_" + intField + "_int"));
            }
            for (String dateField : gelfDateList) {
                Assert.assertTrue(ldpGelf.getDocumentMap().containsKey("_" + dateField + "_int"));
            }
            for (String numField : gelfNumList) {
                Assert.assertTrue(ldpGelf.getDocumentMap().containsKey("_" + numField + "_num"));
            }

        };


        //Preparing first Indexing Test
        gelfStringList.clear();
        gelfStringList.add("name");

        AtomicBoolean hasRun = new AtomicBoolean(false);
        Consumer<LDPGelf> firstTest = (ldpGelf) -> {
            baseConsumer.accept(ldpGelf);
            Assert.assertEquals("Babidi", ldpGelf.getDocumentMap().get("_name"));
            hasRun.set(true);
        };

        kafkaConsumer.setConsumer(firstTest);

        Request indexReq1 = new Request("POST", ldpIndex + "/_doc/" + "id1");
        BasicHttpEntity bHE1 = new BasicHttpEntity();
        bHE1.setContent(new ByteArrayInputStream("{\"name\" : \"Babidi\" }".getBytes()));
        indexReq1.setEntity(bHE1);
        bHE1.setContentType("application/json");

        Response iResp1 = client.getLowLevelClient().performRequest(indexReq1);
        Assert.assertEquals(200, iResp1.getStatusLine().getStatusCode());
        Assert.assertEquals(true, hasRun.get());

        //Bulk Indexing test
        gelfStringList.clear();
        gelfStringList.add("name");
        hasRun.set(false);

        Consumer<LDPGelf> secondTest = (ldpGelf) -> {
            baseConsumer.accept(ldpGelf);
            final String name = ldpGelf.getDocumentMap().get("_name").toString();
            Assert.assertTrue(name.equals("Boo") || name.equals("Dabra"));
            hasRun.set(true);
        };

        kafkaConsumer.setConsumer(secondTest);

        Request indexReq2 = new Request("POST", ldpIndex + "/_bulk");
        BasicHttpEntity bHE2 = new BasicHttpEntity();
        final String source = "{ \"index\" : { \"_index\" : \"" + ldpIndex + "\", \"_id\" : \"id1\" } }" + "\n" +
                "{\"name\" : \"Dabra\" }" + "\n" +
                "{ \"index\" : { \"_index\" : \"" + ldpIndex + "\", \"_id\" : \"id2\" } }" + "\n" +
                "{\"name\" : \"Boo\" }"+"\n";
        bHE2.setContent(new ByteArrayInputStream(source.getBytes()));
        bHE2.setContentType("application/json");
        indexReq2.setEntity(bHE2);

        Response bResp = client.getLowLevelClient().performRequest(indexReq2);

        JsonNode bRespJson = objMapper.reader().readTree(bResp.getEntity().getContent().readAllBytes());
        Assert.assertFalse(bRespJson.get("errors").asBoolean());
        Assert.assertTrue(bRespJson.get("items").isArray());
        Assert.assertEquals(2, bRespJson.get("items").size());
        Assert.assertTrue(hasRun.get());

    }

    @Test
    public void indicesRequestsOnLDPIndex() throws Exception {

        username = "logs-xv-12345";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final String ldpIndex = "ldp-logs";
        final String ldpPipelineName = "ldpDefault";

        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "forbidden", "writer")
                .putList("armor.actionrequestfilter.forbidden.allowed_actions",
                        "indices:admin/template/put",
                        "indices:admin/template/get",
                        "indices:admin/template/delete",
                        "indices:admin/aliases",
                        "indices:admin/mapping*",
                        "indices:admin/settings*",
                        "indices:data/read/scroll",
                        "indices:data/read/scroll/clear")
                .putList("armor.actionrequestfilter.writer.allowed_actions",
                        "indices:admin/create",
                        "indices:data*")
                .put(ConfigConstants.ARMOR_AUDITLOG_ENABLED, false)
                .put(ConfigConstants.ARMOR_LDP_INDEX, ldpIndex)
                .put(ConfigConstants.ARMOR_LDP_FILTER_ENABLED, true)
                .put(ConfigConstants.ARMOR_LDP_FILTER_LDP_PIPELINE_NAME, ldpPipelineName)
                .put(ConfigConstants.ARMOR_INGEST_PIPELINE_FILTER_ENABLED, true)
                .put(ConfigConstants.ARMOR_LDP_PROCESSOR_KAFKA_OUTPUT_USE_KAFKA_IMPL, false)
                .put(ConfigConstants.ARMOR_LDP_PROCESSOR_KAFKA_TOPIC, "log.test")
                .put(authSettings).build();

        final KafkaOutputConsumer kafkaConsumer = new KafkaOutputConsumer(null);
        KafkaOutputFactory.makeInstance(settings).setKafkaOutput(kafkaConsumer);

        startES(settings);

        setupTestData("ac_rules_30.json");

        //create ldpIndex
        RestHighLevelClient localHostClient = getRestClient(true, username, password);

        //create ldpIndex
        CreateIndexResponse cir = localHostClient.indices().create(new CreateIndexRequest(ldpIndex), RequestOptions.DEFAULT);
        Assert.assertTrue(cir.isAcknowledged());

        RestHighLevelClient client = getRestClient(false, username, password);

        AcknowledgedResponse pMR = client.indices().putMapping(new PutMappingRequest(ldpIndex).source("{\n" +
                "  \"properties\": {\n" +
                "    \"email\": {\n" +
                "      \"type\": \"keyword\"\n" +
                "    }\n" +
                "  }\n" +
                "}", XContentType.JSON), RequestOptions.DEFAULT);

        Assert.assertTrue(pMR.isAcknowledged());


        AcknowledgedResponse pSR = client.indices().putSettings(new UpdateSettingsRequest(ldpIndex, "dev")
                .settings(Settings.builder()
                        .put("index.number_of_replicas", 2).build()), RequestOptions.DEFAULT);


        Assert.assertTrue(pSR.isAcknowledged());
        Assert.assertFalse(pSR.toString().contains(ldpIndex));

        ElasticsearchStatusException getFail = expectThrows(ElasticsearchStatusException.class, () -> client.indices().getMapping(new GetMappingsRequest().indices(ldpIndex), RequestOptions.DEFAULT));

        Assert.assertTrue(getFail.getDetailedMessage().contains("This action is not authorized"));


    }


}
