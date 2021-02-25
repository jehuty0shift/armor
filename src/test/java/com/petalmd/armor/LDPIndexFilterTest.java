package com.petalmd.armor;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.petalmd.armor.common.LDPGelf;
import com.petalmd.armor.processor.kafka.KafkaOutputConsumer;
import com.petalmd.armor.processor.kafka.KafkaOutputFactory;
import com.petalmd.armor.tests.GetPipeline;
import com.petalmd.armor.tests.PutSettings;
import com.petalmd.armor.util.ConfigConstants;
import io.searchbox.client.JestResult;
import io.searchbox.core.Bulk;
import io.searchbox.core.Index;
import io.searchbox.indices.CreateIndex;
import io.searchbox.indices.mapping.GetMapping;
import io.searchbox.indices.mapping.PutMapping;
import org.apache.http.HttpResponse;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class LDPIndexFilterTest extends AbstractUnitTest {


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


        //create ldpIndex
        CreateIndex createIndex = new CreateIndex.Builder(ldpIndex).build();

        HeaderAwareJestHttpClient localHostClient = getJestClient(getServerUri(true), username, password);

        Tuple<JestResult, HttpResponse> result = localHostClient.executeE(createIndex);
        Assert.assertTrue(result.v1().isSucceeded());


        GetPipeline getPipeline = new GetPipeline.Builder(ldpPipelineName).build();

        result = localHostClient.executeE(getPipeline);

        int count = 300;
        while (result.v2().getStatusLine().getStatusCode() != 200 && count > 0) {
            Thread.sleep(1000);
            result = localHostClient.executeE(getPipeline);
            count--;
        }

        // Put the instance once the pipeline is created
        KafkaOutputFactory.getInstance().setKafkaOutput(kafkaConsumer);


        HeaderAwareJestHttpClient client = getJestClient(getServerUri(false), username, password);

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

        Index indexFirst = new Index.Builder("{\"name\" : \"Babidi\" }")
                .index(ldpIndex)
                .type("_doc")
                .id("id1")
                .setParameter("timeout", "1m")
                .build();

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

        result = client.executeE(indexFirst);
        Assert.assertTrue(result.v1().isSucceeded());
        Assert.assertEquals(true, hasRun.get());

        //Bulk Indexing test
        gelfStringList.clear();
        gelfStringList.add("name");
        hasRun.set(false);

        Bulk bulkRequest = new Bulk.Builder()
                .addAction(new Index.Builder("{\"name\" : \"Dabra\" }").index(ldpIndex).type("_doc").id("id1").setParameter("timeout", "1m").build())
                .addAction(new Index.Builder("{\"name\" : \"Boo\" }").index(ldpIndex).type("_doc").id("id1").setParameter("timeout", "1m").build())
                .build();


        Consumer<LDPGelf> secondTest = (ldpGelf) -> {
            baseConsumer.accept(ldpGelf);
            final String name = ldpGelf.getDocumentMap().get("_name").toString();
            Assert.assertTrue(name.equals("Boo") || name.equals("Dabra"));
            hasRun.set(true);
        };

        kafkaConsumer.setConsumer(secondTest);


        result = client.executeE(bulkRequest);
        Assert.assertTrue(result.v1().isSucceeded());
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
        CreateIndex createIndex = new CreateIndex.Builder(ldpIndex).build();

        HeaderAwareJestHttpClient localHostClient = getJestClient(getServerUri(true), username, password);

        Tuple<JestResult, HttpResponse> result = localHostClient.executeE(createIndex);
        Assert.assertTrue(result.v1().isSucceeded());

        HeaderAwareJestHttpClient client = getJestClient(getServerUri(false), username, password);

        PutMapping pMapping = new PutMapping.Builder(ldpIndex, "_doc", "{\n" +
                "  \"properties\": {\n" +
                "    \"email\": {\n" +
                "      \"type\": \"keyword\"\n" +
                "    }\n" +
                "  }\n" +
                "}").build();

        result = client.executeE(pMapping);

        Assert.assertTrue(result.v1().isSucceeded());
        Assert.assertTrue(result.v1().getJsonString().contains("true"));

        PutSettings putSettings = new PutSettings.Builder("{\n" +
                "    \"index\" : {\n" +
                "        \"number_of_replicas\" : 2\n" +
                "    }\n" +
                "}").addIndex(ldpIndex).addIndex("dev").build();

        result = client.executeE(putSettings);

        Assert.assertTrue(result.v1().isSucceeded());
        Assert.assertEquals(200, result.v2().getStatusLine().getStatusCode());
        Assert.assertFalse(result.v1().getJsonString().contains(ldpIndex));


        GetMapping gMapping = new GetMapping.Builder().addIndex(ldpIndex).build();

        result = client.executeE(gMapping);

        Assert.assertFalse(result.v1().isSucceeded());
        Assert.assertEquals(403, result.v2().getStatusLine().getStatusCode());
        Assert.assertTrue(result.v1().getErrorMessage().contains("This action is not authorized"));


    }


}
