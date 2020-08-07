package com.petalmd.armor;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.petalmd.armor.processor.LDPGelf;
import com.petalmd.armor.processor.kafka.KafkaOutput;
import com.petalmd.armor.processor.kafka.KafkaOutputConsumer;
import com.petalmd.armor.processor.kafka.KafkaOutputFactory;
import com.petalmd.armor.tests.GetPipeline;
import com.petalmd.armor.tests.PutPipeline;
import com.petalmd.armor.util.ConfigConstants;
import io.searchbox.client.JestResult;
import io.searchbox.core.Get;
import io.searchbox.core.Index;
import org.apache.http.HttpResponse;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.joda.time.DateTime;
import org.junit.Assert;
import org.junit.Test;

import java.io.ObjectInputFilter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class LDPProcessorTest extends AbstractUnitTest {


    public void testKafka() throws Exception {
        final Settings settings = Settings.builder()
                .put(ConfigConstants.ARMOR_LDP_PROCESSOR_KAFKA_ENABLED, true)
                .put(ConfigConstants.ARMOR_LDP_PROCESSOR_KAFKA_OUTPUT_USE_KAFKA_IMPL, true)
                .put(ConfigConstants.ARMOR_LDP_PROCESSOR_KAFKA_CLIENT_ID, "id-1")
                .put(ConfigConstants.ARMOR_LDP_PROCESSOR_KAFKA_ACKS_CONFIG, "all")
                .put(ConfigConstants.ARMOR_LDP_PROCESSOR_KAFKA_BOOTSTRAP_SERVERS, "kafka-1.alpha.thot.ovh.com:9094")
                .put(ConfigConstants.ARMOR_LDP_PROCESSOR_KAFKA_TOPIC, "alpha.log1")
                .build();

        KafkaOutputFactory.makeInstance(settings);

        final KafkaOutput kafkaOutput = KafkaOutputFactory.getInstance().getKafkaOutput();
        kafkaOutput.initialize();

        final LDPGelf ldpGelf = new LDPGelf();
        ldpGelf.addString("name", "C18");
        ldpGelf.addString("X-OVH-TOKEN", "ohyeah");
        ldpGelf.setTimestamp(DateTime.now());
        kafkaOutput.sendLDPGelf(ldpGelf.validate());

        kafkaOutput.flush();
        kafkaOutput.close();

    }


    @Test
    public void setupAndIndex() throws Exception {

        username = "logs-xv-12345";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "forbidden", "ingest")
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
                .putList("armor.actionrequestfilter.ingest.allowed_actions",
                        "indices:admin/create",
                        "indices:admin/mapping/put",
                        "indices:data*")
                .put(ConfigConstants.ARMOR_AUDITLOG_ENABLED, false)
                .put(ConfigConstants.ARMOR_INGEST_PIPELINE_FILTER_ENABLED, true)
                .put(ConfigConstants.ARMOR_LDP_PROCESSOR_KAFKA_OUTPUT_USE_KAFKA_IMPL, false)
                .put(ConfigConstants.ARMOR_LDP_PROCESSOR_KAFKA_TOPIC, "log.test")
                .put(authSettings).build();

        startES(settings);

        setupTestData("ac_rules_29.json");

        HeaderAwareJestHttpClient client = getJestClient(getServerUri(false), username, password);

        List<String> gelfStringList = new ArrayList<>();
        List<String> gelfIntList = new ArrayList<>();
        List<String> gelfDateList = new ArrayList<>();
        List<String> gelfNumList = new ArrayList<>();
        List<String> gelfBoolList = new ArrayList<>();

        final KafkaOutputConsumer kafkaConsumer = new KafkaOutputConsumer(null);
        KafkaOutputFactory.getInstance().setKafkaOutput(kafkaConsumer);

        Consumer<LDPGelf> baseConsumer = (ldpGelf) -> {
            for (String strField : gelfStringList) {
                Assert.assertTrue(ldpGelf.getDocumentMap().containsKey("_" + strField));
            }
            for (String intField : gelfIntList) {
                Assert.assertTrue(ldpGelf.getDocumentMap().containsKey("_" + intField + "_long"));
            }
            for (String dateField : gelfDateList) {
                Assert.assertTrue(ldpGelf.getDocumentMap().containsKey("_" + dateField + "_date"));
            }
            for (String numField : gelfNumList) {
                Assert.assertTrue(ldpGelf.getDocumentMap().containsKey("_" + numField + "_num"));
            }

            for (String boolField : gelfBoolList) {
                Assert.assertTrue(ldpGelf.getDocumentMap().containsKey("_" + boolField + "_bool"));
            }
        };


        PutPipeline putPipelineRequest = new PutPipeline.Builder("test").payload("{\n" +
                "    \"description\": \"_description\",\n" +
                "    \"processors\": [\n" +
                "      {\n" +
                "        \"ldp\" : {\n" +
                "          \"drop_message\" : true\n" +
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

        Index indexFirst = new Index.Builder("{\"name\" : \"Gohan\" }").index(indexName).type("_doc").id("id1").setParameter("timeout", "1m").build();

        result = client.executeE(indexFirst);

        Assert.assertTrue(result.v1().isSucceeded());

        Get getDocument = new Get.Builder(indexName, "id1").build();

        result = client.executeE(getDocument);

        Assert.assertTrue(result.v1().isSucceeded());
        Assert.assertTrue(result.v1().getJsonString().contains("Gohan"));

        //Preparing first Pipeline test
        gelfStringList.clear();
        gelfStringList.add("name");

        AtomicBoolean hasRun = new AtomicBoolean(false);
        Consumer<LDPGelf> firstTest = (ldpGelf) -> {
            baseConsumer.accept(ldpGelf);
            Assert.assertEquals("Cell", ldpGelf.getDocumentMap().get("_name"));
            hasRun.set(true);
        };

        kafkaConsumer.setConsumer(firstTest);


        Index indexPipeline1 = new Index.Builder("{\"name\" : \"Cell\" }").index(indexName).type("_doc").id("id2").setParameter("pipeline", "test").setParameter("timeout", "1m").build();
        result = client.executeE(indexPipeline1);
        Assert.assertTrue(result.v1().isSucceeded());

        Assert.assertEquals(true, hasRun.get());

        //Preparing second Pipeline test
        gelfStringList.clear();
        gelfStringList.add("name");
        gelfStringList.add("X-OVH-TOKEN");
        gelfStringList.add("arrival_date");
        gelfIntList.clear();
        gelfIntList.add("universe");
        gelfNumList.clear();
        gelfNumList.add("power");
        gelfBoolList.clear();
        gelfBoolList.add("is_super_saiyen");

        hasRun.set(false);
        Consumer<LDPGelf> secondTest = (ldpGelf) -> {
            baseConsumer.accept(ldpGelf);
            Assert.assertEquals("Goku", ldpGelf.getDocumentMap().get("_name"));
            Assert.assertEquals("ohyeah", ldpGelf.getDocumentMap().get("_X-OVH-TOKEN"));
            Assert.assertEquals(9000.0, ldpGelf.getDocumentMap().get("_power_num"));
            Assert.assertEquals("true", ldpGelf.getDocumentMap().get("_is_super_saiyen_bool")); //boolean must be in text for Graylog...
            Assert.assertEquals("1984-12-03T05:06:00.000Z", ldpGelf.getDocumentMap().get("_arrival_date"));
            hasRun.set(true);
        };

        kafkaConsumer.setConsumer(secondTest);

        Index indexPipeline2 = new Index.Builder("{\"name\" : \"Goku\",\"power\" : 9000.0,\"universe\" : 7, \"X-OVH-TOKEN\" : \"ohyeah\", \"arrival_date\" : \"1984-12-03T05:06:00.000Z\" , \"is_super_saiyen\" : true }").index(indexName).type("_doc").id("id3").setParameter("pipeline", "test").setParameter("timeout", "1m").build();
        result = client.executeE(indexPipeline2);
        Assert.assertTrue(result.v1().isSucceeded());

        Assert.assertEquals(true, hasRun.get());


    }
}
