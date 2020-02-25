package com.petalmd.armor;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mongodb.MongoClient;
import com.mongodb.ServerAddress;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.petalmd.armor.filter.lifecycle.AliasOperation;
import com.petalmd.armor.filter.lifecycle.EngineUser;
import com.petalmd.armor.filter.lifecycle.Region;
import com.petalmd.armor.service.KafkaService;
import com.petalmd.armor.service.MongoDBService;
import com.petalmd.armor.util.ConfigConstants;
import de.bwaldvogel.mongo.MongoServer;
import de.bwaldvogel.mongo.backend.memory.MemoryBackend;
import io.searchbox.client.JestResult;
import io.searchbox.indices.CreateIndex;
import io.searchbox.indices.aliases.GetAliases;
import io.searchbox.indices.template.GetTemplate;
import io.searchbox.indices.template.PutTemplate;
import kong.unirest.Unirest;
import org.apache.http.HttpResponse;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.clients.producer.internals.FutureRecordMetadata;
import org.apache.kafka.clients.producer.internals.ProduceRequestResult;
import org.apache.kafka.common.TopicPartition;
import org.bson.Document;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;
import org.powermock.core.classloader.annotations.PrepareForTest;

import java.net.InetSocketAddress;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

/**
 * Created by jehuty0shift on 21/02/2020.
 */

@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
@PrepareForTest({Unirest.class})
public class IndexTemplateFilterTest extends AbstractScenarioTest {


    @Test
    public void templateCreationWithoutIndexLifeCycle() throws Exception {

        username = "logs-xv-12345";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final String indexName = username + "-i-test-1";

        final String engineDatabaseName = "engine";

        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "lifecycle_index", "lifecycle_alias", "forbidden")
                .putList("armor.actionrequestfilter.lifecycle_index.allowed_actions", "indices:admin/create", "indices:admin/delete")
                .putList("armor.actionrequestfilter.lifecycle_alias.allowed_actions", "indices:data/read*")
                .putList("armor.actionrequestfilter.forbidden.allowed_actions", "indices:admin/template/put", "indices:admin/template/get", "indices:admin/template/delete", "indices:admin/aliases", "indices:data/read/scroll", "indices:data/read/scroll/clear")
                .put(ConfigConstants.ARMOR_INDEX_TEMPLATE_FILTER_ENABLED, true)
                .put(authSettings).build();

        startES(settings);
        setupTestData("ac_rules_27.json");

        HeaderAwareJestHttpClient client = getJestClient(getServerUri(false), username, password);

        String source1 = buildTemplateBody(Arrays.asList(username + "-i-*"), Collections.emptyList(), Settings.EMPTY);

        PutTemplate putTemplate1 = new PutTemplate.Builder(username + "-template1", source1).build();

        Tuple<JestResult, HttpResponse> result = client.executeE(putTemplate1);

        Assert.assertTrue(result.v1().isSucceeded());
        Assert.assertTrue(result.v1().getJsonString().contains("acknowledged"));

        String source2 = buildTemplateBody(Arrays.asList(username + "-toto"),Collections.emptyList(),Settings.EMPTY);

        PutTemplate putTemplate2 = new PutTemplate.Builder(username + "-template2",source2).build();

        result = client.executeE(putTemplate2);

        Assert.assertFalse(result.v1().isSucceeded());
        Assert.assertTrue(result.v1().getResponseCode() == 403);
        Assert.assertTrue(result.v1().getErrorMessage().contains(username+"-i"));

        String source3 = buildTemplateBody(Arrays.asList(username + "-i-*"), Arrays.asList(username+"-a-alias1"), Settings.EMPTY);

        PutTemplate putTemplate3 = new PutTemplate.Builder(username + "-template3", source3).build();

        result = client.executeE(putTemplate3);

        Assert.assertTrue(result.v1().isSucceeded());
        Assert.assertTrue(result.v1().getJsonString().contains("acknowledged"));


        String source4 = buildTemplateBody(Arrays.asList(username + "-i-*"), Arrays.asList("alias" + username), Settings.EMPTY);

        PutTemplate putTemplate4 = new PutTemplate.Builder(username + "-template4", source4).build();

        result = client.executeE(putTemplate4);

        Assert.assertFalse(result.v1().isSucceeded());
        Assert.assertTrue(result.v1().getJsonString().contains(username+"-a-"));
        Assert.assertEquals(403,result.v2().getStatusLine().getStatusCode());


        //GET Templates test

        GetTemplate getTemplate1 = new GetTemplate.Builder("graylog2_template").build();

        result = client.executeE(getTemplate1);

        Assert.assertFalse(result.v1().isSucceeded());
        Assert.assertTrue(result.v1().getErrorMessage().contains(username));
        Assert.assertEquals(403, result.v2().getStatusLine().getStatusCode());

        GetTemplate getTemplate2 = new GetTemplate.Builder(username + "-template1").build();

        result = client.executeE(getTemplate2);

        Assert.assertTrue(result.v1().isSucceeded());

    }


    @Test
    public void createTemplatedIndiceWithAliasLifeCycleFilter() throws Exception {
        username = "logs-xv-12345";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final String indexName1 = username + "-i-test-1";
        final String indexName2 = username + "-i-test-2";

        final String aliasName1 = username + "-a-alias";

        final String engineDatabaseName = "engine";

        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "lifecycle_index", "lifecycle_alias", "forbidden")
                .putList("armor.actionrequestfilter.lifecycle_index.allowed_actions", "indices:admin/create", "indices:admin/delete")
                .putList("armor.actionrequestfilter.lifecycle_alias.allowed_actions", "indices:data/read*")
                .putList("armor.actionrequestfilter.forbidden.allowed_actions", "indices:admin/template/put", "indices:admin/template/get", "indices:admin/template/delete", "indices:admin/aliases","indices:admin/aliases/get", "indices:data/read/scroll", "indices:data/read/scroll/clear")
                .putList(ConfigConstants.ARMOR_INDEX_TEMPLATE_FILTER_ALLOWED_SETTINGS, "index.number_of_shards","index.number_of_replicas")
                .put(ConfigConstants.ARMOR_INDEX_TEMPLATE_FILTER_ENABLED, true)
                .put(ConfigConstants.ARMOR_INDEX_LIFECYCLE_ENABLED, true)
                .put(ConfigConstants.ARMOR_ALIAS_LIFECYCLE_ENABLED, true)
                .put(ConfigConstants.ARMOR_MONGODB_URI, "test")
                .put(ConfigConstants.ARMOR_MONGODB_ENGINE_DATABASE, engineDatabaseName)
                .put(ConfigConstants.ARMOR_KAFKA_SERVICE_ENABLED, true)
                .put(ConfigConstants.ARMOR_KAFKA_SERVICE_CLIENT_ID, "dummy")
                .put(authSettings).build();

        MongoServer server = new MongoServer(new MemoryBackend());
        InetSocketAddress serverAddress = server.bind();
        MongoClient mongoClient = new MongoClient(new ServerAddress(serverAddress));
        MongoDBService.setMongoClient(mongoClient);

        MongoDatabase engineTestDatabase = mongoClient.getDatabase(engineDatabaseName);
        EngineUser currentUser = new EngineUser();
        currentUser.setRegion(Region.EU);
        currentUser.setUsername(username);
        currentUser.setTrusted(true);

        configureEngineDatabase(engineTestDatabase, Arrays.asList(currentUser));

        ObjectMapper objectMapper = new ObjectMapper();

        KafkaProducer mockProducer = Mockito.mock(KafkaProducer.class);
        KafkaService.setKafkaProducer(mockProducer);

        System.setProperty("es.set.netty.runtime.available.processors", "false");

        startES(settings);
        setupTestData("ac_rules_27.json");

        HeaderAwareJestHttpClient client = getJestClient(getServerUri(false), username, password);

        final AtomicReference<Boolean> hasSent = new AtomicReference<>();
        final AtomicReference<Boolean> indexSent = new AtomicReference<>();
        final List<String> checkAliases = new ArrayList<>();
        final List<AliasOperation> producedObject = new ArrayList<>();
        final AtomicInteger offset = new AtomicInteger(0);
        hasSent.set(false);
        indexSent.set(false);


        Mockito.when(mockProducer.send(Mockito.any())).then(invocationOnMock -> {
                    ProducerRecord<String, String> producerRecord = (ProducerRecord<String, String>) invocationOnMock.getArgument(0);
                    if (producerRecord.value().contains("alias")) {
                        AliasOperation aOp = objectMapper.readValue(producerRecord.value(), AliasOperation.class);
                        producedObject.add(aOp);
                        if (!checkAliases.isEmpty()) {
                            Assert.assertEquals(username, aOp.getUsername());
                            Assert.assertTrue(checkAliases.contains(aOp.getAlias()));
                            hasSent.set(true);
                        }
                    } else {
                        Assert.assertTrue(producerRecord.value().contains(indexName1) || producerRecord.value().contains(indexName2));
                        indexSent.set(true);
                    }
                    //inspired by MockProducer from KafkaInternals
                    TopicPartition topicPartition = new TopicPartition(producerRecord.topic(), 0);
                    ProduceRequestResult result = new ProduceRequestResult(topicPartition);
                    result.set(offset.getAndIncrement(), 1, null);
                    FutureRecordMetadata future = new FutureRecordMetadata(result, 0L, -1L, 0L, 0, 0);
                    result.done();
                    return future;
                }
        );


        //Create Templates
        String source1 = buildTemplateBody(Arrays.asList(username + "-i-*"), Arrays.asList(aliasName1), Settings.EMPTY);
        PutTemplate putTemplate1 = new PutTemplate.Builder(username + "-template1", source1).build();

        Tuple<JestResult, HttpResponse> result = client.executeE(putTemplate1);

        Assert.assertTrue(result.v1().isSucceeded());
        Assert.assertTrue(result.v1().getJsonString().contains("acknowledged"));

        checkAliases.add(aliasName1);
        //Create Indices (assert aliases are properly created too)
        CreateIndex createIndex = new CreateIndex.Builder(indexName1).settings(Map.of("index.number_of_shards", 3, "index.number_of_replicas", 1)).build();
        result = client.executeE(createIndex);
        Assert.assertTrue(result.v1().isSucceeded());

        GetAliases getAliases1 = new GetAliases.Builder().addAlias(aliasName1).build();

        result = client.executeE(getAliases1);
        result.v1().isSucceeded();

        Assert.assertTrue(indexSent.get());
        Assert.assertTrue(hasSent.get());

        //reset everything
        hasSent.set(false);
        indexSent.set(false);


        CreateIndex createIndex2 = new CreateIndex.Builder(indexName2).settings(Map.of("index.number_of_shards", 3, "index.number_of_replicas", 1)).build();
        result = client.executeE(createIndex2);

        Assert.assertTrue(result.v1().isSucceeded());
        Assert.assertTrue(indexSent.get());
        Assert.assertTrue(hasSent.get());

    }

    private String buildTemplateBody(final List<String> indexPatterns, final List<String> aliasesName, final Settings settings) {
        String body = "{\n" +
                "    \"index_patterns\" : [" + indexPatterns.stream().map(s -> "\"" + s + "\"").collect(Collectors.joining(",")) + "],\n" +
                "    \"settings\" : \n" +
                settings.toString() +
                "    ,\n" +
                "    \"aliases\" : {\n" +
                aliasesName.stream().map(s-> "\"" + s + "\" : {}").collect(Collectors.joining(",")) +
                "    }\n" +
                "}";

        return body;
    }


    private void configureEngineDatabase(MongoDatabase engineTestDatabase, List<EngineUser> engineUsers) {

        MongoCollection<Document> configCollection = engineTestDatabase.getCollection("config");

        Document configuration = new Document();
        configuration.put("name", "configuration");
        configuration.put("_list", new ArrayList<>());
        Document dict = new Document();
        dict.put("KSER_TOPIC_PREFIX", "logs");
        Document kserConfig = new Document();
        kserConfig.put("BOOTSTRAP_SERVERS", "kafka.p1.prod.us");
        kserConfig.put("SASL_PLAIN_USERNAME", "goten");
        kserConfig.put("SASL_PLAIN_PASSWORD", "kamehameha");
        kserConfig.put("SASL_MECHANISM", "PLAIN");
        kserConfig.put("SECURITY_PROTOCOL", "SASL_SSL");
        dict.put("KSER_PRODUCER_CONFIG", kserConfig);
        configuration.put("_dict", dict);

        configCollection.insertOne(configuration);

        MongoCollection<Document> usersCollection = engineTestDatabase.getCollection("users");

        for (EngineUser user : engineUsers) {
            Document userDoc = new Document();
            userDoc.put("username", user.getUsername());
            userDoc.put("trusted", user.isTrusted());
            userDoc.put("region", user.getRegion().value);
            usersCollection.insertOne(userDoc);
        }

    }
}
