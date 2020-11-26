package com.petalmd.armor;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.goterl.lazycode.lazysodium.LazySodiumJava;
import com.goterl.lazycode.lazysodium.SodiumJava;
import com.goterl.lazycode.lazysodium.utils.Key;
import com.mongodb.MongoClient;
import com.mongodb.ServerAddress;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.petalmd.armor.filter.lifecycle.AliasOperation;
import com.petalmd.armor.filter.lifecycle.EngineUser;
import com.petalmd.armor.filter.lifecycle.Region;
import com.petalmd.armor.filter.lifecycle.kser.KSerMessage;
import com.petalmd.armor.filter.lifecycle.kser.KSerSecuredMessage;
import com.petalmd.armor.service.KafkaService;
import com.petalmd.armor.service.MongoDBService;
import com.petalmd.armor.util.ConfigConstants;
import de.bwaldvogel.mongo.MongoServer;
import de.bwaldvogel.mongo.backend.memory.MemoryBackend;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.clients.producer.internals.FutureRecordMetadata;
import org.apache.kafka.clients.producer.internals.ProduceRequestResult;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.utils.Time;
import org.bson.Document;
import org.elasticsearch.ElasticsearchStatusException;
import org.elasticsearch.action.admin.indices.alias.get.GetAliasesRequest;
import org.elasticsearch.action.support.master.AcknowledgedResponse;
import org.elasticsearch.client.GetAliasesResponse;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.client.indices.*;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.mock.orig.Mockito;
import org.elasticsearch.rest.RestStatus;
import org.junit.Assert;
import org.junit.Test;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Created by jehuty0shift on 21/02/2020.
 */

@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class IndexTemplateFilterTest extends AbstractArmorTest {

    @Test
    public void templateCreationOnLDPIndex() throws Exception {

        username = "logs-xv-12345";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final String LDPIndexName = "ldp";

        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "lifecycle_index", "lifecycle_alias", "forbidden")
                .putList("armor.actionrequestfilter.lifecycle_index.allowed_actions", "indices:admin/create", "indices:admin/delete")
                .putList("armor.actionrequestfilter.lifecycle_alias.allowed_actions", "indices:data/read*")
                .putList("armor.actionrequestfilter.forbidden.allowed_actions", "indices:admin/template/put", "indices:admin/template/get", "indices:admin/template/delete", "indices:admin/aliases", "indices:data/read/scroll", "indices:data/read/scroll/clear")
                .put(ConfigConstants.ARMOR_INDEX_TEMPLATE_FILTER_ENABLED, true)
                .put(ConfigConstants.ARMOR_LDP_INDEX, LDPIndexName)
                .put(authSettings).build();

        startES(settings);
        setupTestData("ac_rules_27.json");

        RestHighLevelClient client = getRestClient(false, username, password);

        AcknowledgedResponse putResp = client.indices().putTemplate(new PutIndexTemplateRequest("ldp-template")
                        .patterns(Arrays.asList("ldp"))
                , RequestOptions.DEFAULT);

        Assert.assertTrue(putResp.isAcknowledged());
    }


    @Test
    public void templateCreationWithoutIndexLifeCycle() throws Exception {

        username = "logs-xv-12345";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");


        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "lifecycle_index", "lifecycle_alias", "forbidden")
                .putList("armor.actionrequestfilter.lifecycle_index.allowed_actions", "indices:admin/create", "indices:admin/delete")
                .putList("armor.actionrequestfilter.lifecycle_alias.allowed_actions", "indices:data/read*")
                .putList("armor.actionrequestfilter.forbidden.allowed_actions", "indices:admin/template/put", "indices:admin/template/get", "indices:admin/template/delete", "indices:admin/aliases", "indices:data/read/scroll", "indices:data/read/scroll/clear")
                .put(ConfigConstants.ARMOR_INDEX_TEMPLATE_FILTER_ENABLED, true)
                .put(authSettings).build();

        startES(settings);
        setupTestData("ac_rules_27.json");

        RestHighLevelClient client = getRestClient(false, username, password);

        AcknowledgedResponse putTempResp1 = client.indices().putTemplate(new PutIndexTemplateRequest("template1")
                        .patterns(Arrays.asList(username + "-i-*"))
                , RequestOptions.DEFAULT);

        Assert.assertTrue(putTempResp1.isAcknowledged());

        ElasticsearchStatusException putTempFail1 = expectThrows(ElasticsearchStatusException.class,
                () -> client.indices().putTemplate(new PutIndexTemplateRequest("template2")
                                .patterns(Arrays.asList(username + "-toto"))
                        , RequestOptions.DEFAULT));

        Assert.assertTrue(putTempFail1.status().equals(RestStatus.FORBIDDEN));
        Assert.assertTrue(putTempFail1.getDetailedMessage().contains(username + "-i"));

        AcknowledgedResponse putTempResp3 = client.indices().putTemplate(new PutIndexTemplateRequest("template3")
                        .patterns(Arrays.asList(username + "-i-*"))
                        .aliases("{" + "\"" + username + "-a-alias1\"" + ":{} }"),
                RequestOptions.DEFAULT);

        Assert.assertTrue(putTempResp3.isAcknowledged());

        ElasticsearchStatusException putTempFail2 = expectThrows(ElasticsearchStatusException.class,
                () -> client.indices().putTemplate(new PutIndexTemplateRequest("template2")
                                .patterns(Arrays.asList(username + "-i-*"))
                                .aliases("{ \"alias\" : {} }")
                        , RequestOptions.DEFAULT));

        Assert.assertTrue(putTempFail2.status().equals(RestStatus.FORBIDDEN));
        Assert.assertTrue(putTempFail2.getDetailedMessage().contains(username + "-a"));


        //GET Templates test

        ElasticsearchStatusException getFail1 = expectThrows(ElasticsearchStatusException.class,
                () -> client.indices().getIndexTemplate(new GetIndexTemplatesRequest("unknown_template"), RequestOptions.DEFAULT));

        Assert.assertTrue(getFail1.status().equals(RestStatus.NOT_FOUND));

        GetIndexTemplatesResponse getTemp1 = client.indices().getIndexTemplate(new GetIndexTemplatesRequest("template1"), RequestOptions.DEFAULT);

        Assert.assertTrue(getTemp1.getIndexTemplates().stream().allMatch(t -> t.name().contains("template1")));

        GetIndexTemplatesResponse getTemp2 = client.indices().getIndexTemplate(new GetIndexTemplatesRequest(), RequestOptions.DEFAULT);

        Assert.assertTrue(getTemp2.getIndexTemplates().stream().allMatch(t -> t.name().contains("template1") || t.name().contains("template3")));

    }


    @Test
    public void createTemplatedIndiceWithAliasLifeCycleFilter() throws Exception {
        username = "logs-xv-12345";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final String indexName1 = username + "-i-test-1";
        final String indexName2 = username + "-i-test-2";
        final String indexName3 = username + "-i-test-3";

        final String aliasName1 = username + "-a-alias";

        final String engineDatabaseName = "engine";

        final SodiumJava sodium = new SodiumJava();
        LazySodiumJava lazySodium = new LazySodiumJava(sodium);
        final String privateKey = Base64.getEncoder().encodeToString(lazySodium.cryptoSecretBoxKeygen().getAsBytes());

        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "lifecycle_index", "lifecycle_alias", "forbidden")
                .putList("armor.actionrequestfilter.lifecycle_index.allowed_actions",
                        "indices:admin/auto_create",
                        "indices:admin/create",
                        "indices:admin/delete")
                .putList("armor.actionrequestfilter.lifecycle_alias.allowed_actions", "indices:data/read*")
                .putList("armor.actionrequestfilter.forbidden.allowed_actions",
                        "indices:admin/template/put",
                        "indices:admin/template/get",
                        "indices:admin/template/delete",
                        "indices:admin/aliases",
                        "indices:admin/aliases/get",
                        "indices:data/read/scroll",
                        "indices:data/read/scroll/clear")
                .putList(ConfigConstants.ARMOR_INDEX_TEMPLATE_FILTER_ALLOWED_SETTINGS, "index.number_of_shards", "index.number_of_replicas")
                .put(ConfigConstants.ARMOR_INDEX_TEMPLATE_FILTER_ENABLED, true)
                .put(ConfigConstants.ARMOR_INDEX_LIFECYCLE_ENABLED, true)
                .put(ConfigConstants.ARMOR_ALIAS_LIFECYCLE_ENABLED, true)
                .put(ConfigConstants.ARMOR_MONGODB_URI, "test")
                .put(ConfigConstants.ARMOR_MONGODB_ENGINE_DATABASE, engineDatabaseName)
                .put(ConfigConstants.ARMOR_KAFKA_ENGINE_SERVICE_ENABLED, true)
                .put(ConfigConstants.ARMOR_KAFKA_ENGINE_SERVICE_PRIVATE_KEY, privateKey)
                .put(ConfigConstants.ARMOR_KAFKA_ENGINE_SERVICE_CLIENT_ID, "dummy")
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

        KafkaProducer mockProducer = org.elasticsearch.mock.orig.Mockito.mock(KafkaProducer.class);
        KafkaService.setKafkaProducer(mockProducer);

        startES(settings);
        setupTestData("ac_rules_27.json");

        RestHighLevelClient client = getRestClient(false, username, password);

        final AtomicReference<Boolean> aliasSent = new AtomicReference<>();
        final AtomicReference<Boolean> indexSent = new AtomicReference<>();
        final List<String> checkAliases = new ArrayList<>();
        final List<AliasOperation> producedObject = new ArrayList<>();
        final AtomicInteger offset = new AtomicInteger(0);
        aliasSent.set(false);
        indexSent.set(false);


        org.elasticsearch.mock.orig.Mockito.when(mockProducer.send(Mockito.any())).then(invocationOnMock -> {
                    ProducerRecord<String, String> producerRecord = (ProducerRecord<String, String>) invocationOnMock.getArguments()[0];
                    KSerSecuredMessage kSerSecMess = objectMapper.readValue(producerRecord.value(), KSerSecuredMessage.class);
                    String nonceStr = kSerSecMess.getNonce();
                    byte[] nonceByte = Base64.getDecoder().decode(nonceStr);
                    LazySodiumJava lsj = new LazySodiumJava(sodium);
                    String kserOpString = lsj.cryptoSecretBoxOpenEasy(lsj.toHexStr(Base64.getDecoder().decode(kSerSecMess.getData())), nonceByte, Key.fromBase64String(privateKey));
                    KSerMessage kSerMessage = objectMapper.readValue(kserOpString, KSerMessage.class);
                    if (kSerMessage.getEntrypoint().toLowerCase().contains("alias")) {
                        AliasOperation aOp = AliasOperation.fromKSerMessage(kSerMessage);
                        producedObject.add(aOp);
                        if (!checkAliases.isEmpty()) {
                            Assert.assertEquals(username, aOp.getUsername());
                            Assert.assertTrue(checkAliases.contains(aOp.getAlias()));
                            if (aOp.getIndices().contains(indexName3) || aOp.getIndices().contains(indexName2)) {
                                Assert.assertTrue(aOp.getType().equals(AliasOperation.Type.UPDATE));
                            }
                            aliasSent.set(true);
                        }
                    } else {
                        Assert.assertTrue(Stream.of(indexName1, indexName2, indexName3).filter(s -> kserOpString.contains(s)).findAny().isPresent());
                        indexSent.set(true);
                    }
                    //inspired by MockProducer from KafkaInternals
                    TopicPartition topicPartition = new TopicPartition(producerRecord.topic(), 0);
                    ProduceRequestResult result = new ProduceRequestResult(topicPartition);
                    result.set(offset.getAndIncrement(), 1, null);
                    FutureRecordMetadata future = new FutureRecordMetadata(result, 0L, -1L, 0L, 0, 0, Time.SYSTEM);
                    result.done();
                    return future;
                }
        );

        //Create Templates
        AcknowledgedResponse putTempResp1 = client.indices().putTemplate(new PutIndexTemplateRequest("template1")
                        .patterns(Arrays.asList(username + "-i-*"))
                        .aliases("{" + "\"" + aliasName1 + "\"" + ":{} }"),
                RequestOptions.DEFAULT);

        Assert.assertTrue(putTempResp1.isAcknowledged());

        checkAliases.add(aliasName1);
        //Create Indices (assert aliases are properly created too)

        CreateIndexResponse cIResp = client.indices().create(new CreateIndexRequest(indexName1)
                        .settings(Settings.builder()
                                .put("index.number_of_shards", 3)
                                .put("index.number_of_replicas", 1)
                                .build()),
                RequestOptions.DEFAULT);

        Assert.assertTrue(cIResp.isAcknowledged());

        GetAliasesResponse gaResp = client.indices().getAlias(new GetAliasesRequest(aliasName1),RequestOptions.DEFAULT);

        Assert.assertTrue(gaResp.getAliases().get(indexName1).stream().allMatch(a -> a.alias().equals(aliasName1)));
        Assert.assertTrue(indexSent.get());
        Assert.assertTrue(aliasSent.get());

        //reset everything
        aliasSent.set(false);
        indexSent.set(false);

        CreateIndexResponse cIResp2 = client.indices().create(new CreateIndexRequest(indexName2)
                        .settings(Settings.builder()
                                .put("index.number_of_shards", 3)
                                .put("index.number_of_replicas", 1)
                                .build()),
                RequestOptions.DEFAULT);

        Assert.assertTrue(cIResp2.isAcknowledged());

        //reset everything
        aliasSent.set(false);
        indexSent.set(false);


        CreateIndexResponse cIResp3 = client.indices().create(new CreateIndexRequest(indexName3)
                        .settings(Settings.builder()
                                .put("index.number_of_shards", 3)
                                .put("index.number_of_replicas", 1)
                                .build()),
                RequestOptions.DEFAULT);

        Assert.assertTrue(cIResp3.isAcknowledged());


        Assert.assertTrue(indexSent.get());
        Assert.assertTrue(aliasSent.get());


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

        MongoCollection<Document> usersCollection = engineTestDatabase.getCollection("user");

        for (EngineUser user : engineUsers) {
            Document userDoc = new Document();
            userDoc.put("username", user.getUsername());
            userDoc.put("trusted", user.isTrusted());
            userDoc.put("region", user.getRegion().value);
            usersCollection.insertOne(userDoc);
        }

    }
}
