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
import com.petalmd.armor.service.KafkaEngineService;
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
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.elasticsearch.action.support.master.AcknowledgedResponse;
import org.elasticsearch.client.*;
import org.elasticsearch.client.indices.CreateIndexRequest;
import org.elasticsearch.client.indices.CreateIndexResponse;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestStatus;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Created by jehuty0shift on 10/02/2020.
 */

@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class AliasLifeCycleFilterTest extends AbstractArmorTest {


    @Test
    public void aliasCreationDeletion() throws Exception {


        username = "logs-xv-12345";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final String indexName1 = username + "-i-test-1";
        final String indexName2 = username + "-i-test-2";

        final String aliasName1 = username + "-a-alias";

        final String engineDatabaseName = "engine";

        final SodiumJava sodium = new SodiumJava();
        LazySodiumJava lazySodium = new LazySodiumJava(sodium);
        final String privateKey = Base64.getEncoder().encodeToString(lazySodium.cryptoSecretBoxKeygen().getAsBytes());

        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "lifecycle_index", "lifecycle_alias", "forbidden")
                .putList("armor.actionrequestfilter.lifecycle_index.allowed_actions", "indices:admin/create", "indices:admin/delete")
                .putList("armor.actionrequestfilter.lifecycle_alias.allowed_actions", "indices:data/read*")
                .putList("armor.actionrequestfilter.forbidden.allowed_actions", "indices:admin/aliases", "indices:data/read/scroll", "indices:data/read/scroll/clear")
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

        configureEngineDatabase(engineTestDatabase, List.of(currentUser));

        ObjectMapper objectMapper = new ObjectMapper();

        KafkaProducer mockProducer = Mockito.mock(KafkaProducer.class);
        KafkaEngineService.setKafkaProducer(mockProducer);

        startES(settings);
        setupTestData("ac_rules_26.json");

        RestHighLevelClient client = getRestClient(false, username, password);

        final AtomicReference<Boolean> hasSent = new AtomicReference<>();
        final AtomicReference<Boolean> indexSent = new AtomicReference<>();
        final List<String> checkAliases = new ArrayList<>();
        final List<AliasOperation> producedObject = new ArrayList<>();
        final AtomicInteger offset = new AtomicInteger(0);
        hasSent.set(false);
        indexSent.set(false);


        Mockito.when(mockProducer.send(Mockito.any())).then(invocationOnMock -> {
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
                            hasSent.set(true);
                        }
                    } else {
                        Assert.assertTrue(kserOpString.contains(indexName1) || kserOpString.contains(indexName2));
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

        CreateIndexResponse ciResp = client.indices().create(new CreateIndexRequest(indexName1)
                .settings(Settings.builder()
                        .put("index.number_of_shards", 3)
                        .put("index.number_of_replicas", 1)
                        .build()), RequestOptions.DEFAULT);

        Assert.assertTrue(ciResp.isAcknowledged());

        CreateIndexResponse ciResp2 = client.indices().create(new CreateIndexRequest(indexName2)
                .settings(Settings.builder()
                        .put("index.number_of_shards", 3)
                        .put("index.number_of_replicas", 1)
                        .build()), RequestOptions.DEFAULT);

        Assert.assertTrue(ciResp2.isAcknowledged());

        checkAliases.clear();
        checkAliases.add(aliasName1);

        AcknowledgedResponse aliasResp1 = client.indices().updateAliases(new IndicesAliasesRequest()
                .addAliasAction(new IndicesAliasesRequest.AliasActions(IndicesAliasesRequest.AliasActions.Type.ADD)
                        .indices(indexName1, indexName2)
                        .alias(aliasName1)), RequestOptions.DEFAULT);

        Assert.assertTrue(aliasResp1.isAcknowledged());
        Assert.assertTrue(hasSent.get());

        //reset hasSent
        hasSent.set(false);
        producedObject.clear();

        //remove and reset alias only on indexName2
        AcknowledgedResponse aliasResp2 = client.indices().updateAliases(new IndicesAliasesRequest()
                .addAliasAction(new IndicesAliasesRequest.AliasActions(IndicesAliasesRequest.AliasActions.Type.REMOVE)
                        .indices(username + "-i-*")
                        .alias(aliasName1))
                .addAliasAction(new IndicesAliasesRequest.AliasActions(IndicesAliasesRequest.AliasActions.Type.ADD)
                        .indices(indexName2)
                        .alias(aliasName1)), RequestOptions.DEFAULT);

        Assert.assertTrue(aliasResp2.isAcknowledged());
        Assert.assertTrue(hasSent.get());

        //reset hasSent
        hasSent.set(false);
        producedObject.clear();

        //remove all aliases
        AcknowledgedResponse aliasResp3 = client.indices().updateAliases(new IndicesAliasesRequest()
                .addAliasAction(new IndicesAliasesRequest.AliasActions(IndicesAliasesRequest.AliasActions.Type.REMOVE)
                        .indices(username + "-i-*")
                        .alias(aliasName1)), RequestOptions.DEFAULT);

        Assert.assertTrue(aliasResp3.isAcknowledged());
        Assert.assertTrue(hasSent.get());

        AliasOperation producedAliasOp1 = producedObject.get(0);
        Assert.assertTrue(producedAliasOp1.getType().equals(AliasOperation.Type.REMOVE));

        producedObject.clear();
        hasSent.set(false);

        //Prevent Alias to be created
        ElasticsearchStatusException aliasFail1 = expectThrows(ElasticsearchStatusException.class, () ->
                client.indices().updateAliases(new IndicesAliasesRequest()
                        .addAliasAction(new IndicesAliasesRequest.AliasActions(IndicesAliasesRequest.AliasActions.Type.ADD)
                                .indices("dev")
                                .alias(aliasName1)), RequestOptions.DEFAULT));


        //the alias should not be created
        Assert.assertTrue(aliasFail1.status().equals(RestStatus.FORBIDDEN));
        Assert.assertTrue(aliasFail1.getDetailedMessage().contains(username + "-i-"));


        ElasticsearchStatusException aliasFail2 = expectThrows(ElasticsearchStatusException.class, () ->
                client.indices().updateAliases(new IndicesAliasesRequest()
                        .addAliasAction(new IndicesAliasesRequest.AliasActions(IndicesAliasesRequest.AliasActions.Type.ADD)
                                .indices(indexName1)
                                .alias("index_deflector")), RequestOptions.DEFAULT));

        Assert.assertTrue(aliasFail2.status().equals(RestStatus.FORBIDDEN));
        Assert.assertTrue(aliasFail2.getDetailedMessage().contains(username + "-a-"));


        //Add alias on all

        AcknowledgedResponse aliasResp4 = client.indices().updateAliases(new IndicesAliasesRequest()
                .addAliasAction(new IndicesAliasesRequest.AliasActions(IndicesAliasesRequest.AliasActions.Type.ADD)
                        .indices(username + "-i-*")
                        .alias(aliasName1)), RequestOptions.DEFAULT);

        Assert.assertTrue(aliasResp4.isAcknowledged());
        Assert.assertTrue(hasSent.get());
        AliasOperation producedAliasOp2 = producedObject.get(0);
        Assert.assertEquals(aliasName1, producedAliasOp2.getAlias());
        Assert.assertEquals(AliasOperation.Type.ADD, producedAliasOp2.getType());
        Assert.assertEquals(2, producedAliasOp2.getIndices().size());


        producedObject.clear();
        hasSent.set(false);

        //Create a second alias
        String aliasName2 = username + "-a-alias2";
        checkAliases.clear();
        checkAliases.add(aliasName2);


        Response aliasResp5 = client.getLowLevelClient().performRequest(new Request("PUT", username + "-i-*/_alias/" + aliasName2));

        Assert.assertEquals(200, aliasResp5.getStatusLine().getStatusCode());
        Assert.assertTrue(hasSent.get());
        AliasOperation producedAliasOp3 = producedObject.get(0);
        Assert.assertEquals(aliasName2, producedAliasOp3.getAlias());
        Assert.assertEquals(AliasOperation.Type.ADD, producedAliasOp3.getType());
        Assert.assertEquals(2, producedAliasOp3.getIndices().size());

        hasSent.set(false);
        producedObject.clear();

        //Fail on a forbidden alias name
        ResponseException aliasFail6 = expectThrows(ResponseException.class,
                () -> client.getLowLevelClient().performRequest(new Request("PUT", username + "-i-*/_alias/" + "logs_deflector")));

        Assert.assertEquals(403, aliasFail6.getResponse().getStatusLine().getStatusCode());
        Assert.assertTrue(new String(aliasFail6.getResponse().getEntity().getContent().readAllBytes()).contains(username + "-a-"));


        //Delete all aliases at once
        checkAliases.clear();
        checkAliases.addAll(Arrays.asList(aliasName1, aliasName2));

        Response aliasResp7 = client.getLowLevelClient().performRequest(new Request("DELETE", username + "-i-*/_alias/" + "_all"));

        Assert.assertEquals(200, aliasResp7.getStatusLine().getStatusCode());
        Assert.assertTrue(hasSent.get());
        for (AliasOperation pAOp : producedObject) {
            Assert.assertTrue(checkAliases.contains(producedAliasOp3.getAlias()));
            Assert.assertEquals(AliasOperation.Type.REMOVE, pAOp.getType());
        }

        hasSent.set(false);
        producedObject.clear();


        //fail on REMOVE INDEX
        checkAliases.clear();
        checkAliases.add(aliasName1);

        ElasticsearchStatusException aliasFail8 = expectThrows(ElasticsearchStatusException.class, () ->
                client.indices().updateAliases(new IndicesAliasesRequest()
                        .addAliasAction(new IndicesAliasesRequest.AliasActions(IndicesAliasesRequest.AliasActions.Type.ADD)
                                .indices(indexName1)
                                .alias("index_deflector"))
                        .addAliasAction(new IndicesAliasesRequest.AliasActions(IndicesAliasesRequest.AliasActions.Type.REMOVE_INDEX)
                                .indices("dev")), RequestOptions.DEFAULT));


        Assert.assertTrue(aliasFail8.status().equals(RestStatus.FORBIDDEN));

        //Remove index on REMOVE INDEX
        checkAliases.clear();
        checkAliases.add(aliasName1);

        AcknowledgedResponse aliasResp8 = client.indices().updateAliases(new IndicesAliasesRequest()
                .addAliasAction(new IndicesAliasesRequest.AliasActions(IndicesAliasesRequest.AliasActions.Type.ADD)
                        .indices(indexName1)
                        .alias(aliasName1))
                .addAliasAction(new IndicesAliasesRequest.AliasActions(IndicesAliasesRequest.AliasActions.Type.REMOVE_INDEX)
                        .indices(indexName2)), RequestOptions.DEFAULT);

        Assert.assertTrue(aliasResp8.isAcknowledged());
        Assert.assertTrue(hasSent.get());
        Assert.assertTrue(indexSent.get());
        Assert.assertEquals(AliasOperation.Type.ADD, producedObject.get(0).getType());
        Assert.assertEquals(aliasName1, producedObject.get(0).getAlias());
        Assert.assertEquals(1, producedObject.get(0).getIndices().size());
        Assert.assertEquals(indexName1, producedObject.get(0).getIndices().get(0));


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

    @Test
    public void aliasCreationCheckLightly() throws Exception {


        username = "logs-xv-12345";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final String indexName1 = username + "-i-test_1";
        final String indexName2 = username + "-i-test_2";

        final String aliasName1 = username + "-i-test";

        final String engineDatabaseName = "engine";

        final SodiumJava sodium = new SodiumJava();
        LazySodiumJava lazySodium = new LazySodiumJava(sodium);
        final String privateKey = Base64.getEncoder().encodeToString(lazySodium.cryptoSecretBoxKeygen().getAsBytes());

        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "lifecycle_index", "lifecycle_alias", "forbidden")
                .putList("armor.actionrequestfilter.lifecycle_index.allowed_actions", "indices:admin/create", "indices:admin/delete")
                .putList("armor.actionrequestfilter.lifecycle_alias.allowed_actions", "indices:data/read*")
                .putList("armor.actionrequestfilter.forbidden.allowed_actions", "indices:admin/aliases", "indices:data/read/scroll", "indices:data/read/scroll/clear")
                .put(ConfigConstants.ARMOR_INDEX_LIFECYCLE_ENABLED, true)
                .put(ConfigConstants.ARMOR_ALIAS_LIFECYCLE_ENABLED, true)
                .put(ConfigConstants.ARMOR_HTTP_ADDITIONAL_RIGHTS_HEADER+"kibana","myawesomekibanaheader")
                .putList(ConfigConstants.ARMOR_ALIAS_LIFECYCLE_ADDITIONAL_RIGHTS_LIGHT_CHECK, "kibana")
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

        configureEngineDatabase(engineTestDatabase, List.of(currentUser));

        ObjectMapper objectMapper = new ObjectMapper();

        KafkaProducer mockProducer = Mockito.mock(KafkaProducer.class);
        KafkaEngineService.setKafkaProducer(mockProducer);

        startES(settings);
        setupTestData("ac_rules_26.json");

        RestHighLevelClient client = getRestClient(false, username, password);

        final AtomicReference<Boolean> hasSent = new AtomicReference<>();
        final AtomicReference<Boolean> indexSent = new AtomicReference<>();
        final List<String> checkAliases = new ArrayList<>();
        final List<AliasOperation> producedObject = new ArrayList<>();
        final AtomicInteger offset = new AtomicInteger(0);
        hasSent.set(false);
        indexSent.set(false);


        Mockito.when(mockProducer.send(Mockito.any())).then(invocationOnMock -> {
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
                            hasSent.set(true);
                        }
                    } else {
                        Assert.assertTrue(kserOpString.contains(indexName1) || kserOpString.contains(indexName2));
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

        CreateIndexResponse ciResp = client.indices().create(new CreateIndexRequest(indexName1)
                .settings(Settings.builder()
                        .put("index.number_of_shards", 3)
                        .put("index.number_of_replicas", 1)
                        .build()), RequestOptions.DEFAULT);

        Assert.assertTrue(ciResp.isAcknowledged());

        CreateIndexResponse ciResp2 = client.indices().create(new CreateIndexRequest(indexName2)
                .settings(Settings.builder()
                        .put("index.number_of_shards", 3)
                        .put("index.number_of_replicas", 1)
                        .build()), RequestOptions.DEFAULT);

        Assert.assertTrue(ciResp2.isAcknowledged());

        checkAliases.clear();
        checkAliases.add(aliasName1);

        AcknowledgedResponse aliasResp1 = client.indices().updateAliases(new IndicesAliasesRequest()
                .addAliasAction(new IndicesAliasesRequest.AliasActions(IndicesAliasesRequest.AliasActions.Type.ADD)
                        .indices(indexName1, indexName2)
                        .alias(aliasName1)), RequestOptions.DEFAULT.toBuilder().addHeader("kibana","myawesomekibanaheader").build());

        Assert.assertTrue(aliasResp1.isAcknowledged());
        Assert.assertTrue(hasSent.get());

        //reset hasSent
        hasSent.set(false);
        producedObject.clear();
    }
}
