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
import com.petalmd.armor.tests.IndexAliasAction;
import com.petalmd.armor.tests.RemoveIndexAliasMapping;
import com.petalmd.armor.util.ConfigConstants;
import de.bwaldvogel.mongo.MongoServer;
import de.bwaldvogel.mongo.backend.memory.MemoryBackend;
import io.searchbox.client.JestResult;
import io.searchbox.indices.CreateIndex;
import io.searchbox.indices.aliases.AddAliasMapping;
import io.searchbox.indices.aliases.ModifyAliases;
import io.searchbox.indices.aliases.RemoveAliasMapping;
import kong.unirest.Unirest;
import org.apache.http.HttpResponse;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.clients.producer.internals.FutureRecordMetadata;
import org.apache.kafka.clients.producer.internals.ProduceRequestResult;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.utils.Time;
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

/**
 * Created by jehuty0shift on 10/02/2020.
 */

@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
@PrepareForTest({Unirest.class})
public class AliasLifeCycleFilterTest extends AbstractScenarioTest {


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
        KafkaService.setKafkaProducer(mockProducer);

        System.setProperty("es.set.netty.runtime.available.processors", "false");

        startES(settings);
        setupTestData("ac_rules_26.json");

        HeaderAwareJestHttpClient client = getJestClient(getServerUri(false), username, password);

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

        CreateIndex createIndex = new CreateIndex.Builder(indexName1).settings(Map.of("index.number_of_shards", 3, "index.number_of_replicas", 1)).build();
        Tuple<JestResult, HttpResponse> result = client.executeE(createIndex);

        Assert.assertTrue(result.v1().isSucceeded());

        CreateIndex createIndex2 = new CreateIndex.Builder(indexName2).settings(Map.of("index.number_of_shards", 3, "index.number_of_replicas", 1)).build();
        result = client.executeE(createIndex2);

        Assert.assertTrue(result.v1().isSucceeded());

        AddAliasMapping addAliasMapping1 = new AddAliasMapping.Builder(Arrays.asList(indexName1, indexName2), aliasName1).build();

        checkAliases.clear();
        checkAliases.add(aliasName1);

        ModifyAliases modifyAliases1 = new ModifyAliases.Builder(Arrays.asList(addAliasMapping1)).build();
        result = client.executeE(modifyAliases1);

        Assert.assertTrue(result.v1().isSucceeded());
        Assert.assertTrue(hasSent.get());

        //reset hasSent
        hasSent.set(false);
        producedObject.clear();

        //remove and reset alias only on indexName2
        AddAliasMapping addAliasMapping2 = new AddAliasMapping.Builder(Arrays.asList(indexName2), aliasName1).build();
        RemoveAliasMapping removeAliasMapping1 = new RemoveAliasMapping.Builder(Arrays.asList(username + "-i-*"), aliasName1).build();

        ModifyAliases modifyAliases2 = new ModifyAliases.Builder(Arrays.asList(removeAliasMapping1, addAliasMapping2)).build();
        result = client.executeE(modifyAliases2);

        Assert.assertTrue(result.v1().isSucceeded());
        Assert.assertTrue(hasSent.get());

        //reset hasSent
        hasSent.set(false);
        producedObject.clear();


        RemoveAliasMapping removeAliasMapping2 = new RemoveAliasMapping.Builder(Arrays.asList(username + "-i-*"), aliasName1).build();

        ModifyAliases modifyAliases3 = new ModifyAliases.Builder(Arrays.asList(removeAliasMapping2)).build();
        result = client.executeE(modifyAliases3);

        Assert.assertTrue(result.v1().isSucceeded());
        Assert.assertTrue(hasSent.get());

        AliasOperation producedAliasOp1 = producedObject.get(0);
        Assert.assertTrue(producedAliasOp1.getType().equals(AliasOperation.Type.REMOVE));

        producedObject.clear();
        hasSent.set(false);

        AddAliasMapping addAliasMapping4 = new AddAliasMapping.Builder("dev", aliasName1).build();
        ModifyAliases modifyAliases4 = new ModifyAliases.Builder(Arrays.asList(addAliasMapping4)).build();

        result = client.executeE(modifyAliases4);

        Assert.assertFalse(result.v1().isSucceeded());
        //the alias should not be created
        Assert.assertEquals(403, result.v2().getStatusLine().getStatusCode());
        Assert.assertTrue(result.v1().getErrorMessage().contains(username + "-i-"));


        AddAliasMapping addAliasMapping5 = new AddAliasMapping.Builder(indexName1, "graylog2_deflector").build();
        ModifyAliases modifyAliases5 = new ModifyAliases.Builder(Arrays.asList(addAliasMapping5)).build();
        result = client.executeE(modifyAliases5);
        Assert.assertFalse(result.v1().isSucceeded());
        Assert.assertEquals(403, result.v2().getStatusLine().getStatusCode());
        Assert.assertTrue(result.v1().getErrorMessage().contains(username + "-a-"));

        IndexAliasAction indexAliasAction1 = new IndexAliasAction.Builder(aliasName1).addIndex(username + "-i-*").setRestMethod("PUT").build();
        result = client.executeE(indexAliasAction1);
        Assert.assertTrue(result.v1().isSucceeded());
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
        IndexAliasAction indexAliasAction2 = new IndexAliasAction.Builder(aliasName2).addIndex(username + "-i-*").setRestMethod("PUT").build();
        result = client.executeE(indexAliasAction2);
        Assert.assertTrue(result.v1().isSucceeded());
        Assert.assertTrue(hasSent.get());
        AliasOperation producedAliasOp3 = producedObject.get(0);
        Assert.assertEquals(aliasName2, producedAliasOp3.getAlias());
        Assert.assertEquals(AliasOperation.Type.ADD, producedAliasOp3.getType());
        Assert.assertEquals(2, producedAliasOp3.getIndices().size());

        hasSent.set(false);
        producedObject.clear();

        //Fail on a forbidden alias name
        IndexAliasAction indexAliasAction3 = new IndexAliasAction.Builder("logs_deflector").addIndex(username + "-i-*").setRestMethod("PUT").build();
        result = client.executeE(indexAliasAction3);
        Assert.assertTrue(!result.v1().isSucceeded());
        Assert.assertEquals(403, result.v2().getStatusLine().getStatusCode());
        Assert.assertTrue(result.v1().getErrorMessage().contains(username + "-a-"));


        //Delete all aliases at once
        checkAliases.clear();
        checkAliases.addAll(Arrays.asList(aliasName1, aliasName2));
        IndexAliasAction indexAliasAction4 = new IndexAliasAction.Builder("_all").addIndex(username + "-i-*").setRestMethod("DELETE").build();
        result = client.executeE(indexAliasAction4);
        Assert.assertTrue(result.v1().isSucceeded());
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
        RemoveIndexAliasMapping remIAM1 = new RemoveIndexAliasMapping.Builder("dev").build();
        AddAliasMapping addAliasMapping6 = new AddAliasMapping.Builder(indexName1, aliasName1).build();
        ModifyAliases modifyAliases6 = new ModifyAliases.Builder(Arrays.asList(addAliasMapping6, remIAM1)).build();
        result = client.executeE(modifyAliases6);
        Assert.assertFalse(result.v1().isSucceeded());
        Assert.assertEquals(403, result.v2().getStatusLine().getStatusCode());

        //Remove index on REMOVE INDEX
        checkAliases.clear();
        checkAliases.add(aliasName1);
        RemoveIndexAliasMapping remIAM2 = new RemoveIndexAliasMapping.Builder(indexName2).build();
        AddAliasMapping addAliasMapping7 = new AddAliasMapping.Builder(indexName1, aliasName1).build();
        ModifyAliases modifyAliases7 = new ModifyAliases.Builder(Arrays.asList(addAliasMapping7, remIAM2)).build();
        result = client.executeE(modifyAliases7);
        Assert.assertTrue(result.v1().isSucceeded());
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
                .put(ConfigConstants.ARMOR_MONGODB_URI, "test")
                .put(ConfigConstants.ARMOR_MONGODB_ENGINE_DATABASE, engineDatabaseName)
                .put(ConfigConstants.ARMOR_KAFKA_ENGINE_SERVICE_ENABLED, true)
                .put(ConfigConstants.ARMOR_KAFKA_ENGINE_SERVICE_PRIVATE_KEY, privateKey)
                .put(ConfigConstants.ARMOR_KAFKA_ENGINE_SERVICE_CLIENT_ID, "dummy")
                .put(ConfigConstants.ARMOR_HTTP_ADDITIONAL_RIGHTS_HEADER+ "kibana","awesomekibanaheader")
                .put(ConfigConstants.ARMOR_ALIAS_LIFECYCLE_ADDITIONAL_RIGHTS_LIGHT_CHECK, "kibana")
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
        KafkaService.setKafkaProducer(mockProducer);

        System.setProperty("es.set.netty.runtime.available.processors", "false");

        startES(settings);
        setupTestData("ac_rules_26.json");

        HeaderAwareJestHttpClient client = getJestClient(getServerUri(false), username, password);

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

        CreateIndex createIndex = new CreateIndex.Builder(indexName1).settings(Map.of("index.number_of_shards", 3, "index.number_of_replicas", 1)).build();
        Tuple<JestResult, HttpResponse> result = client.executeE(createIndex);

        Assert.assertTrue(result.v1().isSucceeded());

        CreateIndex createIndex2 = new CreateIndex.Builder(indexName2).settings(Map.of("index.number_of_shards", 3, "index.number_of_replicas", 1)).build();
        result = client.executeE(createIndex2);

        Assert.assertTrue(result.v1().isSucceeded());

        AddAliasMapping addAliasMapping1 = new AddAliasMapping.Builder(Arrays.asList(indexName1, indexName2), aliasName1).build();

        checkAliases.clear();
        checkAliases.add(aliasName1);

        ModifyAliases modifyAliases1 = new ModifyAliases.Builder(Arrays.asList(addAliasMapping1)).setHeader("kibana","awesomekibanaheader").build();
        result = client.executeE(modifyAliases1);

        Assert.assertTrue(result.v1().isSucceeded());
        Assert.assertTrue(hasSent.get());

        //reset hasSent
        hasSent.set(false);
        producedObject.clear();
    }
}
