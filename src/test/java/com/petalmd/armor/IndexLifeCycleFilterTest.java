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
import com.petalmd.armor.filter.lifecycle.*;
import com.petalmd.armor.filter.lifecycle.kser.KSerMessage;
import com.petalmd.armor.filter.lifecycle.kser.KSerSecuredMessage;
import com.petalmd.armor.service.KafkaEngineService;
import com.petalmd.armor.service.MongoDBService;
import com.petalmd.armor.util.ConfigConstants;
import de.bwaldvogel.mongo.MongoServer;
import de.bwaldvogel.mongo.backend.memory.MemoryBackend;
import io.searchbox.client.JestResult;
import io.searchbox.indices.CreateIndex;
import io.searchbox.indices.DeleteIndex;
import kong.unirest.Unirest;
import org.abstractj.kalium.crypto.SecretBox;
import org.apache.http.HttpResponse;
import org.apache.kafka.clients.producer.*;
import org.apache.kafka.clients.producer.internals.FutureRecordMetadata;
import org.apache.kafka.clients.producer.internals.ProduceRequestResult;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.serialization.StringSerializer;
import org.apache.kafka.common.utils.Time;
import org.bson.Document;
import org.bson.codecs.configuration.CodecRegistries;
import org.bson.codecs.configuration.CodecRegistry;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;
import org.powermock.core.classloader.annotations.PrepareForTest;

import java.net.InetSocketAddress;
import java.util.*;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Created by jehuty0shift on 24/01/2020.
 */

@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
@PrepareForTest({Unirest.class})
public class IndexLifeCycleFilterTest extends AbstractScenarioTest {

    @Test
    public void testKafkaConfigurationCodec() {

        MongoServer server = new MongoServer(new MemoryBackend());

        InetSocketAddress serverAddress = server.bind();

        MongoClient client = new MongoClient(new ServerAddress(serverAddress));

        MongoDatabase engineTestDatabase = client.getDatabase("engine");
        CodecRegistry cR = CodecRegistries.fromRegistries(CodecRegistries.fromProviders(new LifeCycleMongoCodecProvider()), MongoClient.getDefaultCodecRegistry());

        MongoCollection<Document> initialCollection = engineTestDatabase.getCollection("config");

        Document configuration = new Document();
        configuration.put("name", "configuration");
        configuration.put("_list", new ArrayList<>());
        Document dict = new Document();
        dict.put("INPUT_RSA_LENGTH", 2048);
        dict.put("INPUT_SIGN_PROTO", "sha1");
        dict.put("KIBANA_CPU", 0.1);
        dict.put("KIBANA_MEM", 320);
        dict.put("KSER_TOPIC_PREFIX", "prefix-42.ext");
        Document kserConfig = new Document();
        kserConfig.put("BOOTSTRAP_SERVERS", "kafka.p1.prod.us");
        kserConfig.put("SASL_PLAIN_USERNAME", "goten");
        kserConfig.put("SASL_PLAIN_PASSWORD", "kamehameha");
        kserConfig.put("SASL_MECHANISM", "PLAIN");
        kserConfig.put("SECURITY_PROTOCOL", "SASL_SSL");
        dict.put("KSER_PRODUCER_CONFIG", kserConfig);
        configuration.put("_dict", dict);

        initialCollection.insertOne(configuration);

        MongoCollection<KafkaConfig> configCollection = engineTestDatabase.getCollection("config").withCodecRegistry(cR).withDocumentClass(KafkaConfig.class);

        KafkaConfig kConfig = configCollection.find().first();

        Assert.assertEquals("kafka.p1.prod.us", kConfig.bootstrapServers);
        Assert.assertEquals("PLAIN", kConfig.SASLMechanism);
        Assert.assertEquals("kamehameha", kConfig.SASLPlainPassword);
        Assert.assertEquals("SASL_SSL", kConfig.securityProtocol);
        Assert.assertEquals("prefix-42.ext", kConfig.topicPrefix);
        Assert.assertEquals("goten", kConfig.SASLPlainUsername);

    }

    public void testKafka() throws Exception {

        Properties props = new Properties();

        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, "");
        props.put(ProducerConfig.CLIENT_ID_CONFIG, "id-1");
        props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        props.put("security.protocol", "SASL_SSL");
        props.put("sasl.mechanism", "PLAIN");

        final String jaasConfig = "org.apache.kafka.common.security.plain.PlainLoginModule required \n" +
                "  username=\"admin\" \n" +
                "  password=\"dev2113\";";
        props.put("sasl.jaas.config", jaasConfig);

        props.put(ProducerConfig.ACKS_CONFIG, "all");

        Producer kafkaProducer = new KafkaProducer<String, String>(props);

        IndexOperation indexOp = new IndexOperation(IndexOperation.Type.CREATE, "ghostdiasse", "test", 3);
        ObjectMapper mapper = new ObjectMapper();

        String indexOpString = mapper.writeValueAsString(indexOp);

        Future<RecordMetadata> recordMetadata = kafkaProducer.send(new ProducerRecord("logs.EU.armor", "ghostdiasse", indexOpString));

        RecordMetadata md = recordMetadata.get(60, TimeUnit.SECONDS);

        Assert.assertTrue(md.partition() != -1);

    }

    @Test
    public void KserSecuredMessageIntegrity() throws Exception {
        final SodiumJava sodium = new SodiumJava();
        LazySodiumJava lsj = new LazySodiumJava(sodium);

        final byte[] privateKey = lsj.cryptoSecretBoxKeygen().getAsBytes();

        ObjectMapper mapper = new ObjectMapper();

        String originalMessage = "test";

        SecretBox secretBox = new SecretBox(privateKey);

        KSerSecuredMessage kserSecMess = new KSerSecuredMessage(originalMessage, secretBox);

        String nonceStr = kserSecMess.getNonce();

        byte[] nonceByte = Base64.getDecoder().decode(nonceStr);

        System.out.println(mapper.writeValueAsString(kserSecMess));

        String messageDecoded = lsj.cryptoSecretBoxOpenEasy(lsj.toHexStr(Base64.getDecoder().decode(kserSecMess.getData())), nonceByte, Key.fromBase64String(Base64.getEncoder().encodeToString(privateKey)));

        Assert.assertEquals(originalMessage, messageDecoded);

    }

    @Test
    public void testIndexCreation() throws Exception {

        username = "logs-xv-12345";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final AtomicReference<String> indexName = new AtomicReference<>(username + "-i-test-1");

        final String engineDatabaseName = "engine";

        final SodiumJava sodium = new SodiumJava();
        LazySodiumJava lazySodium = new LazySodiumJava(sodium);
        final String privateKey = Base64.getEncoder().encodeToString(lazySodium.cryptoSecretBoxKeygen().getAsBytes());

        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "lifecycle_index", "forbidden")
                .putList("armor.actionrequestfilter.lifecycle_index.allowed_actions", "indices:admin/create")
                .putList("armor.actionrequestfilter.forbidden.allowed_actions", "indices:data/read/scroll", "indices:data/read/scroll/clear")
                .put(ConfigConstants.ARMOR_INDEX_LIFECYCLE_ENABLED, true)
                .put(ConfigConstants.ARMOR_INDEX_LIFECYCLE_MAX_NUM_OF_SHARDS_BY_INDEX,5)
                .put(ConfigConstants.ARMOR_INDEX_LIFECYCLE_MAX_NUM_OF_REPLICAS_BY_INDEX, 2)
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

        KafkaProducer mockProducer = Mockito.mock(KafkaProducer.class);
        KafkaEngineService.setKafkaProducer(mockProducer);

        // avoid conflicting with MongoServer
        System.setProperty("es.set.netty.runtime.available.processors", "false");

        startES(settings);
        setupTestData("ac_rules_25.json");

        HeaderAwareJestHttpClient client = getJestClient(getServerUri(false), username, password);


        CreateIndex createIndex = new CreateIndex.Builder(indexName.get()).settings(Map.of("index.number_of_shards", 3, "index.number_of_replicas", 1)).build();

        final AtomicReference<Boolean> hasSent = new AtomicReference<>();
        hasSent.set(false);

        Mockito.when(mockProducer.send(Mockito.any())).then(invocationOnMock -> {
                    ProducerRecord<String, String> producerRecord = (ProducerRecord<String, String>) invocationOnMock.getArguments()[0];
                    KSerSecuredMessage kSerSecMess = objectMapper.readValue(producerRecord.value(), KSerSecuredMessage.class);
                    String nonceStr = kSerSecMess.getNonce();
                    byte[] nonceByte = Base64.getDecoder().decode(nonceStr);
                    LazySodiumJava lsj = new LazySodiumJava(sodium);
                    String kserOpString = lsj.cryptoSecretBoxOpenEasy(lsj.toHexStr(Base64.getDecoder().decode(kSerSecMess.getData())), nonceByte, Key.fromBase64String(privateKey));
                    KSerMessage kSerMessage = objectMapper.readValue(kserOpString, KSerMessage.class);

                    IndexOperation iOp = IndexOperation.fromKserMessage(kSerMessage);
                    Assert.assertEquals(username, iOp.getUsername());
                    Assert.assertEquals(IndexOperation.Type.CREATE, iOp.getType());
                    Assert.assertEquals(indexName.get(), iOp.getIndex());
                    //inspired by MockProducer from KafkaInternals
                    TopicPartition topicPartition = new TopicPartition(producerRecord.topic(), 0);
                    ProduceRequestResult result = new ProduceRequestResult(topicPartition);
                    result.set(0, 1, null);
                    FutureRecordMetadata future = new FutureRecordMetadata(result, 0L, -1L, 0L, 0, 0, Time.SYSTEM);
                    result.done();
                    hasSent.set(true);
                    return future;
                }
        );

        Tuple<JestResult, HttpResponse> result = client.executeE(createIndex);

        Assert.assertTrue(hasSent.get());

        Assert.assertTrue(result.v1().isSucceeded());
        Assert.assertTrue(result.v1().getJsonString().contains("acknowledged"));
        Assert.assertTrue(result.v1().getJsonString().contains("true"));

        indexName.set(username +"-i-test-2");

        CreateIndex createIndex2 = new CreateIndex.Builder(indexName.get()).settings(Map.of("number_of_shards", 8, "index.number_of_replicas", 1)).build();
        result = client.executeE(createIndex2);

        Assert.assertFalse(result.v1().isSucceeded());
        Assert.assertEquals(403, result.v2().getStatusLine().getStatusCode());

        hasSent.set(false);

        indexName.set(username +"-i-test-3");

        CreateIndex createIndex3 = new CreateIndex.Builder(indexName.get()).settings(Map.of("index.number_of_shards", 1, "number_of_replicas", 2)).build();
        result = client.executeE(createIndex3);

        Assert.assertTrue(result.v1().isSucceeded());
        Assert.assertEquals(200, result.v2().getStatusLine().getStatusCode());
        Assert.assertTrue(hasSent.get());

    }


    @Test
    public void testIndexDelete() throws Exception {

        username = "logs-xv-12345";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final String indexName = username + "-i-test-1";

        final String engineDatabaseName = "engine";

        final SodiumJava sodium = new SodiumJava();
        LazySodiumJava lazySodium = new LazySodiumJava(sodium);
        final String privateKey = Base64.getEncoder().encodeToString(lazySodium.cryptoSecretBoxKeygen().getAsBytes());

        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "lifecycle_index", "forbidden")
                .putList("armor.actionrequestfilter.lifecycle_index.allowed_actions", "indices:admin/create", "indices:admin/delete")
                .putList("armor.actionrequestfilter.forbidden.allowed_actions", "indices:data/read/scroll", "indices:data/read/scroll/clear")
                .put(ConfigConstants.ARMOR_INDEX_LIFECYCLE_ENABLED, true)
                .put(ConfigConstants.ARMOR_INDEX_LIFECYCLE_MAX_NUM_OF_SHARDS_BY_INDEX,5)
                .put(ConfigConstants.ARMOR_INDEX_LIFECYCLE_MAX_NUM_OF_REPLICAS_BY_INDEX, 2)
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

        configureEngineDatabase(engineTestDatabase, Collections.singletonList(currentUser));

        ObjectMapper objectMapper = new ObjectMapper();

        KafkaProducer mockProducer = Mockito.mock(KafkaProducer.class);
        KafkaEngineService.setKafkaProducer(mockProducer);

        System.setProperty("es.set.netty.runtime.available.processors", "false");

        startES(settings);
        setupTestData("ac_rules_25.json");

        HeaderAwareJestHttpClient client = getJestClient(getServerUri(false), username, password);


        CreateIndex createIndex = new CreateIndex.Builder(indexName).settings(Map.of("index.number_of_shards", 3, "index.number_of_replicas", 1)).build();

        final AtomicReference<Boolean> hasSent = new AtomicReference<>();
        final AtomicReference<String> checkDelete = new AtomicReference<>();
        checkDelete.set(null);
        hasSent.set(false);

        Mockito.when(mockProducer.send(Mockito.any())).then(invocationOnMock -> {
                    ProducerRecord<String, String> producerRecord = (ProducerRecord<String, String>) invocationOnMock.getArguments()[0];
                    KSerSecuredMessage kSerSecMess = objectMapper.readValue(producerRecord.value(), KSerSecuredMessage.class);
                    String nonceStr = kSerSecMess.getNonce();
                    byte[] nonceByte = Base64.getDecoder().decode(nonceStr);
                    LazySodiumJava lsj = new LazySodiumJava(sodium);
                    String kserOpString = lsj.cryptoSecretBoxOpenEasy(lsj.toHexStr(Base64.getDecoder().decode(kSerSecMess.getData())), nonceByte, Key.fromBase64String(privateKey));
                    KSerMessage kSerMessage = objectMapper.readValue(kserOpString, KSerMessage.class);
                    IndexOperation iOp = IndexOperation.fromKserMessage(kSerMessage);

                    if (checkDelete.get() != null && iOp.getType().equals(IndexOperation.Type.DELETE)) {
                        Assert.assertEquals(username, iOp.getUsername());
                        Assert.assertEquals(checkDelete.get(), iOp.getIndex());
                        hasSent.set(true);
                    }
                    //inspired by MockProducer from KafkaInternals
                    TopicPartition topicPartition = new TopicPartition(producerRecord.topic(), 0);
                    ProduceRequestResult result = new ProduceRequestResult(topicPartition);
                    result.set(iOp.getType().equals(IndexOperation.Type.CREATE) ? 0 : 1, 1, null);
                    FutureRecordMetadata future = new FutureRecordMetadata(result, 0L, -1L, 0L, 0, 0, Time.SYSTEM);
                    result.done();
                    return future;
                }
        );

        Tuple<JestResult, HttpResponse> result = client.executeE(createIndex);


        Assert.assertTrue(result.v1().isSucceeded());
        Assert.assertTrue(result.v1().getJsonString().contains("acknowledged"));
        Assert.assertTrue(result.v1().getJsonString().contains("true"));

        //DeleteIndex Failed
        DeleteIndex deleteIndexFail = new DeleteIndex.Builder("dev").build();
        result = client.executeE(deleteIndexFail);

        Assert.assertFalse(result.v1().isSucceeded());
        Assert.assertEquals(403, result.v2().getStatusLine().getStatusCode());
        Assert.assertTrue(result.v1().getErrorMessage().contains("dev"));

        DeleteIndex deleteIndexFail2 = new DeleteIndex.Builder("logs-xv-12345-i-*").build();
        result = client.executeE(deleteIndexFail2);

        Assert.assertFalse(result.v1().isSucceeded());
        Assert.assertEquals(403, result.v2().getStatusLine().getStatusCode());
        Assert.assertTrue(result.v1().getErrorMessage().contains("logs-xv-12345-i-*"));

        checkDelete.set(indexName);

        DeleteIndex deleteIndexSuccess = new DeleteIndex.Builder(indexName).build();
        result = client.executeE(deleteIndexSuccess);

        Assert.assertTrue(hasSent.get());

        Assert.assertTrue(result.v1().isSucceeded());
        Assert.assertTrue(result.v1().getJsonString().contains("acknowledged"));
        Assert.assertTrue(result.v1().getJsonString().contains("true"));


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
