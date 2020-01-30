package com.petalmd.armor;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.mongodb.MongoClient;
import com.mongodb.ServerAddress;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.petalmd.armor.filter.lifecycle.KafkaConfig;
import com.petalmd.armor.filter.lifecycle.LifeCycleMongoCodecProvider;
import de.bwaldvogel.mongo.MongoServer;
import de.bwaldvogel.mongo.backend.memory.MemoryBackend;
import kong.unirest.Unirest;
import org.bson.Document;
import org.bson.codecs.configuration.CodecRegistries;
import org.bson.codecs.configuration.CodecRegistry;
import org.junit.Assert;
import org.junit.Test;
import org.powermock.core.classloader.annotations.PrepareForTest;

import java.net.InetSocketAddress;
import java.util.ArrayList;

/**
 * Created by jehuty0shift on 24/01/2020.
 */

@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
@PrepareForTest({Unirest.class})
public class IndexLifeCycleFilterTest extends AbstractScenarioTest {

    @Test
    public void testKafkaConfigurationCodec() {

        MongoServer server = new MongoServer(new MemoryBackend());

        InetSocketAddress serverAddress  = server.bind();

        MongoClient client = new MongoClient(new ServerAddress(serverAddress));

        MongoDatabase engineTestDatabase = client.getDatabase("engine");
        CodecRegistry cR = CodecRegistries.fromRegistries(CodecRegistries.fromProviders(new LifeCycleMongoCodecProvider()), MongoClient.getDefaultCodecRegistry());

        MongoCollection<Document> initialCollection = engineTestDatabase.getCollection("config");

        Document configuration = new Document();
        configuration.put("name","configuration");
        configuration.put("_list",new ArrayList<>());
        Document dict = new Document();
        dict.put("INPUT_RSA_LENGTH",2048);
        dict.put("INPUT_SIGN_PROTO","sha1");
        dict.put("KIBANA_CPU",0.1);
        dict.put("KIBANA_MEM",320);
        dict.put("KSER_TOPIC_PREFIX","prefix-42.ext");
        Document kserConfig = new Document();
        kserConfig.put("BOOTSTRAP_SERVERS","kafka.p1.prod.us");
        kserConfig.put("SASL_PLAIN_USERNAME","goten");
        kserConfig.put("SASL_PLAIN_PASSWORD","kamehameha");
        kserConfig.put("SASL_MECHANISM","PLAIN");
        kserConfig.put("SECURITY_PROTOCOL","SASL_SSL");
        dict.put("KSER_PRODUCER_CONFIG",kserConfig);
        configuration.put("_dict",dict);

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

}
