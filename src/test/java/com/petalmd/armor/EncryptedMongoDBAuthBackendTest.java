package com.petalmd.armor;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.google.common.hash.Hashing;
import com.mongodb.BasicDBObject;
import com.mongodb.MongoClient;
import com.mongodb.ServerAddress;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.IndexOptions;
import com.petalmd.armor.authentication.AuthCredentials;
import com.petalmd.armor.authentication.AuthException;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authentication.backend.graylog.EncryptedMongoDBTokenAuthenticationBackend;
import com.petalmd.armor.service.MongoDBService;
import com.petalmd.armor.util.ConfigConstants;
import de.bwaldvogel.mongo.MongoServer;
import de.bwaldvogel.mongo.backend.memory.MemoryBackend;
import org.apache.commons.codec.binary.Hex;
import org.bson.Document;
import org.cryptomator.siv.SivMode;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;

/**
 * Created by jehuty0shift on 17/02/2020.
 */

@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class EncryptedMongoDBAuthBackendTest extends AbstractUnitTest {


    private SivMode SIV_MODE;

    @Before
    void configureSIV() {
        if (SIV_MODE == null) {
            SIV_MODE = AccessController.doPrivileged((PrivilegedAction<SivMode>) () -> new SivMode());
        }
    }


    @Test
    public void userSuccess() throws Exception {
        final String privateKeyString = "Upf7CYWy6qEVo813w1QWUpf7CYWy6qEVo813w1QW";

        final byte[] privateKey = Hashing.sha256().hashString(privateKeyString, StandardCharsets.UTF_8).asBytes();

        MongoServer server = new MongoServer(new MemoryBackend());

        InetSocketAddress serverAddress = server.bind();

        MongoClient client = new MongoClient(new ServerAddress(serverAddress));

        MongoDatabase graylogDatabase = client.getDatabase("graylog");

        configureDatabase(graylogDatabase, privateKey);

        Settings authTestSettings = Settings.builder()
                .put(ConfigConstants.ARMOR_MONGODB_URI, "test")
                .put(ConfigConstants.ARMOR_MONGODB_GRAYLOG_DATABASE, "graylog")
                .put(ConfigConstants.ARMOR_MONGODB_ENCRYPTED_TOKEN_PRIVATE_KEY, privateKeyString)
                .build();

        MongoDBService.setMongoClient(client);

        MongoDBService mongoService = new MongoDBService(authTestSettings);

        EncryptedMongoDBTokenAuthenticationBackend mongoAuthBackend = new EncryptedMongoDBTokenAuthenticationBackend(authTestSettings);

        User userOne = mongoAuthBackend.authenticate(new AuthCredentials("7tjlgvrx7fq84an4t0yny7sg4c1225likmwvzeq626dvov3qgjp", "token".toCharArray()));

        Assert.assertEquals(userOne.getName(), "logs-dr-78293");
    }

    @Test
    public void userSuccessGraylog() throws Exception {

        final String privateKeyString = "5FWL3KFXkMmZYNdJynJnOTFO1rfLvXoE2SVSyKDzmAYBljTwmx5J4NGn910GKN5NaHTUoDHnAGyMSENgn0dE6oUjoYwB4B6o";

        final byte[] privateKey = Hashing.sha256().hashString(privateKeyString, StandardCharsets.UTF_8).asBytes();

        MongoServer server = new MongoServer(new MemoryBackend());

        InetSocketAddress serverAddress = server.bind();

        MongoClient client = new MongoClient(new ServerAddress(serverAddress));

        MongoDatabase graylogDatabase = client.getDatabase("graylog");

        configureDatabase(graylogDatabase, privateKey);

        Settings authTestSettings = Settings.builder()
                .put(ConfigConstants.ARMOR_MONGODB_URI, "test")
                .put(ConfigConstants.ARMOR_MONGODB_GRAYLOG_DATABASE, "graylog")
                .put(ConfigConstants.ARMOR_MONGODB_ENCRYPTED_TOKEN_PRIVATE_KEY, privateKeyString)
                .build();

        MongoDBService.setMongoClient(client);

        MongoDBService mongoService = new MongoDBService(authTestSettings);

        EncryptedMongoDBTokenAuthenticationBackend mongoAuthBackend = new EncryptedMongoDBTokenAuthenticationBackend(authTestSettings);

        User userOne = mongoAuthBackend.authenticate(new AuthCredentials("ablktdf9h7ch6s6pu5f2rkp6r7f1s8qig84bvhkgk1u85kota6r", "token".toCharArray()));

        Assert.assertEquals(userOne.getName(), "logs-gd-44789");
    }


    @Test
    public void passwordIsntToken() throws Exception {

        final String privateKeyString = "Upf7CYWy6qEVo813w1QWUpf7CYWy6qEVo813w1QW";

        final byte[] privateKey = Hashing.sha256().hashString(privateKeyString, StandardCharsets.UTF_8).asBytes();

        MongoServer server = new MongoServer(new MemoryBackend());

        InetSocketAddress serverAddress = server.bind();

        MongoClient client = new MongoClient(new ServerAddress(serverAddress));

        MongoDatabase graylogDatabase = client.getDatabase("graylog");

        configureDatabase(graylogDatabase, privateKey);

        Settings authTestSettings = Settings.builder()
                .put(ConfigConstants.ARMOR_MONGODB_URI, "test")
                .put(ConfigConstants.ARMOR_MONGODB_GRAYLOG_DATABASE, "graylog")
                .put(ConfigConstants.ARMOR_MONGODB_ENCRYPTED_TOKEN_PRIVATE_KEY, privateKeyString)
                .build();

        MongoDBService.setMongoClient(client);

        MongoDBService mongoService = new MongoDBService(authTestSettings);

        EncryptedMongoDBTokenAuthenticationBackend mongoAuthBackend = new EncryptedMongoDBTokenAuthenticationBackend(authTestSettings);

        try {
            User userOne = mongoAuthBackend.authenticate(new AuthCredentials("7tjlgvrx7fq84an4t0yny7sg4c1225likmwvzeq626dvov3qgjp", "thisisnotToken".toCharArray()));
            throw new IllegalStateException("Shouldn't reach here");
        } catch (AuthException ex) {
            Assert.assertTrue(ex.getMessage().contains("Not a token"));
        }
    }


    @Test
    public void userUnknown() throws Exception {

        final String privateKeyString = "Upf7CYWy6qEVo813w1QWUpf7CYWy6qEVo813w1QW";

        final byte[] privateKey = Hashing.sha256().hashString(privateKeyString, StandardCharsets.UTF_8).asBytes();

        MongoServer server = new MongoServer(new MemoryBackend());

        InetSocketAddress serverAddress = server.bind();

        MongoClient client = new MongoClient(new ServerAddress(serverAddress));

        MongoDatabase graylogDatabase = client.getDatabase("graylog");

        configureDatabase(graylogDatabase, privateKey);

        Settings authTestSettings = Settings.builder()
                .put(ConfigConstants.ARMOR_MONGODB_URI, "test")
                .put(ConfigConstants.ARMOR_MONGODB_GRAYLOG_DATABASE, "graylog")
                .put(ConfigConstants.ARMOR_MONGODB_ENCRYPTED_TOKEN_PRIVATE_KEY, privateKeyString)
                .build();

        MongoDBService.setMongoClient(client);

        MongoDBService mongoService = new MongoDBService(authTestSettings);

        EncryptedMongoDBTokenAuthenticationBackend mongoAuthBackend = new EncryptedMongoDBTokenAuthenticationBackend(authTestSettings);
        try {
            User userOne = mongoAuthBackend.authenticate(new AuthCredentials("7tjlgvrx7fq84an4t0yny7sg4c12yiovicmwvzeq626dvov3qgjp", "token".toCharArray()));
            throw new IllegalStateException("shouldn't reach here");
        } catch (AuthException ex) {
            Assert.assertTrue(ex.getMessage().contains("Unauthorized"));
        }
    }


    private void configureDatabase(final MongoDatabase graylogDB, final byte[] privateKey) {

        MongoCollection<Document> mongoCollection = graylogDB.getCollection("access_tokens");
        mongoCollection.createIndex(new BasicDBObject("token", 1), new IndexOptions().unique(true));
        // put 3 tokens
        Document token1 = new Document();

        token1.put("token", encryptToken(privateKey, "7tjlgvrx7fq84an4t0yny7sg4c1225likmwvzeq626dvov3qgjp"));
        token1.put("last_access", Date.from(Instant.EPOCH));
        token1.put("username", "logs-dr-78293");
        token1.put("NAME", "token1");

        mongoCollection.insertOne(token1);


        Document token2 = new Document();

        token2.put("token", encryptToken(privateKey, "usdu9bb09to3a1sef8h1l8abx5y74gegf52zccwd7jb1skrl77t"));
        token2.put("last_access", Date.from(Instant.parse("2020-01-03T10:00:00.000Z")));
        token2.put("username", "logs-ab-12789");
        token2.put("NAME", "token2");

        mongoCollection.insertOne(token2);


        Document token3 = new Document();
        //This token should be already Encrypted
        token3.put("token", "f68cd99822ce917de12c8b038103dae57c86aec529db2dae3f2ce6340d574831d7d2aa77c06ab9825f3982eb64ede9a8d566bdd29a3e3483502c70bc1482f2a50107ac");
        token3.put("last_access", Date.from(Instant.parse("2019-11-03T06:45:23.000Z")));
        token3.put("username", "logs-gd-44789");
        token3.put("NAME", "token3");

        mongoCollection.insertOne(token3);

    }

    private String encryptToken(final byte[] privateKey, final String token) {
        if (token == null || token.isBlank()) {
            log.error("token provided is blank");
            return null;
        }

        try {
            final byte[] cipherBytes = SIV_MODE.encrypt(
                    Arrays.copyOf(privateKey, 16),
                    Arrays.copyOfRange(privateKey, 16, 32),
                    token.getBytes(StandardCharsets.UTF_8)
            );
            return Hex.encodeHexString(cipherBytes);
        } catch (Exception e) {
            log.error("Couldn't encrypt token value", e);
            return null;
        }


    }
}
