package com.petalmd.armor;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.mongodb.BasicDBObject;
import com.mongodb.MongoClient;
import com.mongodb.ServerAddress;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.IndexOptions;
import com.petalmd.armor.authentication.AuthCredentials;
import com.petalmd.armor.authentication.AuthException;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authentication.backend.graylog.MongoDBTokenAuthenticationBackend;
import com.petalmd.armor.service.MongoDBService;
import com.petalmd.armor.util.ConfigConstants;
import de.bwaldvogel.mongo.MongoServer;
import de.bwaldvogel.mongo.backend.memory.MemoryBackend;
import org.bson.Document;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import java.net.InetSocketAddress;
import java.time.Instant;
import java.util.Date;

/**
 * Created by jehuty0shift on 17/02/2020.
 */

@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class MongoDBAuthBackendTest extends AbstractUnitTest {


    @Test
    public void userSuccess() throws Exception {

        MongoServer server = new MongoServer(new MemoryBackend());

        InetSocketAddress serverAddress = server.bind();

        MongoClient client = new MongoClient(new ServerAddress(serverAddress));

        MongoDatabase graylogDatabase = client.getDatabase("graylog");

        configureDatabase(graylogDatabase);

        Settings authTestSettings = Settings.builder()
                .put(ConfigConstants.ARMOR_MONGODB_URI, "test")
                .put(ConfigConstants.ARMOR_MONGODB_GRAYLOG_DATABASE, "graylog")
                .build();

        MongoDBService.setMongoClient(client);

        MongoDBService mongoService = new MongoDBService(authTestSettings);

        MongoDBTokenAuthenticationBackend mongoAuthBackend = new MongoDBTokenAuthenticationBackend(authTestSettings);

        User userOne = mongoAuthBackend.authenticate(new AuthCredentials("7tjlgvrx7fq84an4t0yny7sg4c1225likmwvzeq626dvov3qgjp", "token".toCharArray()));

        Assert.assertEquals(userOne.getName(), "logs-dr-78293");
    }


    @Test
    public void passwordIsntToken() throws Exception {

        MongoServer server = new MongoServer(new MemoryBackend());

        InetSocketAddress serverAddress = server.bind();

        MongoClient client = new MongoClient(new ServerAddress(serverAddress));

        MongoDatabase graylogDatabase = client.getDatabase("graylog");

        configureDatabase(graylogDatabase);

        Settings authTestSettings = Settings.builder()
                .put(ConfigConstants.ARMOR_MONGODB_URI, "test")
                .put(ConfigConstants.ARMOR_MONGODB_GRAYLOG_DATABASE, "graylog")
                .build();

        MongoDBService.setMongoClient(client);

        MongoDBService mongoService = new MongoDBService(authTestSettings);

        MongoDBTokenAuthenticationBackend mongoAuthBackend = new MongoDBTokenAuthenticationBackend(authTestSettings);

        try {
            User userOne = mongoAuthBackend.authenticate(new AuthCredentials("7tjlgvrx7fq84an4t0yny7sg4c1225likmwvzeq626dvov3qgjp", "thisisnotToken".toCharArray()));
            throw new IllegalStateException("Shouldn't reach here");
        } catch (AuthException ex) {
            Assert.assertTrue(ex.getMessage().contains("Unauthorized"));
        }
    }


    @Test
    public void userUnknown() throws Exception {

        MongoServer server = new MongoServer(new MemoryBackend());

        InetSocketAddress serverAddress = server.bind();

        MongoClient client = new MongoClient(new ServerAddress(serverAddress));

        MongoDatabase graylogDatabase = client.getDatabase("graylog");

        configureDatabase(graylogDatabase);

        Settings authTestSettings = Settings.builder()
                .put(ConfigConstants.ARMOR_MONGODB_URI, "test")
                .put(ConfigConstants.ARMOR_MONGODB_GRAYLOG_DATABASE, "graylog")
                .build();

        MongoDBService.setMongoClient(client);

        MongoDBService mongoService = new MongoDBService(authTestSettings);

        MongoDBTokenAuthenticationBackend mongoAuthBackend = new MongoDBTokenAuthenticationBackend(authTestSettings);
        try {
            User userOne = mongoAuthBackend.authenticate(new AuthCredentials("7tjlgvrx7fq84an4t0yny7sg4c12yiovicmwvzeq626dvov3qgjp", "token".toCharArray()));
            throw new IllegalStateException("shouldn't reach here");
        } catch (AuthException ex) {
            Assert.assertTrue(ex.getMessage().contains("Unauthorized"));
        }
    }


    @Test
    public void checkAccessDate() throws Exception {

        MongoServer server = new MongoServer(new MemoryBackend());

        InetSocketAddress serverAddress = server.bind();

        MongoClient client = new MongoClient(new ServerAddress(serverAddress));

        MongoDatabase graylogDatabase = client.getDatabase("graylog");

        configureDatabase(graylogDatabase);

        Settings authTestSettings = Settings.builder()
                .put(ConfigConstants.ARMOR_MONGODB_URI, "test")
                .put(ConfigConstants.ARMOR_MONGODB_GRAYLOG_DATABASE, "graylog")
                .build();

        MongoDBService.setMongoClient(client);

        MongoDBService mongoService = new MongoDBService(authTestSettings);

        MongoDBTokenAuthenticationBackend mongoAuthBackend = new MongoDBTokenAuthenticationBackend(authTestSettings);

        User userOne = mongoAuthBackend.authenticate(new AuthCredentials("7tjlgvrx7fq84an4t0yny7sg4c1225likmwvzeq626dvov3qgjp", "token".toCharArray()));

        Assert.assertEquals(userOne.getName(), "logs-dr-78293");

        MongoCollection<Document> tokenCollections = graylogDatabase.getCollection("access_tokens");

        Document token1 = tokenCollections.find(Filters.eq("token", "7tjlgvrx7fq84an4t0yny7sg4c1225likmwvzeq626dvov3qgjp")).first();

        Assert.assertTrue(token1.getDate("last_access").toInstant().isAfter(Instant.EPOCH));


    }

    private void configureDatabase(final MongoDatabase graylogDB) {

        MongoCollection<Document> mongoCollection = graylogDB.getCollection("access_tokens");
        mongoCollection.createIndex(new BasicDBObject("token", 1), new IndexOptions().unique(true));
        // put 3 tokens
        Document token1 = new Document();

        token1.put("token", "7tjlgvrx7fq84an4t0yny7sg4c1225likmwvzeq626dvov3qgjp");
        token1.put("last_access", Date.from(Instant.EPOCH));
        token1.put("username", "logs-dr-78293");
        token1.put("NAME", "token1");

        mongoCollection.insertOne(token1);


        Document token2 = new Document();

        token2.put("token", "usdu9bb09to3a1sef8h1l8abx5y74gegf52zccwd7jb1skrl77t");
        token2.put("last_access", Date.from(Instant.parse("2020-01-03T10:00:00.000Z")));
        token2.put("username", "logs-ab-12789");
        token2.put("NAME", "token2");

        mongoCollection.insertOne(token2);


        Document token3 = new Document();

        token3.put("token", "hp5z1gionln12u9sov0tiec2b6eykx56bktliy14i62izt9hb0x");
        token3.put("last_access", Date.from(Instant.parse("2019-11-03T06:45:23.000Z")));
        token3.put("username", "logs-ab-12789");
        token3.put("NAME", "token3");

        mongoCollection.insertOne(token3);

    }
}
