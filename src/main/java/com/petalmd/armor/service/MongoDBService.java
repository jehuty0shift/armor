package com.petalmd.armor.service;

import com.mongodb.MongoClient;
import com.mongodb.MongoClientURI;
import com.mongodb.client.MongoDatabase;
import com.petalmd.armor.util.ConfigConstants;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.component.AbstractLifecycleComponent;
import org.elasticsearch.common.settings.Settings;

import java.io.IOException;
import java.util.Optional;

/**
 * Created by jehuty0shift on 23/01/2020.
 */
public class MongoDBService extends AbstractLifecycleComponent {

    private static final Logger log = LogManager.getLogger(MongoDBService.class);
    private final Settings settings;
    private boolean enabled;
    private static MongoClient mongoClient;
    private MongoDatabase engineDatabase;
    private MongoDatabase graylogDatabase;

    public MongoDBService(final Settings settings) {
        this.enabled = !settings.get(ConfigConstants.ARMOR_MONGODB_URI, "").isBlank();
        this.settings = settings;
        engineDatabase = null;
        graylogDatabase = null;
        if (enabled) {
            final String mongoDBUriString = settings.get(ConfigConstants.ARMOR_MONGODB_URI);
            log.info("connecting to MongoDB with URI {}", mongoDBUriString);
            if (!mongoDBUriString.equals("test")) {
                mongoClient = new MongoClient(new MongoClientURI(mongoDBUriString));
            }
            //configure Engine
            final String engineDatabaseName = settings.get(ConfigConstants.ARMOR_MONGODB_ENGINE_DATABASE);
            if (engineDatabaseName == null || engineDatabaseName.isBlank()) {
                log.warn("Engine Database name is not provided !");
            } else {
                engineDatabase = mongoClient.getDatabase(engineDatabaseName);
                log.info("configured engine database {}", engineDatabaseName);
            }

            //configure Graylog
//            final String graylogDatabaseName = settings.get(ConfigConstants.ARMOR_MONGODB_GRAYLOG_DATABASE);
//            if (graylogDatabaseName == null || graylogDatabaseName.isBlank()) {
//                log.warn("Graylog Database is not provided !");
//            } else {
//                graylogDatabase = mongoClient.getDatabase(graylogDatabaseName);
//                log.info("configured graylog database {}", graylogDatabaseName);
//            }
        } else {
            log.info("MongoDBService is not available");
        }
    }


    @Override
    protected void doStart() {

    }

    @Override
    protected void doStop() {
        //noop
    }

    @Override
    protected void doClose() throws IOException {
        if (mongoClient != null) {
            mongoClient.close();
        }
    }

    public Optional<MongoDatabase> getEngineDatabase() {
        return Optional.ofNullable(engineDatabase);
    }

    public Optional<MongoDatabase> getGraylogDatabase() {
        return Optional.ofNullable(graylogDatabase);
    }

    public static void setMongoClient(MongoClient newMongoClient) {
        mongoClient = newMongoClient;
    }
}
