package com.petalmd.armor.authentication.backend.graylog;

import com.mongodb.BasicDBObject;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.*;
import com.petalmd.armor.authentication.AuthCredentials;
import com.petalmd.armor.authentication.AuthException;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authentication.backend.NonCachingAuthenticationBackend;
import com.petalmd.armor.service.MongoDBService;
import com.petalmd.armor.util.ConfigConstants;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bson.Document;
import org.elasticsearch.common.settings.Settings;
import org.joda.time.Instant;

/**
 * Created by jehuty0shift on 17/02/2020.
 */
public class MongoDBTokenAuthenticationBackend implements NonCachingAuthenticationBackend {

    private static final Logger log = LogManager.getLogger(MongoDBTokenAuthenticationBackend.class);
    private final MongoCollection<Document> tokenCollection;
    private final boolean enabled;

    public MongoDBTokenAuthenticationBackend(final Settings settings) {

        final String mongoDBURI = settings.get(ConfigConstants.ARMOR_MONGODB_URI, "");
        if (!mongoDBURI.isBlank() && MongoDBService.getGraylogDatabase().isPresent()) {
            enabled = true;
            tokenCollection = MongoDBService.getGraylogDatabase().get().getCollection("access_tokens");
            tokenCollection.createIndex(new BasicDBObject("token",1), new IndexOptions().unique(true));
        } else {
            enabled = false;
            tokenCollection = null;
        }
    }


    @Override
    public User authenticate(AuthCredentials credentials) throws AuthException {
        if (!enabled) {
            return null;
        }
        final String password = new String(credentials.getPassword());

        if (!password.equals("token")) {
            throw new AuthException("Unauthorized");
        }

        final String tokenValue = credentials.getUsername();

        credentials.clear();

        final Document userDocument = tokenCollection.find(Filters.eq("token", tokenValue)).first();

        if (userDocument == null) {
            log.warn("nothing found for token {}", tokenValue);
            throw new AuthException(("Unauthorized"));
        }

        final String username = userDocument.getString("username");

        // Implement last access like Graylog do
        userDocument.put("last_access", Instant.now().toDate());
        try {
            tokenCollection.replaceOne(Filters.eq("token", tokenValue), userDocument, new ReplaceOptions().upsert(false));
        } catch (Exception ex) {
            log.error("Error during last access update",ex);
            throw new AuthException("Unexpected Error during update");
        }
        return new User(username);

    }
}
