package com.petalmd.armor.authentication.backend.graylog;

import com.mongodb.BasicDBObject;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.*;
import com.mongodb.client.result.UpdateResult;
import com.petalmd.armor.authentication.AuthCredentials;
import com.petalmd.armor.authentication.AuthException;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authentication.backend.NonCachingAuthenticationBackend;
import com.petalmd.armor.service.MongoDBService;
import com.petalmd.armor.util.ConfigConstants;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bson.Document;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.joda.time.Instant;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

/**
 * Created by jehuty0shift on 17/02/2020.
 */
public class MongoDBTokenAuthenticationBackend implements NonCachingAuthenticationBackend {

    private static final Logger log = LogManager.getLogger(MongoDBTokenAuthenticationBackend.class);
    private final MongoCollection<Document> tokenCollection;
    private final boolean enabled;

    @Inject
    public MongoDBTokenAuthenticationBackend(final Settings settings) {

        final String mongoDBURI = settings.get(ConfigConstants.ARMOR_MONGODB_URI, "");
        if (!mongoDBURI.isBlank() && MongoDBService.getGraylogDatabase().isPresent()) {
            enabled = true;
            tokenCollection = AccessController.doPrivileged((PrivilegedAction<MongoCollection>) () -> {
                MongoCollection<Document> tCollection = MongoDBService.getGraylogDatabase().get().getCollection("access_tokens");
                tCollection.createIndex(new BasicDBObject("token", 1), new IndexOptions().unique(true));
                return tCollection;
            });
        } else {
            enabled = false;
            tokenCollection = null;
        }
        log.info("MongoDB Authentication is {}", enabled ? "enabled" : "disabled");
    }


    @Override
    public User authenticate(AuthCredentials credentials) throws AuthException {
        if (!enabled) {
            throw new AuthException("MongoDB Token Authentication is disabled", AuthException.ExceptionType.ERROR);
        }
        final String password = new String(credentials.getPassword());

        if (!password.equals("token")) {
            throw new AuthException("Unauthorized");
        }

        final String tokenValue = credentials.getUsername();

        credentials.clear();

        try {
            User user = AccessController.doPrivileged((PrivilegedExceptionAction<User>) () -> {
                final Document userDocument = tokenCollection.find(Filters.eq("token", tokenValue)).first();

                if (userDocument == null) {
                    log.debug("nothing found for token {}", tokenValue);
                    throw new AuthException("Unauthorized", AuthException.ExceptionType.NOT_FOUND);
                }

                final String username = userDocument.getString("username");
                return new User(username);
            });

            return user;
        } catch (PrivilegedActionException ex) {
            if (ex.getException() instanceof AuthException) {
                throw (AuthException) ex.getException();
            }
        }
        throw new AuthException("Unable to retrieve graylog User", AuthException.ExceptionType.NOT_FOUND);
    }
}
