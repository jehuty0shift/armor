package com.petalmd.armor.authentication.backend.graylog;

import com.google.common.hash.Hashing;
import com.mongodb.BasicDBObject;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.IndexOptions;
import com.petalmd.armor.authentication.AuthCredentials;
import com.petalmd.armor.authentication.AuthException;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authentication.backend.NonCachingAuthenticationBackend;
import com.petalmd.armor.service.MongoDBService;
import com.petalmd.armor.util.ConfigConstants;
import org.apache.commons.codec.binary.Hex;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bson.Document;
import org.cryptomator.siv.SivMode;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;

import java.nio.charset.StandardCharsets;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Arrays;

/**
 * Created by jehuty0shift on 17/02/2020.
 */
public class EncryptedMongoDBTokenAuthenticationBackend implements NonCachingAuthenticationBackend {

    private static final Logger log = LogManager.getLogger(EncryptedMongoDBTokenAuthenticationBackend.class);
    private final MongoCollection<Document> tokenCollection;
    private final boolean enabled;
    private final byte[] privateKey;
    private final SivMode SIV_MODE;

    @Inject
    public EncryptedMongoDBTokenAuthenticationBackend(final Settings settings) {

        final String mongoDBURI = settings.get(ConfigConstants.ARMOR_MONGODB_URI, "");
        String privateKeyString = settings.get(ConfigConstants.ARMOR_MONGODB_ENCRYPTED_TOKEN_PRIVATE_KEY);
        privateKey = privateKeyString != null ? Hashing.sha256().hashString(privateKeyString, StandardCharsets.UTF_8).asBytes() : null;
        if (!mongoDBURI.isBlank() && MongoDBService.getGraylogDatabase().isPresent() && privateKey != null) {
            enabled = true;
            tokenCollection = AccessController.doPrivileged((PrivilegedAction<MongoCollection>) () -> {
                MongoCollection<Document> tCollection = MongoDBService.getGraylogDatabase().get().getCollection("access_tokens");
                tCollection.createIndex(new BasicDBObject("token", 1), new IndexOptions().unique(true));
                return tCollection;
            });
            SIV_MODE = AccessController.doPrivileged((PrivilegedAction<SivMode>) () -> new SivMode());
        } else {
            enabled = false;
            tokenCollection = null;
            SIV_MODE = null;
        }
        log.info("MongoDB Authentication is {}", enabled ? "enabled" : "disabled");
    }


    private String encryptToken(final String token) throws AuthException {

        if (token == null || token.isBlank()) {
            log.error("token provided is blank");
            throw new AuthException("invalid token given", AuthException.ExceptionType.NOT_FOUND);
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
            throw new AuthException("Couldn't encrypt token value", AuthException.ExceptionType.ERROR);
        }
    }


    @Override
    public User authenticate(AuthCredentials credentials) throws AuthException {
        if (!enabled) {
            throw new AuthException("Encrypted MongoDB Token Authentication is disabled", AuthException.ExceptionType.ERROR);
        }
        final String password = new String(credentials.getPassword());

        if (!password.equals("token")) {
            throw new AuthException("Not a token auth", AuthException.ExceptionType.NOT_FOUND);
        }

        final String tokenValue = credentials.getUsername();

        credentials.clear();

        try {
            User user = AccessController.doPrivileged((PrivilegedExceptionAction<User>) () -> {
                final Document userDocument = tokenCollection.find(Filters.eq("token", encryptToken(tokenValue))).first();

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
