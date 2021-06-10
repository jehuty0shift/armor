

package com.petalmd.armor.authentication.backend.multi;

import com.google.common.collect.Lists;
import com.petalmd.armor.authentication.AuthCredentials;
import com.petalmd.armor.authentication.AuthException;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authentication.backend.NonCachingAuthenticationBackend;
import com.petalmd.armor.authentication.backend.graylog.MongoDBTokenAuthenticationBackend;
import com.petalmd.armor.util.ConfigConstants;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

public class MultiAuthenticationBackend
        implements NonCachingAuthenticationBackend {
    private final List<NonCachingAuthenticationBackend> nonCachingAuthBackends;
    protected static final Logger log = LogManager.getLogger(MultiAuthenticationBackend.class);
    private MongoDBTokenAuthenticationBackend mongoDBTokenBackend;

    @Inject
    public MultiAuthenticationBackend(Settings settings) {

        this.nonCachingAuthBackends = new ArrayList<NonCachingAuthenticationBackend>();
        for (String backend : settings.getAsList(ConfigConstants.ARMOR_AUTHENTICATION_MULTI_AUTH_BACKEND_LIST)) {
            try {
                Class clazz = Class.forName(backend);
                Constructor ctor = clazz.getDeclaredConstructor(Settings.class);
                NonCachingAuthenticationBackend nonCachingBackend = (NonCachingAuthenticationBackend) ctor.newInstance(new Object[]{settings});
                this.nonCachingAuthBackends.add(nonCachingBackend);
                if (clazz.equals(MongoDBTokenAuthenticationBackend.class)) {
                    mongoDBTokenBackend = (MongoDBTokenAuthenticationBackend) nonCachingBackend;
                }
                continue;
            } catch (ClassNotFoundException ex) {
                this.log.warn("Class " + backend + "has not been found ! Skipping this class", ex, new Object[0]);
                this.log.warn(ex);
                continue;
            } catch (NoSuchMethodException ex) {
                this.log.warn("Couldn't find suitable constructor for " + backend + " ! Skipping this class", ex, new Object[0]);
                this.log.warn(ex);
                continue;
            } catch (InstantiationException ex) {
                this.log.warn("InstantiationException: Couldn't instantiate backend " + backend + " ! Skipping this class", ex, new Object[0]);
                this.log.warn(ex);
                this.log.warn("WTF");
                continue;
            } catch (IllegalAccessException ex) {
                this.log.warn("IllegalAccessException: Couldn't instantiate backend " + backend + " ! Skipping this class", ex, new Object[0]);
                this.log.warn(ex);
                continue;
            } catch (IllegalArgumentException ex) {
                this.log.warn("IllegalArgumentException: Couldn't instantiate backend " + backend + " ! Skipping this class", ex, new Object[0]);
                this.log.warn(ex);
                continue;
            } catch (InvocationTargetException ex) {
                this.log.warn("InvocationTargetException: Couldn't instantiate backend " + backend + " ! Skipping this class", ex, new Object[0]);
                ex.getCause().printStackTrace();
                this.log.error("cause", ex.getCause());
                this.log.error("target", ex.getTargetException());
                this.log.error("error", ex);
            }
        }
    }

    @Override
    public User authenticate(AuthCredentials credentials) throws AuthException {
        ArrayList<AuthException> exceptions = new ArrayList<AuthException>();
        if(mongoDBTokenBackend != null && credentials.getPassword() != null && Arrays.equals(credentials.getPassword(), "token".toCharArray())) {
            log.debug("trying to authenticate first with {}",MongoDBTokenAuthenticationBackend.class.getName());
            AuthCredentials copiedCredentials = new AuthCredentials(credentials.getUsername(), credentials.getPassword());
            User user = mongoDBTokenBackend.authenticate(copiedCredentials);
            credentials.clear();
            if(user!=null) {
                this.log.debug("Found User: " + user.getName() + " for backend " + mongoDBTokenBackend.getClass().getName());
                return user;
            }
        }
        for (NonCachingAuthenticationBackend backend : this.nonCachingAuthBackends) {
            try {
                AuthCredentials copiedCredentials;
                User user;
                this.log.debug("Trying to Authenticate against " + backend.getClass().getName(), new Object[0]);
                if (credentials.getPassword() != null) {
                    char[] passwordCopy = Arrays.copyOf(credentials.getPassword(), credentials.getPassword().length);
                    copiedCredentials = new AuthCredentials(credentials.getUsername(), passwordCopy);
                    this.log.debug("credentials use passsword", new Object[0]);
                } else if (credentials.getNativeCredentials() != null) {
                    copiedCredentials = new AuthCredentials(credentials.getUsername(), credentials.getNativeCredentials());
                    this.log.debug("credentials use native Handler", new Object[0]);
                } else {
                    copiedCredentials = new AuthCredentials(credentials.getUsername());
                    this.log.debug("only the username was provided", new Object[0]);
                }
                if ((user = backend.authenticate(copiedCredentials)) == null) continue;
                this.log.debug("Found User: " + user.getName() + " for backend " + backend.getClass().getName(), new Object[0]);
                credentials.clear();
                return user;
            } catch (AuthException ex) {
                this.log.debug("This backend has not been able to authenticate the user: " + backend.getClass().getName(), ex, new Object[0]);
                exceptions.add(ex);
                continue;
            }
        }
        Optional<AuthException> authEx = exceptions.stream().filter(ex-> ex.getType().equals(AuthException.ExceptionType.ERROR)).findAny();
        if(authEx.isPresent()) {
            throw new ElasticsearchException("error with the authentication system, please retry or report the error");
        } else {
            throw new AuthException("Couldn't authenticate user " + credentials.getUsername() + " against any of the backends.", new MultiAuthException(exceptions), AuthException.ExceptionType.NOT_FOUND);
        }
    }
}

