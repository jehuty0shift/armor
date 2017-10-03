

package com.petalmd.armor.authentication.backend.multi;

import com.petalmd.armor.authentication.AuthCredentials;
import com.petalmd.armor.authentication.AuthException;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authentication.backend.NonCachingAuthenticationBackend;
import com.petalmd.armor.util.ConfigConstants;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLoggerFactory;
import org.elasticsearch.common.settings.Settings;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class MultiAuthenticationBackend
implements NonCachingAuthenticationBackend {
    private final Settings settings;
    private final List<NonCachingAuthenticationBackend> nonCachingAuthBackends;
    protected final Logger log;

    @Inject
    public MultiAuthenticationBackend(Settings settings) {
        String[] backendArray;
        this.log = ESLoggerFactory.getLogger(this.getClass());
        this.settings = settings;
        this.nonCachingAuthBackends = new ArrayList<NonCachingAuthenticationBackend>();
        for (String backend : backendArray = settings.getAsArray(ConfigConstants.ARMOR_AUTHENTICATION_MULTI_AUTH_BACKEND_LIST)) {
            try {
                Class clazz = Class.forName(backend);
                Constructor ctor = clazz.getDeclaredConstructor(Settings.class);
                NonCachingAuthenticationBackend nonCachingBackend = (NonCachingAuthenticationBackend)ctor.newInstance(new Object[]{settings});
                this.nonCachingAuthBackends.add(nonCachingBackend);
                continue;
            }
            catch (ClassNotFoundException ex) {
                this.log.warn("Class " + backendArray + "has not been found ! Skipping this class", ex, new Object[0]);
                continue;
            }
            catch (NoSuchMethodException ex) {
                this.log.warn("Couldn't find suitable constructor for " + backend + " ! Skipping this class", ex, new Object[0]);
                continue;
            }
            catch (InstantiationException ex) {
                this.log.warn("Couldn't instantiate backend " + backend + " ! Skipping this class", ex, new Object[0]);
                continue;
            }
            catch (IllegalAccessException ex) {
                this.log.warn("Couldn't instantiate backend " + backend + " ! Skipping this class", ex, new Object[0]);
                continue;
            }
            catch (IllegalArgumentException ex) {
                this.log.warn("Couldn't instantiate backend " + backend + " ! Skipping this class", ex, new Object[0]);
                continue;
            }
            catch (InvocationTargetException ex) {
                this.log.warn("Couldn't instantiate backend " + backend + " ! Skipping this class", ex, new Object[0]);
            }
        }
    }

    @Override
    public User authenticate(AuthCredentials credentials) throws AuthException {
        ArrayList<AuthException> exceptions = new ArrayList<AuthException>();
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
            }
            catch (AuthException ex) {
                this.log.debug("This backend has not been able to authenticate the user: " + backend.getClass().getName(), ex, new Object[0]);
                exceptions.add(ex);
                continue;
            }
        }
        throw new AuthException("Couldn't authenticate user " + credentials.getUsername() + " against any of the backends.", new MultiAuthException(exceptions));
    }
}

