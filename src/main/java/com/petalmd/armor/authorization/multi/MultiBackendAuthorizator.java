/*
 * Copyright 2016 PetalMD
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */


package com.petalmd.armor.authorization.multi;

import com.petalmd.armor.authentication.AuthCredentials;
import com.petalmd.armor.authentication.AuthException;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authorization.NonCachingAuthorizator;
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

public class MultiBackendAuthorizator
implements NonCachingAuthorizator {
    private final Settings settings;
    private final List<NonCachingAuthorizator> nonCachingAuthBackends;
    private final Logger log = ESLoggerFactory.getLogger(MultiBackendAuthorizator.class);

    @Inject
    public MultiBackendAuthorizator(Settings settings) {
        String[] backendArray;
        this.settings = settings;
        this.nonCachingAuthBackends = new ArrayList<NonCachingAuthorizator>();
        for (String backend : backendArray = settings.getAsArray(ConfigConstants.ARMOR_AUTHENTICATION_AUTHORIZATION_MULTI_BACKEND_LIST)) {
            try {
                Class clazz = Class.forName(backend);
                Constructor ctor = clazz.getDeclaredConstructor(Settings.class);
                NonCachingAuthorizator nonCachingBackend = (NonCachingAuthorizator)ctor.newInstance(new Object[]{settings});
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
    public void fillRoles(User user, AuthCredentials authCreds) throws AuthException {
        for (NonCachingAuthorizator backend : this.nonCachingAuthBackends) {
            try {
                AuthCredentials copiedCredentials;
                if (authCreds.getPassword() != null) {
                    char[] passwordCopy = Arrays.copyOf(authCreds.getPassword(), authCreds.getPassword().length);
                    copiedCredentials = new AuthCredentials(authCreds.getUsername(), passwordCopy);
                } else {
                    copiedCredentials = authCreds.getNativeCredentials() != null ? new AuthCredentials(authCreds.getUsername(), authCreds.getNativeCredentials()) : new AuthCredentials(authCreds.getUsername());
                }
                this.log.debug("Trying to Authenticate against " + backend.getClass().getName(), new Object[0]);
                backend.fillRoles(user, copiedCredentials);
            }
            catch (AuthException ex) {
                this.log.debug("This backend has not been able to authenticate the user: " + backend.getClass().getName(), ex, new Object[0]);
            }
        }
    }
}

