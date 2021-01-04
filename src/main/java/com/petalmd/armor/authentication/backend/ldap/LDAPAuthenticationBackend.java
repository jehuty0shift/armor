/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
 * Copyright 2015 PetalMD
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

package com.petalmd.armor.authentication.backend.ldap;

import com.petalmd.armor.authentication.AuthCredentials;
import com.petalmd.armor.authentication.AuthException;
import com.petalmd.armor.authentication.LdapUser;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authentication.backend.NonCachingAuthenticationBackend;
import com.petalmd.armor.util.ConfigConstants;
import com.petalmd.armor.util.SecurityUtil;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapOperationException;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;

import java.io.IOException;
import java.security.AccessController;
import java.security.PrivilegedExceptionAction;

public class LDAPAuthenticationBackend implements NonCachingAuthenticationBackend {

    protected final Logger log = LogManager.getLogger(this.getClass());
    private final Settings settings;

    @Inject
    public LDAPAuthenticationBackend(final Settings settings) {
        this.settings = settings;
    }

    @Override
    public User authenticate(final AuthCredentials authCreds) throws AuthException {

        final String user = authCreds.getUsername();

        final char[] password = authCreds.getPassword();
        authCreds.clear();

        EntryCursor result = null;


        LdapConnection ldapConnection = null;

        try {

            SecurityManager sm = System.getSecurityManager();
            if (sm != null) {
                sm.checkPermission(new SpecialPermission());
            }

            final String bindDn = settings.get(ConfigConstants.ARMOR_AUTHENTICATION_LDAP_BIND_DN, null);

            try {

                ldapConnection = AccessController.doPrivileged(new PrivilegedExceptionAction<LdapConnection>() {
                    @Override
                    public LdapConnection run() throws Exception {
                        return SecurityUtil.getLdapConnection(settings);
                    }
                });
            } catch (final Exception e) {
                log.error(e.toString(), e);
                throw new AuthException("cannot get a valid Ldap Connection", e);
            }

            if (bindDn != null) {
                ldapConnection.bind(bindDn, settings.get(ConfigConstants.ARMOR_AUTHENTICATION_LDAP_PASSWORD, null));
            } else {
                ldapConnection.anonymousBind();
            }

            result = ldapConnection.search(settings.get(ConfigConstants.ARMOR_AUTHENTICATION_LDAP_USERBASE, ""),
                    settings.get(ConfigConstants.ARMOR_AUTHENTICATION_LDAP_USERSEARCH, "(sAMAccountName={0})").replace("{0}", user),
                    SearchScope.SUBTREE);

            if (!result.next()) {
                throw new AuthException("No user " + user + " found", AuthException.ExceptionType.NOT_FOUND);
            }

            final Entry entry = result.get();
            final String dn = entry.getDn().toString();

            if (result.next()) {
                throw new AuthException("More than one user found");
            }

            log.trace("Disconnect {}", bindDn == null ? "anonymous" : bindDn);

            SecurityUtil.releaseConnectionSilently(ldapConnection);

            try {
                ldapConnection = AccessController.doPrivileged(new PrivilegedExceptionAction<LdapConnection>() {
                    @Override
                    public LdapConnection run() throws Exception {
                        return SecurityUtil.getLdapConnection(settings);
                    }
                });
            } catch (final Exception e) {
                log.error(e.toString(), e);
                throw new AuthException("error during second bind", e);
            }

            log.trace("Try to authenticate dn {}", dn);

            ldapConnection.bind(dn, new String(password));

            final String usernameAttribute = settings.get(ConfigConstants.ARMOR_AUTHENTICATION_LDAP_USERNAME_ATTRIBUTE, null);
            String username = dn;

            if (usernameAttribute != null && entry.get(usernameAttribute) != null) {
                username = entry.get(usernameAttribute).getString();
            }

            log.debug("Authenticated username {}", username);

            return new LdapUser(username, entry);

        } catch (LdapOperationException e) {
            log.warn("cannot authenticate due to {}", e);
            throw new AuthException("Cannot authenticate user", AuthException.ExceptionType.NOT_FOUND);
        } catch (final AuthException e) {
            log.debug("Auth exception thrown {}",e.toString());
            throw e;
        } catch (final Exception e) {
            log.error(e.toString(), e);
            throw new AuthException("error during bind with the user credentials", e);
        } finally {
            if (result != null) {
                try {
                    result.close();
                } catch (IOException e) {
                    log.error("Couldn't close result due to IOException: ", e);
                }
            }

            SecurityUtil.releaseConnectionSilently(ldapConnection);
        }

    }

}
