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

package com.petalmd.armor.authentication.http.clientcert;

import com.petalmd.armor.authentication.AuthCredentials;
import com.petalmd.armor.authentication.AuthException;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authentication.backend.AuthenticationBackend;
import com.petalmd.armor.authentication.http.HTTPAuthenticator;
import com.petalmd.armor.authorization.Authorizator;
import com.petalmd.armor.http.netty.SSLPrincipalExtractor;
import com.petalmd.armor.util.ConfigConstants;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;

import java.security.Principal;
import java.util.Locale;

public class HTTPSClientCertAuthenticator implements HTTPAuthenticator {

    protected final Logger log = LogManager.getLogger(this.getClass());
    private final Settings settings;

    @Inject
    public HTTPSClientCertAuthenticator(final Settings settings) {
        this.settings = settings;
    }

    @SuppressWarnings("restriction")
    @Override
    public User authenticate(final RestRequest request, final RestChannel channel, final AuthenticationBackend backend,
            final Authorizator authorizator, final ThreadContext threadContext) throws AuthException {

        String dn = "";

        Principal x509Principal;
        try {
            x509Principal = SSLPrincipalExtractor.extractPrincipalfromChannel(channel, threadContext);
            if (x509Principal != null) {
                dn = String.valueOf(x509Principal.getName());
                log.debug("principal found was: {}", dn);
            }
        } catch (final Exception e) {
            log.error("Invalid request or invalid principal. Please check settings, this authenticator works only with https/ssl", e);
            throw new AuthException("No x500 principal found in request",e);
        }

        if (dn.isEmpty() || dn.equals("null")) {
            throw new AuthException("No x500 principal found in request");
        }

        final String userAttribute = settings.get(ConfigConstants.ARMOR_AUTHENTICATION_HTTPS_CLIENTCERT_ATTRIBUTENAME, "cn")
                .toLowerCase(Locale.ENGLISH);
        final int index = dn.toLowerCase(Locale.ENGLISH).indexOf(userAttribute + "=");
        String userName = dn;
        if (index > -1) {
            final int start = index + userAttribute.length() + 1;
            userName = dn.substring(start, dn.indexOf(",", start));
        }

        final User authenticatedUser = backend.authenticate(new AuthCredentials(userName, x509Principal));
        authorizator.fillRoles(authenticatedUser, new AuthCredentials(authenticatedUser.getName(), x509Principal));

        log.debug("User '{}' is authenticated", authenticatedUser);

        return authenticatedUser;
    }

}
