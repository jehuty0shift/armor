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

package com.petalmd.armor.authentication.http.proxy;

import com.petalmd.armor.authentication.AuthCredentials;
import com.petalmd.armor.authentication.AuthException;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authentication.backend.AuthenticationBackend;
import com.petalmd.armor.authentication.http.HTTPAuthenticator;
import com.petalmd.armor.authorization.Authorizator;
import com.petalmd.armor.util.ConfigConstants;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;

import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.List;

public class HTTPProxyAuthenticator implements HTTPAuthenticator {

    protected final Logger log = LogManager.getLogger(this.getClass());
    private final Settings settings;

    @Inject
    public HTTPProxyAuthenticator(final Settings settings) {
        this.settings = settings;
    }

    @Override
    public User authenticate(final RestRequest request, final RestChannel channel, final AuthenticationBackend backend,
                             final Authorizator authorizator, final ThreadContext threadContext) throws AuthException {
        final String headerName = settings.get(ConfigConstants.ARMOR_AUTHENTICATION_PROXY_HEADER, "X-Authenticated-User");
        final List<String> trustedSourceIps = settings.getAsList(
                ConfigConstants.ARMOR_AUTHENTICATION_PROXY_TRUSTED_IPS);

        if (!trustedSourceIps.contains("*")
                && !trustedSourceIps.contains(request.getHttpChannel().getRemoteAddress().getAddress().getHostAddress())) {
            throw new AuthException("source ip not trusted");
        }

        final String proxyUser = request.header(headerName);

        if (proxyUser == null || proxyUser.isEmpty()) {
            throw new AuthException("no or empty " + headerName + " header");
        }

        final User authenticatedUser = backend.authenticate(new AuthCredentials(proxyUser, null));
        authorizator.fillRoles(authenticatedUser, new AuthCredentials(authenticatedUser.getName(), null));

        log.debug("User '{}' is authenticated", authenticatedUser);

        return authenticatedUser;
    }

}
