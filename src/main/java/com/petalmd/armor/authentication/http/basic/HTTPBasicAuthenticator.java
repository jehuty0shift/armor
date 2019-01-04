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

package com.petalmd.armor.authentication.http.basic;

import com.petalmd.armor.authentication.AuthCredentials;
import com.petalmd.armor.authentication.AuthException;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authentication.backend.AuthenticationBackend;
import com.petalmd.armor.authentication.http.HTTPAuthenticator;
import com.petalmd.armor.authorization.Authorizator;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;

//TODO FUTURE allow only if protocol==https
public class HTTPBasicAuthenticator implements HTTPAuthenticator {

    protected final Logger log = LogManager.getLogger(this.getClass());
    private final Settings settings;

    @Inject
    public HTTPBasicAuthenticator(final Settings settings) {
        this.settings = settings;
    }

    @Override
    public User authenticate(final RestRequest request, final RestChannel channel, final AuthenticationBackend backend,
                             final Authorizator authorizator, final ThreadContext threadContext) throws AuthException {

        String authorizationHeader = request.header("Authorization");

        if (authorizationHeader != null) {

            if (!authorizationHeader.trim().toLowerCase(Locale.ENGLISH).startsWith("basic ")) {
                throw new AuthException("Bad 'Authorization' header");
            } else {

                final String decodedBasicHeader = new String(Base64.getDecoder().decode(authorizationHeader.split(" ")[1]),
                        StandardCharsets.US_ASCII);

                final String[] decodedBasicHeaderParts = decodedBasicHeader.split(":",2);

                if (decodedBasicHeaderParts.length != 2 || decodedBasicHeaderParts[1] == null) {
                    log.warn("Invalid 'Authorization' header, send 401 and 'WWW-Authenticate Basic'");
                    askAgain(channel);
                    return null;
                } else {

                    final String username = decodedBasicHeaderParts[0];
                    char[] password = decodedBasicHeaderParts[1].toCharArray();

                    final User authenticatedUser = backend.authenticate(new AuthCredentials(username, password));
                    Arrays.fill(password,'\0');

                    authorizator.fillRoles(authenticatedUser, new AuthCredentials(authenticatedUser.getName(), null));

                    log.debug("User '{}' is authenticated", authenticatedUser);

                    return authenticatedUser;
                }
            }

        } else {
            log.trace("No 'Authorization' header, send 401 and 'WWW-Authenticate Basic'");
            askAgain(channel);
            return null;

        }
    }

    private void askAgain(final RestChannel channel) {
        final BytesRestResponse wwwAuthenticateResponse = new BytesRestResponse(RestStatus.UNAUTHORIZED,"{\"error\" : \"Unauthorized\"}");
        wwwAuthenticateResponse.addHeader("WWW-Authenticate", "Basic realm=\"Armor\"");
        channel.sendResponse(wwwAuthenticateResponse);
    }

}
