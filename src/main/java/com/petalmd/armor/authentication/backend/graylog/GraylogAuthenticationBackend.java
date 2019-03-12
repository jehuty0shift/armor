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

package com.petalmd.armor.authentication.backend.graylog;

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import com.petalmd.armor.authentication.AuthCredentials;
import com.petalmd.armor.authentication.AuthException;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authentication.backend.NonCachingAuthenticationBackend;
import com.petalmd.armor.util.ConfigConstants;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;

public class GraylogAuthenticationBackend
implements NonCachingAuthenticationBackend {
    private static final Logger log = LogManager.getLogger(GraylogAuthenticationBackend.class);
    private String graylogAPIEndpoint;

    @Inject
    public GraylogAuthenticationBackend(Settings settings) {
        this.graylogAPIEndpoint = settings.get(ConfigConstants.ARMOR_AUTHENTICATION_GRAYLOG_ENDPOINT);
        if (this.graylogAPIEndpoint == null) {
            this.graylogAPIEndpoint = "http://localhost:12900";
        }
        log.info("using following endpoint for Graylog Authentication : " + this.graylogAPIEndpoint, new Object[0]);
        int routesNeeded = settings.getAsInt("http.netty.worker_count",32);
        Unirest.setConcurrency(routesNeeded>200?routesNeeded:200, routesNeeded/2);
    }

    @Override
    public User authenticate(AuthCredentials credentials) throws AuthException {
        String username = credentials.getUsername();
        String password = credentials.getPassword() != null && credentials.getPassword().length > 0 ? new String(credentials.getPassword()) : "";
        try {
            HttpResponse jsonResponse = Unirest.get(this.graylogAPIEndpoint + "/roles").basicAuth(username, password).asJson();
            if (jsonResponse.getStatus() == 401) {
                throw new AuthException("Unauthorized by Graylog");
            }
            if (jsonResponse.getStatus() == 403) {
                String message = ((JsonNode)jsonResponse.getBody()).getObject().getString("message");
                String graylogUsername = message.split("\\[")[1].split("\\]")[0];
                log.debug("identified the User : " + graylogUsername, new Object[0]);
                return new User(graylogUsername);
            }
            if (jsonResponse.getStatus() == 200) {
                return new User("admin");
            }
            log.debug("receive status " + jsonResponse.getStatus() + ". Identification of user failed with: " + jsonResponse.toString());
        }
        catch (UnirestException ex) {
            log.warn("Unirest Exception " + ex.getMessage(), ex);
            throw new AuthException("Graylog Auth Backend Exception", ex);
        }
        throw new AuthException("Unable to retrieve graylog User", AuthException.ExceptionType.NOT_FOUND);
    }
}

