/*
 * Copyright 2017 PetalMD
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

package com.petalmd.armor.rest;

import com.petalmd.armor.audit.AuditListener;
import com.petalmd.armor.authentication.AuthException;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authentication.backend.AuthenticationBackend;
import com.petalmd.armor.authentication.http.HTTPAuthenticator;
import com.petalmd.armor.authorization.Authorizator;
import com.petalmd.armor.http.Session;
import com.petalmd.armor.http.SessionStore;
import com.petalmd.armor.util.ArmorConstants;
import com.petalmd.armor.util.ConfigConstants;
import com.petalmd.armor.util.SecurityUtil;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;
import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.*;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

/**
 * Created by Babacar Diassé on 14/09/17.
 */
public class ArmorRestShield {


    private static final Logger log = LogManager.getLogger(ArmorRestShield.class);
    protected final boolean allowAllFromLoopback;
    private final AuthenticationBackend authenticationBackend;
    private final Authorizator authorizator;
    private final ThreadContext threadContext;
    private final Settings additionalRightHeaders;
    private final HTTPAuthenticator httpAuthenticator;
    private final AuditListener auditListener;
    private final SessionStore sessionStore;
    private final Settings settings;

    public ArmorRestShield(Settings settings, AuthenticationBackend authenticationBackend, Authorizator authorizator, HTTPAuthenticator httpAuthenticator, ThreadContext threadContext, AuditListener auditListener, SessionStore sessionStore) {
        this.authorizator = authorizator;
        this.threadContext = threadContext;
        this.authenticationBackend = authenticationBackend;
        this.httpAuthenticator = httpAuthenticator;
        this.auditListener = auditListener;
        this.sessionStore = sessionStore;
        this.settings = settings;
        this.allowAllFromLoopback = settings.getAsBoolean(ConfigConstants.ARMOR_ALLOW_ALL_FROM_LOOPBACK, false);
        this.additionalRightHeaders = settings.getByPrefix(ConfigConstants.ARMOR_HTTP_ADDITIONAL_RIGHTS_HEADER);
    }

    public RestHandler shield(RestHandler original) {

        return (request, channel, client) -> {

            if (requestIsAuthorized(request, channel, client)) {
                original.handleRequest(request, channel, client);
            }
        };
    }


    private boolean requestIsAuthorized(final RestRequest request, final RestChannel channel, NodeClient client) throws Exception {

        final boolean isLoopback = allowAllFromLoopback
                && request.getHttpChannel().getRemoteAddress().getAddress().isLoopbackAddress();

        log.debug("--> Rest request {} {} (loopback?: {})", request.method(), request.path(), isLoopback);
        //log.trace("Context: {}", request.getContext());

        //we always mark the request as external to the cluster.
        threadContext.putTransient(ArmorConstants.ARMOR_REQUEST_IS_EXTERNAL, new AtomicBoolean(true));

        threadContext.putTransient(ArmorConstants.ARMOR_AUDIT_REQUEST_METHOD, request.method());
        threadContext.putTransient(ArmorConstants.ARMOR_AUDIT_REQUEST_URL, request.path());


        //allow all if request is coming from loopback
        if (isLoopback) {
            threadContext.putTransient(ArmorConstants.ARMOR_IS_LOOPBACK, Boolean.TRUE);
            log.debug("This is a connection from localhost/loopback, will allow all");
            return true;
        }


        final InetAddress resolvedAddress = SecurityUtil.getProxyResolvedHostAddressFromRequest(request, settings);
        log.debug("This is a connection from {}", resolvedAddress.getHostAddress());
        threadContext.putTransient(ArmorConstants.ARMOR_RESOLVED_REST_ADDRESS, resolvedAddress);


        if (request.method() == RestRequest.Method.OPTIONS) {
            log.debug("This is a OPTIONS request, will allow");
            return true;
        }

        if (request.method() == RestRequest.Method.GET && request.path().startsWith("/_armor")) {
            log.debug("checking armor status, will allow");
            return true;
        }

        //this is needed because of a authentication attempt with kerberos could be identified as a reply
        if (threadContext.getTransient(ArmorConstants.ARMOR_AUTHENTICATED_USER) != null) {
            log.trace("Already processed, execute directly");
            return true;
        }

        //log.debug("execute filter {}", filterName == null ? "DEFAULT" : filterName);
        if (log.isTraceEnabled()) {
            log.trace("Path: {} {}", request.method(), request.path());

            if (log.isTraceEnabled()) {
                log.trace("Headers: {}", "{ \n" + request.getHeaders().entrySet().stream()
                        .map(e ->  "[" + e.getKey() + ": " + e.getValue().stream().collect(Collectors.joining(",")) + "],")
                        .collect(Collectors.joining(", ")) + "\n}");
            }

            try {
                log.trace("Source: {}", request.content() == null ? "null" : request.content().utf8ToString());
            } catch (final Exception e) {
                log.error("Source content printing generated an Exception", e);
                throw e;
            }
        }



        User sessionUser = null;

        if (settings.getAsBoolean(ConfigConstants.ARMOR_HTTP_ENABLE_SESSIONS, false)) {

            final String sessionId = SecurityUtil.getArmorSessionIdFromCookie(request);

            if (sessionId == null) {
                log.debug("No cookie found, will call authenticator");
            } else {
                final Session session = sessionStore.getSession(sessionId);
                if (session != null) {
                    sessionUser = session.getAuthenticatedUser();
                    log.debug("Found a session {}", session);
                } else {
                    log.warn("Found armor cookie but with invalid id, will call authenticator");
                }
            }

        }

        try {

            if (sessionUser == null) {
                sessionUser = httpAuthenticator.authenticate(request, channel, authenticationBackend, authorizator, threadContext);

                if (sessionUser == null) {
                    log.trace("Authentication not finished");
                    return false;
                } else {
                    log.trace("Authentication finished");
                }

            } else {
                log.debug("User already authenticated earlier in the session");
            }

            final User authenticatedUser = sessionUser;

            log.debug("Authenticated user is {}", authenticatedUser);

            List<String> additionalRightsList = new ArrayList<>();
            for (String addRightKey : additionalRightHeaders.names()) {
                List<String> headerValues = request.getAllHeaderValues(addRightKey);
                if (headerValues != null && !headerValues.isEmpty()) {
                    for (String headerValue : headerValues) {
                        if (headerValue.equals(additionalRightHeaders.get(addRightKey))) {
                            additionalRightsList.add(addRightKey);
                            break;
                        }
                    }
                }
            }

            threadContext.putTransient(ArmorConstants.ARMOR_ADDITIONAL_RIGHTS, additionalRightsList);

            threadContext.putTransient(ArmorConstants.ARMOR_AUTHENTICATED_USER, authenticatedUser);
            return true;

        } catch (final AuthException e1) {
            channel.sendResponse(new BytesRestResponse(channel, RestStatus.FORBIDDEN, e1));
            auditListener.onFailedLogin("unknown", request, threadContext);
            log.error(e1.toString(), e1);
            return false;
        } catch (final Exception e1) {
            log.error(e1.toString(), e1);
            channel.sendResponse(new BytesRestResponse(channel, RestStatus.INTERNAL_SERVER_ERROR, e1));
            throw e1;
        }

    }

}
