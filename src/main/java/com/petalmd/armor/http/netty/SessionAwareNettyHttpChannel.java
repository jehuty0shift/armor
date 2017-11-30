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

package com.petalmd.armor.http.netty;

import com.petalmd.armor.authentication.User;
import com.petalmd.armor.http.Session;
import com.petalmd.armor.http.SessionStore;
import com.petalmd.armor.util.ArmorConstants;
import com.petalmd.armor.util.SecurityUtil;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.cookie.Cookie;
import io.netty.handler.codec.http.cookie.CookieEncoder;
import io.netty.handler.codec.http.cookie.DefaultCookie;
import io.netty.handler.codec.http.cookie.ServerCookieEncoder;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.logging.ESLoggerFactory;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.http.netty4.Netty4HttpRequest;
import org.elasticsearch.rest.AbstractRestChannel;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestResponse;
import org.elasticsearch.threadpool.ThreadPool;

public class SessionAwareNettyHttpChannel extends AbstractRestChannel {

    private final Logger log = ESLoggerFactory.getLogger(this.getClass());
    private final SessionStore sessionStore;
    private final RestChannel channel;
    private final ThreadPool threadPool;

    public SessionAwareNettyHttpChannel(final RestChannel channel, final SessionStore sessionStore, final boolean detailedErrorsEnabled, final ThreadPool threadPool) {
        super(channel.request(), detailedErrorsEnabled);
        this.channel = channel;
        this.sessionStore = sessionStore;
        this.threadPool = threadPool;
    }

    @Override
    public void sendResponse(final RestResponse response) {

        if(log.isTraceEnabled()){
            log.trace("sending session Response : " + sessionStore.getSession("null"));
        }
        ThreadContext threadContext = threadPool.getThreadContext();
        final User user = threadContext.getTransient(ArmorConstants.ARMOR_AUTHENTICATED_USER);
        final Session _session = sessionStore.getSession(SecurityUtil.getArmorSessionIdFromCookie(request));

        if (user != null) {
            if (_session == null) {
                final Session session = sessionStore.createSession(user);
                log.trace("Create session and set cookie for {}", user.getName());
                final Cookie cookie = new DefaultCookie(ArmorConstants.ARMOR_ES_ARMOR_SESSION, session.getId());

                //TODO FUTURE check cookie domain/path
                //cookie.setDomain(arg0);
                //cookie.setPath(arg0);
                boolean secure = false;
                if (request instanceof Netty4HttpRequest) {
                    Netty4HttpRequest nettyRequest = (Netty4HttpRequest) request;
                    if (nettyRequest.getChannel().pipeline().get("ssl_http") != null) {
                        secure = true;
                    }
                }

                cookie.setSecure(secure);
                cookie.setMaxAge(60 * 60); //1h
                cookie.setHttpOnly(true);

                response.addHeader("Set-Cookie", ServerCookieEncoder.STRICT.encode(cookie));
            } else {

                //Set-Cookie: token=deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT
                log.trace("There is already a session");
                //TODO FUTURE check cookie seesion validity, expire, ...

            }

        }

        channel.sendResponse(response);
    }

}
