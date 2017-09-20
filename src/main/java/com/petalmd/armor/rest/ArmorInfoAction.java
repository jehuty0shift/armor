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

package com.petalmd.armor.rest;

import static org.elasticsearch.rest.RestRequest.Method.GET;

import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.elasticsearch.client.Client;
import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.rest.BaseRestHandler;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;

import com.petalmd.armor.ArmorPlugin;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authentication.backend.AuthenticationBackend;
import com.petalmd.armor.authentication.http.HTTPAuthenticator;
import com.petalmd.armor.authorization.Authorizator;
import com.petalmd.armor.service.ArmorService;
import com.petalmd.armor.util.SecurityUtil;

public class ArmorInfoAction extends BaseRestHandler {

    private final ArmorService service;

    @Inject
    public ArmorInfoAction(final Settings settings, RestController controller,
                           final ArmorService service) {
        super(settings);
        controller.registerHandler(GET, "/_armor", this);
        this.service = service;
    }

    @Override
    public RestChannelConsumer prepareRequest(final RestRequest request, final NodeClient client) {

        return new RestChannelConsumer() {

            @Override
            public void accept(RestChannel restChannel) throws Exception {


                final boolean isLoopback = ((InetSocketAddress) request.getRemoteAddress()).getAddress().isLoopbackAddress();
                final InetAddress resolvedAddress = SecurityUtil.getProxyResolvedHostAddressFromRequest(request, settings);

//                final Authorizator authorizator = service.getAuthorizator();
//                final AuthenticationBackend authenticationBackend = service.getAuthenticationBackend();
//                final HTTPAuthenticator httpAuthenticator = service.getHttpAuthenticator();

                BytesRestResponse response;
                final XContentBuilder builder = restChannel.newBuilder();

                try {

                    //TODO : To Delete ? Authentication is done in REST Wrapper
//
//                    final User authenticatedUser = httpAuthenticator.authenticate(request, restChannel, authenticationBackend, authorizator);
//
//                    if (authenticatedUser == null) {
//
//                    }

                    builder.startObject();

                    builder.field("armor.status", "running");
//                    builder.field("armor.dls.supported", ArmorPlugin.DLS_SUPPORTED);
//                    builder.field("armor.fls.supported", ArmorPlugin.DLS_SUPPORTED);
                    builder.field("armor.isloopback", isLoopback);
                    builder.field("armor.resolvedaddress", resolvedAddress);
//                    builder.field("armor.authenticated_user", authenticatedUser.getName());

//                    builder.field("armor.roles", authenticatedUser.getRoles());

                    builder.endObject();

                    response = new BytesRestResponse(RestStatus.OK, builder);
                } catch (final Exception e1) {
                    builder.startObject();
                    builder.field("error", e1.toString());
                    builder.endObject();
                    response = new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder);
                }

                final BytesRestResponse finalResponse = response;
                restChannel.sendResponse(response);
            }
        };
    }

}
