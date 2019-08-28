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

import com.petalmd.armor.service.ArmorConfigService;
import com.petalmd.armor.service.ArmorService;
import com.petalmd.armor.util.ConfigConstants;
import com.petalmd.armor.util.SecurityUtil;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.rest.*;

import java.net.InetAddress;
import java.net.InetSocketAddress;

import static org.elasticsearch.rest.RestRequest.Method.GET;

public class ArmorInfoAction extends BaseRestHandler {

    private final Settings settings;
    private final ArmorConfigService armorConfigService;

    @Inject
    public ArmorInfoAction(final Settings settings, RestController controller,
                           final ArmorConfigService armorConfigService) {
        super(settings);
        controller.registerHandler(GET, "/_armor", this);
        this.armorConfigService = armorConfigService;
        this.settings = settings;
    }

    @Override
    public String getName() {
        return "armor_info_action";
    }

    @Override
    public RestChannelConsumer prepareRequest(final RestRequest request, final NodeClient client) {

        return restChannel -> {


            final boolean isLoopback = ((InetSocketAddress) request.getRemoteAddress()).getAddress().isLoopbackAddress();
            final InetAddress resolvedAddress = SecurityUtil.getProxyResolvedHostAddressFromRequest(request, settings);

            BytesRestResponse response;
            final XContentBuilder builder = restChannel.newBuilder();

            boolean available;
            try {
                final BytesReference securityConfig = armorConfigService.getSecurityConfiguration();
                available = securityConfig != null && securityConfig.length() > 0;
            } catch (ElasticsearchException e) {
                available = false;
            }

            try {

                builder.startObject();

                builder.field("status", "running");
                builder.field("enabled", settings.getAsBoolean(ConfigConstants.ARMOR_ENABLED, false).toString());
                builder.field("isLoopback", isLoopback);
                builder.field("resolvedAddress", resolvedAddress);
                builder.field("available", available);


                builder.endObject();
                if (available) {
                    response = new BytesRestResponse(RestStatus.OK, builder);
                } else {
                    response = new BytesRestResponse(RestStatus.SERVICE_UNAVAILABLE, builder);
                }
            } catch (final Exception e1) {
                builder.startObject();
                builder.field("error", e1.toString());
                builder.endObject();
                response = new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder);
            }
            restChannel.sendResponse(response);
        };
    }

}
