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
import com.petalmd.armor.util.ConfigConstants;
import com.petalmd.armor.util.SecurityUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.rest.*;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.elasticsearch.rest.RestRequest.Method.GET;
import static org.elasticsearch.rest.RestRequest.Method.POST;

public class ArmorInfoAction extends BaseRestHandler {

    private final Settings settings;
    private final ArmorConfigService armorConfigService;
    private static final Logger log = LogManager.getLogger(ArmorInfoAction.class);
    private static final AtomicBoolean available = new AtomicBoolean(true);


    @Inject
    public ArmorInfoAction(final Settings settings, RestController controller,
                           final ArmorConfigService armorConfigService) {
        super();
        this.armorConfigService = armorConfigService;
        this.settings = settings;
    }

    @Override
    public String getName() {
        return "armor_info_action";
    }

    @Override
    public List<Route> routes() {
        return List.of(
                new Route(GET, "/_armor"),
                new Route(POST, "/_armor/local/maintenance"));
    }


    @Override
    public RestChannelConsumer prepareRequest(final RestRequest request, NodeClient nodeClient) {

        return restChannel -> {
            if (request.method().equals(GET)) {
                processGET(restChannel, request);
            } else if (request.method().equals(POST)) {
                processPOST(restChannel, request);
            }


        };
    }


    public void processGET(RestChannel restChannel, RestRequest request) throws IOException {
        final boolean isLoopback = request.getHttpChannel().getRemoteAddress().getAddress().isLoopbackAddress();
        final InetAddress resolvedAddress = SecurityUtil.getProxyResolvedHostAddressFromRequest(request, settings);

        BytesRestResponse response;
        final XContentBuilder builder = restChannel.newBuilder();

        boolean hasSecurityConf;
        log.debug("retrieving Security Configuration...");
        try {
            final BytesReference securityConfig = armorConfigService.getSecurityConfiguration();
            hasSecurityConf = securityConfig != null && securityConfig.length() > 0;
        } catch (ElasticsearchException e) {
            hasSecurityConf = false;
        }
        log.debug("retrieved Security Configuration.");

        try {

            builder.startObject();

            final Boolean enabled = settings.getAsBoolean(ConfigConstants.ARMOR_ENABLED, false);
            builder.field("enabled", enabled.toString());
            builder.field("isLoopback", isLoopback);
            builder.field("resolvedAddress", resolvedAddress.toString());
            //availability depends on maintenance local mode
            builder.field("available", available.get() ? hasSecurityConf : false);
            log.debug("enabled {}, isLoopback {}, resolvedAddress {}, available {}", enabled, isLoopback, resolvedAddress, hasSecurityConf);
            builder.endObject();
            if (!available.get()) {
                response = new BytesRestResponse(RestStatus.GONE, builder);
            } else {
                //should be available
                if (hasSecurityConf) {
                    response = new BytesRestResponse(RestStatus.OK, builder);
                } else {
                    response = new BytesRestResponse(RestStatus.SERVICE_UNAVAILABLE, builder);
                }
            }
        } catch (final Exception e1) {
            builder.startObject();
            builder.field("error", e1.toString());
            builder.endObject();
            response = new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder);
        }
        log.debug("Armor available: {}", hasSecurityConf);
        restChannel.sendResponse(response);

    }

    public void processPOST(RestChannel restChannel, RestRequest restRequest) throws IOException {

        BytesRestResponse response;
        final XContentBuilder builder = restChannel.newBuilder();

        if (!restRequest.hasContent()) {
            builder.startObject();
            builder.field("error", "maintenance call needs a payload");
            builder.endObject();

            response = new BytesRestResponse(RestStatus.BAD_REQUEST, builder);
            restChannel.sendResponse(response);
            return;
        }

        XContentParser contentParser = restRequest.contentParser();
        if (XContentParser.Token.START_OBJECT == contentParser.nextToken()) {
            while (XContentParser.Token.END_OBJECT != contentParser.nextToken()) {
                if (XContentParser.Token.FIELD_NAME == contentParser.currentToken()) {
                    String currentFieldName = contentParser.currentName();
                    if ("maintenance_enabled".equals(currentFieldName)) {
                        if (XContentParser.Token.VALUE_BOOLEAN == contentParser.nextToken()) {
                            available.set(!contentParser.booleanValue());
                            builder.startObject();
                            builder.field("acknowledged", true);
                            builder.endObject();
                            response = new BytesRestResponse(RestStatus.OK, builder);
                            restChannel.sendResponse(response);
                            return;
                        }
                    }
                }
            }
        }

        builder.startObject();
        builder.field("error", "the content is not right (expected field 'maintenance_enabled'");
        builder.endObject();
        response = new BytesRestResponse(RestStatus.BAD_REQUEST, builder);

        restChannel.sendResponse(response);

    }
}
