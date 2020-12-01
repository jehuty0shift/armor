package com.petalmd.armor;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.petalmd.armor.filter.kefla.KeflaUtils;
import com.petalmd.armor.util.ConfigConstants;
import com.sun.net.httpserver.HttpServer;
import org.elasticsearch.action.fieldcaps.FieldCapabilitiesRequest;
import org.elasticsearch.action.fieldcaps.FieldCapabilitiesResponse;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.client.indices.GetFieldMappingsRequest;
import org.elasticsearch.client.indices.GetFieldMappingsResponse;
import org.elasticsearch.client.indices.GetMappingsRequest;
import org.elasticsearch.client.indices.GetMappingsResponse;
import org.elasticsearch.common.compress.CompressedXContent;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.List;

/**
 * Created by jehuty0shift on 11/10/19.
 */

@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class KeflaFilterTest extends AbstractArmorTest {

    @Test
    public void KUtilsStreamFromFilter() throws Exception {
        CompressedXContent filter = new CompressedXContent("{\n" +
                "          \"bool\" : {\n" +
                "            \"should\" : [\n" +
                "              {\n" +
                "                \"term\" : {\n" +
                "                  \"streams\" : \"5b7c2d801d533f00010864b1\"\n" +
                "                }\n" +
                "              }\n" +
                "            ],\n" +
                "            \"minimum_should_match\" : 1\n" +
                "          }\n" +
                "        }");

        List<String> streamIds = KeflaUtils.streamFromFilters(filter);
        Assert.assertEquals(1, streamIds.size());
        Assert.assertEquals("5b7c2d801d533f00010864b1", streamIds.get(0));
    }

    @Test
    public void KUtils2StreamFromFilter() throws Exception {
        CompressedXContent filter = new CompressedXContent("{\n" +
                "          \"bool\" : {\n" +
                "            \"minimum_should_match\" : 1,\n" +
                "            \"should\" : [\n" +
                "              {\n" +
                "                \"term\" : {\n" +
                "                  \"streams\" : \"5cf9278497a7d700019b8052\"\n" +
                "                }\n" +
                "              },\n" +
                "              {\n" +
                "                \"term\" : {\n" +
                "                  \"streams\" : \"5cfa787e97a7d300019cd3c6\"\n" +
                "                }\n" +
                "              }\n" +
                "            ]\n" +
                "          }\n" +
                "        }");

        List<String> streamIds = KeflaUtils.streamFromFilters(filter);
        Assert.assertEquals(2, streamIds.size());
        Assert.assertTrue(streamIds.contains("5cf9278497a7d700019b8052"));
        Assert.assertTrue(streamIds.contains("5cfa787e97a7d300019cd3c6"));
    }


    @Test
    public void getMappingForUnfilteredAlias() throws Exception {
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final String indices = "unfiltered";

        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "reader", "forbidden")
                .putList("armor.actionrequestfilter.reader.allowed_actions", "indices:data/read/field_caps", "indices:data/read/mapping*", "indices:admin/mappings/get", "indices:admin/mappings/fields/get*")
                .putList("armor.actionrequestfilter.forbidden.forbidden_actions", "indices:data*")
                .put(ConfigConstants.ARMOR_KIBANA_HELPER_ENABLED, true)
                .put(ConfigConstants.ARMOR_KEFLA_FILTER_ENABLED, true)
                .put(ConfigConstants.ARMOR_KEFLA_PLUGIN_ENDPOINT, "http://localhost:8080")
                .put(authSettings).build();


        HttpServer httpServer = HttpServer.create(new InetSocketAddress(8080), 0); // or use InetSocketAddress(0) for ephemeral port
        httpServer.createContext("/plugins/com.ovh.graylog/mapping/fields", exchange -> {
            byte[] response = loadFile("kefla_response_1.json").getBytes();
            exchange.sendResponseHeaders(HttpURLConnection.HTTP_OK, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });

        httpServer.start();

        startES(settings);

        setupTestDataWithFilteredAliasWithStreams("ac_rules_24.json");

        RestHighLevelClient client = getRestClient(false, username, password);

        com.fasterxml.jackson.databind.ObjectMapper objMapper = new com.fasterxml.jackson.databind.ObjectMapper();

        GetMappingsResponse gmr1 = client.indices().getMapping(new GetMappingsRequest().indices(indices), RequestOptions.DEFAULT);

        com.fasterxml.jackson.databind.JsonNode jsonNode = objMapper.reader().readTree(gmr1.mappings().get("dev").source().uncompressed().utf8ToString());

        Assert.assertTrue(jsonNode.path("properties").size() > 5);
        Assert.assertTrue(jsonNode.path("properties").has("user"));
        Assert.assertTrue(jsonNode.path("properties").has("previous_club"));

        httpServer.stop(0);

    }

    @Test
    public void getMappingForAlias() throws Exception {
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final String indices = "filtered";

        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "reader", "forbidden")
                .putList("armor.actionrequestfilter.reader.allowed_actions", "indices:data/read/field_caps", "indices:data/read/mapping*", "indices:admin/mappings/get", "indices:admin/mappings/fields/get*")
                .putList("armor.actionrequestfilter.forbidden.forbidden_actions", "indices:data*")
                .put(ConfigConstants.ARMOR_KIBANA_HELPER_ENABLED, true)
                .put(ConfigConstants.ARMOR_KEFLA_FILTER_ENABLED, true)
                .put(ConfigConstants.ARMOR_KEFLA_PLUGIN_ENDPOINT, "http://localhost:8080")
                .put(authSettings).build();

        HttpServer httpServer = HttpServer.create(new InetSocketAddress(8080), 0); // or use InetSocketAddress(0) for ephemeral port
        httpServer.createContext("/plugins/com.ovh.graylog/mapping/fields", exchange -> {
            byte[] response = loadFile("kefla_response_1.json").getBytes();
            exchange.sendResponseHeaders(HttpURLConnection.HTTP_OK, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });

        httpServer.start();

        startES(settings);

        setupTestDataWithFilteredAliasWithStreams("ac_rules_24.json");

        RestHighLevelClient client = getRestClient(false, username, password);

        GetMappingsResponse gmr1 = client.indices().getMapping(new GetMappingsRequest().indices(indices), RequestOptions.DEFAULT);

        com.fasterxml.jackson.databind.ObjectMapper objMapper = new com.fasterxml.jackson.databind.ObjectMapper();

       com.fasterxml.jackson.databind.JsonNode jsonNode = objMapper.reader().readTree(gmr1.mappings().get("dev").source().uncompressed().utf8ToString());

        Assert.assertTrue(jsonNode.path("properties").size() == 5);
        Assert.assertTrue(jsonNode.path("properties").has("user"));
        Assert.assertTrue(jsonNode.path("properties").has("message"));
        Assert.assertFalse(jsonNode.path("properties").has("has_ballon_dor_bool"));

        httpServer.stop(0);
    }


    @Test
    public void getFieldMappingsForAlias() throws Exception {
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final String indices = "filtered";

        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "reader", "forbidden")
                .putList("armor.actionrequestfilter.reader.allowed_actions", "indices:data/read/field_caps", "indices:data/read/mapping*", "indices:admin/mappings/fields/get*")
                .putList("armor.actionrequestfilter.forbidden.forbidden_actions", "indices:data*")
                .put(ConfigConstants.ARMOR_KIBANA_HELPER_ENABLED, true)
                .put(ConfigConstants.ARMOR_KEFLA_FILTER_ENABLED, true)
                .put(ConfigConstants.ARMOR_KEFLA_PLUGIN_ENDPOINT, "http://localhost:8080")
                .put(authSettings).build();

        HttpServer httpServer = HttpServer.create(new InetSocketAddress(8080), 0); // or use InetSocketAddress(0) for ephemeral port
        httpServer.createContext("/plugins/com.ovh.graylog/mapping/fields", exchange -> {
            byte[] response = loadFile("kefla_response_1.json").getBytes();
            exchange.sendResponseHeaders(HttpURLConnection.HTTP_OK, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });

        httpServer.start();


        startES(settings);

        setupTestDataWithFilteredAliasWithStreams("ac_rules_24.json");

        RestHighLevelClient client = getRestClient(false, username, password);

        GetFieldMappingsResponse gFMResp = client.indices().getFieldMapping(new GetFieldMappingsRequest().
                indices(indices)
                .fields("user", "previous_club"),RequestOptions.DEFAULT);


        Assert.assertEquals(1,gFMResp.mappings().size());
        Assert.assertNotNull(gFMResp.fieldMappings("dev","user"));
        //previous club should not be returned
        Assert.assertNull(gFMResp.fieldMappings("dev","previous_club"));

        httpServer.stop(0);
    }


    @Test
    public void getFieldCapabilitiesForAlias() throws Exception {
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final String indices = "filtered";

        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "reader", "forbidden")
                .putList("armor.actionrequestfilter.reader.allowed_actions", "indices:data/read/field_caps", "indices:data/read/mapping*", "indices:admin/mappings/fields/get*")
                .putList("armor.actionrequestfilter.forbidden.forbidden_actions", "indices:data*")
                .put(ConfigConstants.ARMOR_KIBANA_HELPER_ENABLED, true)
                .put(ConfigConstants.ARMOR_KEFLA_FILTER_ENABLED, true)
                .put(ConfigConstants.ARMOR_KEFLA_PLUGIN_ENDPOINT, "http://localhost:8080")
                .put(authSettings).build();

        HttpServer httpServer = HttpServer.create(new InetSocketAddress(8080), 0); // or use InetSocketAddress(0) for ephemeral port
        httpServer.createContext("/plugins/com.ovh.graylog/mapping/fields", exchange -> {
            byte[] response = loadFile("kefla_response_1.json").getBytes();
            exchange.sendResponseHeaders(HttpURLConnection.HTTP_OK, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });

        httpServer.start();

        startES(settings);

        setupTestDataWithFilteredAliasWithStreams("ac_rules_24.json");

        RestHighLevelClient client = getRestClient(false, username, password);

        FieldCapabilitiesResponse fCapResp = client.fieldCaps(new FieldCapabilitiesRequest()
                .indices(indices)
        .fields("user", "previous_club", "message","source_ip_geolocation.geo","source_ip_geolocation"),RequestOptions.DEFAULT);

        Assert.assertEquals(1, fCapResp.getIndices().length);
        Assert.assertTrue(Arrays.stream(fCapResp.getField("user").get("keyword").indices()).allMatch( i -> i.equals("dev")));
        Assert.assertTrue(fCapResp.getField("message").containsKey("text"));
        Assert.assertTrue(Arrays.stream(fCapResp.getField("message").get("text").indices()).allMatch( i -> i.equals("dev")));
        Assert.assertNotNull(fCapResp.getField("source_ip_geolocation.geo"));
        Assert.assertNotNull(fCapResp.getField("source_ip_geolocation"));
        Assert.assertNull(fCapResp.getField("previous_club"));

        httpServer.stop(0);
    }

}
