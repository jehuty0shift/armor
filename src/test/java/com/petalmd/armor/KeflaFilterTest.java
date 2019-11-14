package com.petalmd.armor;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.petalmd.armor.filter.kefla.KeflaUtils;
import com.petalmd.armor.tests.GetFieldMappingsAction;
import com.petalmd.armor.util.ConfigConstants;
import io.searchbox.client.JestClient;
import io.searchbox.client.JestResult;
import io.searchbox.fields.FieldCapabilities;
import io.searchbox.indices.mapping.GetMapping;
import kong.unirest.*;
import org.apache.http.HttpResponse;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.compress.CompressedXContent;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.modules.junit4.PowerMockRunnerDelegate;

import java.util.Arrays;
import java.util.List;

/**
 * Created by jehuty0shift on 11/10/19.
 */

@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
@RunWith(PowerMockRunner.class)
@PowerMockRunnerDelegate(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@PowerMockIgnore({"javax.net.ssl.*", "jdk.internal.reflect.*", "javax.crypto.*", "org.apache.logging.log4j.*", "com.sun.org.apache.xerces.*", "jdk.nashorn.api.scripting.*"})
@PrepareForTest({Unirest.class})
public class KeflaFilterTest extends AbstractScenarioTest {

    @Before
    public void setup() {
        PowerMockito.mockStatic(Unirest.class);
    }

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
                .put(ConfigConstants.ARMOR_KEFLA_PLUGIN_ENDPOINT, "https://localhost:443")
                .put(authSettings).build();

        HttpRequestWithBody httpReq = Mockito.mock(HttpRequestWithBody.class);
        RequestBodyEntity rbe = Mockito.mock(RequestBodyEntity.class);
        Config uniConfig = Mockito.mock(Config.class);
        kong.unirest.HttpResponse<JsonNode> httpRes = Mockito.mock(kong.unirest.HttpResponse.class);


        JsonNode bodyNode = new JsonNode(loadFile("kefla_response_1.json"));
        Mockito.when(httpReq.basicAuth(Mockito.anyString(), Mockito.anyString())).thenReturn(httpReq);
        Mockito.when(httpReq.header(Mockito.anyString(),Mockito.anyString())).thenReturn(httpReq);
        Mockito.when(httpReq.body((Object) Mockito.any())).thenReturn(rbe);

        Mockito.when(rbe.asJson()).thenReturn(httpRes);

        Mockito.when(httpRes.getBody()).thenReturn(bodyNode);

        Mockito.when(Unirest.config()).thenReturn(uniConfig);
        Mockito.when(uniConfig.setObjectMapper(Mockito.any())).thenReturn(uniConfig);
        Mockito.when(Unirest.post(Mockito.anyString())).thenReturn(httpReq);


        startES(settings);

        setupTestDataWithFilteredAliasWithStreams("ac_rules_24.json");

        JestClient client = getJestClient(getServerUri(false), username, password);

        final Tuple<JestResult, HttpResponse> resulttu = ((HeaderAwareJestHttpClient) client).executeE((new GetMapping.Builder())
                .addIndex(indices)
                .build());

        Assert.assertTrue(resulttu.v2().getStatusLine().getStatusCode() == 200);
        Assert.assertTrue(resulttu.v1().isSucceeded());
        Assert.assertTrue(resulttu.v1().getJsonObject()
                .getAsJsonObject("dev")
                .getAsJsonObject("mappings")
                .getAsJsonObject("beta")
                .getAsJsonObject("properties")
                .has("user"));
        Assert.assertFalse(resulttu.v1()
                .getJsonObject()
                .getAsJsonObject("dev")
                .getAsJsonObject("mappings")
                .getAsJsonObject("beta")
                .getAsJsonObject("properties")
                .has("previous_club"));


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
                .put(ConfigConstants.ARMOR_KEFLA_PLUGIN_ENDPOINT, "https://localhost:443")
                .put(authSettings).build();

        HttpRequestWithBody httpReq = Mockito.mock(HttpRequestWithBody.class);
        RequestBodyEntity rbe = Mockito.mock(RequestBodyEntity.class);
        kong.unirest.HttpResponse<JsonNode> httpRes = Mockito.mock(kong.unirest.HttpResponse.class);
        Config uniConfig = Mockito.mock(Config.class);

        JsonNode bodyNode = new JsonNode(loadFile("kefla_response_1.json"));
        Mockito.when(httpReq.basicAuth(Mockito.anyString(), Mockito.anyString())).thenReturn(httpReq);
        Mockito.when(httpReq.header(Mockito.anyString(),Mockito.anyString())).thenReturn(httpReq);
        Mockito.when(httpReq.body((Object) Mockito.any())).thenReturn(rbe);

        Mockito.when(rbe.asJson()).thenReturn(httpRes);

        Mockito.when(httpRes.getBody()).thenReturn(bodyNode);

        Mockito.when(Unirest.config()).thenReturn(uniConfig);
        Mockito.when(uniConfig.setObjectMapper(Mockito.any())).thenReturn(uniConfig);
        Mockito.when(Unirest.post(Mockito.anyString())).thenReturn(httpReq);


        startES(settings);

        setupTestDataWithFilteredAliasWithStreams("ac_rules_24.json");

        JestClient client = getJestClient(getServerUri(false), username, password);

        final Tuple<JestResult, HttpResponse> resulttu = ((HeaderAwareJestHttpClient) client).executeE((new GetFieldMappingsAction.Builder())
                .addIndex(indices)
                .addType("beta")
                .setFields(List.of("user", "previous_club"))
                .build()
        );

        Assert.assertTrue(resulttu.v2().getStatusLine().getStatusCode() == 200);
        Assert.assertTrue(resulttu.v1().isSucceeded());
        Assert.assertTrue(resulttu.v1().getJsonObject()
                .getAsJsonObject("dev")
                .getAsJsonObject("mappings")
                .getAsJsonObject("beta")
                .has("user"));
        Assert.assertFalse(resulttu.v1()
                .getJsonObject()
                .getAsJsonObject("dev")
                .getAsJsonObject("mappings")
                .getAsJsonObject("beta")
                .has("previous_club"));

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
                .put(ConfigConstants.ARMOR_KEFLA_PLUGIN_ENDPOINT, "https://localhost:443")
                .put(authSettings).build();

        HttpRequestWithBody httpReq = Mockito.mock(HttpRequestWithBody.class);
        RequestBodyEntity rbe = Mockito.mock(RequestBodyEntity.class);
        kong.unirest.HttpResponse<JsonNode> httpRes = Mockito.mock(kong.unirest.HttpResponse.class);
        Config uniConfig = Mockito.mock(Config.class);

        JsonNode bodyNode = new JsonNode(loadFile("kefla_response_1.json"));
        Mockito.when(httpReq.basicAuth(Mockito.anyString(), Mockito.anyString())).thenReturn(httpReq);
        Mockito.when(httpReq.header(Mockito.anyString(),Mockito.anyString())).thenReturn(httpReq);
        Mockito.when(httpReq.body((Object) Mockito.any())).thenReturn(rbe);

        Mockito.when(rbe.asJson()).thenReturn(httpRes);

        Mockito.when(httpRes.getBody()).thenReturn(bodyNode);

        Mockito.when(Unirest.config()).thenReturn(uniConfig);
        Mockito.when(uniConfig.setObjectMapper(Mockito.any())).thenReturn(uniConfig);
        Mockito.when(Unirest.post(Mockito.anyString())).thenReturn(httpReq);


        startES(settings);

        setupTestDataWithFilteredAliasWithStreams("ac_rules_24.json");

        JestClient client = getJestClient(getServerUri(false), username, password);

        final Tuple<JestResult, HttpResponse> resulttu = ((HeaderAwareJestHttpClient) client).executeE(new FieldCapabilities.Builder(Arrays.asList("user", "previous_club", "message"))
                .setIndex(indices)
                .build());

        Assert.assertTrue(resulttu.v2().getStatusLine().getStatusCode() == 200);
        Assert.assertTrue(resulttu.v1().getJsonObject()
                .getAsJsonObject("fields")
                .getAsJsonObject("user")
                .getAsJsonObject("text")
                .getAsJsonArray("indices").size() == 1);
        Assert.assertTrue(resulttu.v1().isSucceeded());
        Assert.assertTrue(resulttu.v1().getJsonObject()
                .getAsJsonObject("fields")
                .getAsJsonObject("user")
                .getAsJsonObject("text")
                .getAsJsonArray("indices")
                .get(0)
                .getAsString().equals("dev"));
        Assert.assertTrue(resulttu.v1().getJsonObject()
                .getAsJsonObject("fields")
                .getAsJsonObject("message")
                .has("text"));

        Assert.assertFalse(resulttu.v1().getJsonObject()
                .getAsJsonObject("fields")
                .getAsJsonObject("message")
                .getAsJsonObject("text").has("indices"));
        Assert.assertFalse(resulttu.v1()
                .getJsonObject()
                .getAsJsonObject("fields")
                .has("previous_club"));

    }

}
