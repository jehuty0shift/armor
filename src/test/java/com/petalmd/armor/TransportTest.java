package com.petalmd.armor;

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.petalmd.armor.service.ArmorService;
import com.petalmd.armor.util.ConfigConstants;
import com.petalmd.armor.util.SecurityUtil;
import org.apache.http.HttpHost;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.action.admin.cluster.node.info.NodeInfo;
import org.elasticsearch.action.get.GetRequest;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.client.transport.NoNodeAvailableException;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.io.stream.NotSerializableExceptionWrapper;
import org.elasticsearch.common.network.NetworkAddress;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.network.InetAddresses;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.http.HttpInfo;
import org.elasticsearch.index.query.MatchAllQueryBuilder;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import org.elasticsearch.test.ESIntegTestCase;
import org.elasticsearch.transport.Transport;
import org.elasticsearch.transport.TransportInfo;
import org.elasticsearch.transport.client.PreBuiltTransportClient;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@RunWith(RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
@ESIntegTestCase.ClusterScope(scope = ESIntegTestCase.Scope.TEST,numDataNodes = 0, minNumDataNodes = 0)
public class TransportTest extends AbstractArmorTest {

    @Test
    public void sslFail() throws Exception {

        final Settings settings = Settings
                .builder()
                .putList("armor.actionrequestfilter.names", "readonly")
                .putList("armor.actionrequestfilter.readonly.allowed_actions", "indices:data/read/search", "cluster:monitor/health")
                .put("transport.type","armor_ssl_netty4transport")
                .putList("node.roles", "data", "ingest","master")
                .put(ConfigConstants.ARMOR_TRANSPORT_AUTH_ENABLED, true)
                .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_ENABLED, true)
                .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_KEYSTORE_FILEPATH,
                        SecurityUtil.getAbsoluteFilePathFromClassPath("ArmorKS.jks"))
                .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_TRUSTSTORE_FILEPATH,
                        SecurityUtil.getAbsoluteFilePathFromClassPath("ArmorTS.jks"))
                .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_ENFORCE_HOSTNAME_VERIFICATION, false)

                .put(getAuthSettings(false, "ceo")).build();

        startES(settings,false);

        setupTestData("ac_rules_1.json");

        log.debug("------------------------------------------------------------------------------------------------------------------------------------------------------------------------");

        final Settings tSettings = Settings.builder().put("cluster.name", "armor_testcluster")
                .put("client.type", "transport")
                .build();

        final TransportClient tc = new PreBuiltTransportClient(tSettings, Arrays.asList(ArmorPlugin.class))
                .addTransportAddress(
                        new TransportAddress(InetAddress.getByName("127.0.0.1"), returnTransportPort())
                );

        try {
            ensureGreenCustom();
            Assert.fail();
        } catch (final Exception e) {
            Assert.assertTrue(e.getClass().toString(), e instanceof NoNodeAvailableException);
        }

        tc.close();
    }

    @Test
    public void ssl() throws Exception {
        final String[] indices = new String[]{"internal"};

        username = "jacksonm";
        password = "secret";

        final Settings settings = Settings
                .builder()
                .putList("armor.actionrequestfilter.names", "readonly")
                .putList("armor.actionrequestfilter.readonly.allowed_actions", "indices:data/read/search", "cluster:monitor/health")
                .put("transport.type","armor_ssl_netty4transport")
                .put(ConfigConstants.ARMOR_TRANSPORT_AUTH_ENABLED, true)
                .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_ENABLED, true)
                .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_KEYSTORE_FILEPATH,
                        SecurityUtil.getAbsoluteFilePathFromClassPath("ArmorKS.jks"))
                .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_TRUSTSTORE_FILEPATH,
                        SecurityUtil.getAbsoluteFilePathFromClassPath("ArmorTS.jks"))
                .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_ENFORCE_HOSTNAME_VERIFICATION, false)
                .put(getAuthSettings(false, "ceo"))
                .build();

        startES(settings);

        setupTestData("ac_rules_1.json");

        log.debug("------------------------------------------------------------------------------------------------------------------------------------------------------------------------");

        final Settings tsettings = Settings
                .builder()
                .put("cluster.name", "armor_testcluster")
                .put("client.type", "transport")
                .put("transport.type","armor_ssl_netty4transport")
                .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_ENABLED, true)
                .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_KEYSTORE_FILEPATH,
                        SecurityUtil.getAbsoluteFilePathFromClassPath("ArmorKS.jks"))
                .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_TRUSTSTORE_FILEPATH,
                        SecurityUtil.getAbsoluteFilePathFromClassPath("ArmorTS.jks"))
                .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_ENFORCE_HOSTNAME_VERIFICATION, false)
                .build();


        final Client tc = new PreBuiltTransportClient(tsettings, ArmorPlugin.class)
                .addTransportAddress(
                        new TransportAddress(InetAddress.getByName("127.0.0.1"),returnTransportPort())
                );

        ensureGreen();

        final SearchRequest sr = new SearchRequest(indices).source(new SearchSourceBuilder().query(new MatchAllQueryBuilder()));

        Map<String, String> credsMap = new HashMap<>();
        credsMap.put("armor_transport_creds", "amFja3Nvbm06c2VjcmV0");
        Client credClient = tc.filterWithHeader(credsMap);
        final SearchResponse response = credClient.search(sr).actionGet();
        assertSearchResult(response, 7);

        credClient.close();
        tc.close();
    }

    //@Test should re-identify inter cluster request before reactivating this test.
    public void dls() throws Exception {

        username = "jacksonm";
        password = "secret";

        final Settings settings = Settings.builder().putList("armor.dlsfilter.names", "dummy2-only")
                .putList("armor.dlsfilter.dummy2-only", "term", "user", "umberto", "true")
                .put("transport.type","armor_ssl_netty4transport")
                .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_ENABLED, true)
                .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_KEYSTORE_FILEPATH,
                        SecurityUtil.getAbsoluteFilePathFromClassPath("ArmorKS.jks"))
                .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_TRUSTSTORE_FILEPATH,
                        SecurityUtil.getAbsoluteFilePathFromClassPath("ArmorTS.jks"))
                .put(ConfigConstants.ARMOR_TRANSPORT_AUTH_ENABLED, true).put(getAuthSettings(false, "ceo")).build();

        startES(settings);

        setupTestData("ac_rules_execute_all.json");

        final Settings tsettings = Settings.builder().put("cluster.name", "armor_testcluster")
                .put("transport.type","armor_ssl_netty4transport")
                .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_ENABLED, true)
                .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_KEYSTORE_FILEPATH,
                        SecurityUtil.getAbsoluteFilePathFromClassPath("ArmorKS.jks"))
                .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_TRUSTSTORE_FILEPATH,
                        SecurityUtil.getAbsoluteFilePathFromClassPath("ArmorTS.jks"))
                .build();

        final Client tc = null;//new PreBuiltTransportClient(tsettings, ArmorPlugin.class)
//                .addTransportAddress(
//                        new TransportAddress(InetAddress.getByName("127.0.0.1"), elasticsearchNodePort1)
//                );

        ensureGreen();

        final SearchRequest sr = new SearchRequest(new String[]{"ceo", "future"}).source(new SearchSourceBuilder().query(new MatchAllQueryBuilder()));


        Map<String, String> credsMap = new HashMap<>();
        credsMap.put("armor_transport_creds", "amFja3Nvbm06c2VjcmV0");
        Client credClient = tc.filterWithHeader(credsMap);
        final SearchResponse response = credClient.search(sr).actionGet();
        assertSearchResult(response, 2);
        credClient.close();

        tc.close();
    }

    protected final Client newTransportClient() throws IOException {
        final Settings tsettings = Settings.builder().put("cluster.name", "armor_testcluster")
                .put("client.type", "transport")
                .put("transport.type","armor_ssl_netty4transport")
                .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_KEYSTORE_FILEPATH,
                        SecurityUtil.getAbsoluteFilePathFromClassPath("ArmorKS.jks"))
                .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_TRUSTSTORE_FILEPATH,
                        SecurityUtil.getAbsoluteFilePathFromClassPath("ArmorTS.jks"))
                .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_ENFORCE_HOSTNAME_VERIFICATION, false)
                .build();

        final Client tc = null;//new PreBuiltTransportClient(tsettings, ArmorPlugin.class)
//                .addTransportAddress(new TransportAddress(InetAddress.getByName("127.0.0.1"), elasticsearchNodePort1))
//                .addTransportAddress(new TransportAddress(InetAddress.getByName("127.0.0.1"), elasticsearchNodePort2))
//                .addTransportAddress(new TransportAddress(InetAddress.getByName("127.0.0.1"), elasticsearchNodePort1));
//
//        ensureGreen();
        return tc;
    }

    //@Test This test needs to refactor detection of internal cluster requests.
    public void searchOnlyAllowed() throws Exception {
        final String[] indices = new String[]{"internal"};

        username = "jacksonm";
        password = "secret";

        final Settings settings = Settings.builder()
                .put("transport.type","armor_ssl_netty4transport")
                .putList("armor.actionrequestfilter.names", "readonly")
                .putList("armor.actionrequestfilter.readonly.allowed_actions", "indices:data/read/search")
                .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_KEYSTORE_FILEPATH,
                        SecurityUtil.getAbsoluteFilePathFromClassPath("ArmorKS.jks"))
                .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_TRUSTSTORE_FILEPATH,
                        SecurityUtil.getAbsoluteFilePathFromClassPath("ArmorTS.jks"))
                .put(ConfigConstants.ARMOR_TRANSPORT_AUTH_ENABLED, true)
                .put(ConfigConstants.ARMOR_AUDITLOG_ENABLED, false)
                .put(getAuthSettings(false, "ceo"))
                .build();

        startES(settings);

        setupTestData("ac_rules_1.json");

        log.debug("------------------------------------------------------------------------------------------------------------------------------------------------------------------------");

        final Settings tsettings = Settings.builder().put("cluster.name", "armor_testcluster")
                .put("client.type", "transport")
                .put("transport.type","armor_ssl_netty4transport")
                .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_KEYSTORE_FILEPATH,
                        SecurityUtil.getAbsoluteFilePathFromClassPath("ArmorKS.jks"))
                .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_TRUSTSTORE_FILEPATH,
                        SecurityUtil.getAbsoluteFilePathFromClassPath("ArmorTS.jks"))
                .build();

        Map<String, String> credsMap = new HashMap<>();
        credsMap.put("armor_transport_creds", "amFja3Nvbm06c2VjcmV0");

        final Client tc = null;//new PreBuiltTransportClient(tsettings, ArmorPlugin.class)
//                .addTransportAddress(new TransportAddress(InetAddress.getByName("127.0.0.1"), elasticsearchNodePort1))
//                .addTransportAddress(new TransportAddress(InetAddress.getByName("127.0.0.1"), elasticsearchNodePort2))
//                .addTransportAddress(new TransportAddress(InetAddress.getByName("127.0.0.1"), elasticsearchNodePort3))
//                .filterWithHeader(credsMap);
//
//
//        ensureGreen();

        SearchRequest sr = new SearchRequest(indices).source(new SearchSourceBuilder().query(new MatchAllQueryBuilder()));

        SearchResponse response = tc.search(sr).actionGet();
        assertSearchResult(response, 7);

        try {
            final GetRequest getRequest = new GetRequest(indices[0],  "dummy");

            final GetResponse getResponse = newTransportClient().get(getRequest).actionGet();
            Assert.fail();
        } catch (final NotSerializableExceptionWrapper e) {
            if (!e.status().name().equals("FORBIDDEN")) {
                Assert.fail();
            }
        }

        try {
            final IndexRequest indexRequest = new IndexRequest(indices[0]);
            indexRequest.source(new HashMap<String, String>());

            final IndexResponse indexResponse = tc.index(indexRequest).actionGet();
            Assert.fail();
        } catch (final NotSerializableExceptionWrapper e) {
            if (!e.status().name().equals("FORBIDDEN")) {
                Assert.fail();
            }
        }

        try (Client unauthClient = tc.filterWithHeader(new HashMap<>())) {
            unauthClient.index(new IndexRequest(indices[0]).source(new HashMap())).actionGet();
            Assert.fail();
        } catch (final RuntimeException e) {
            Assert.assertTrue(e.getMessage().contains("Unauthenticated request"));
        }

        //authorized internal request
        Map<String, String> internalMap = new HashMap<>();
        internalMap.put("armor_authenticated_transport_request",
                SecurityUtil.encryptAndSerializeObject("authorized", ArmorService.getSecretKey()));
        try (Client internalClient = tc.filterWithHeader(internalMap)) {
            SearchRequest searchRequest = new SearchRequest(indices);
            searchRequest.source(new SearchSourceBuilder().query(new MatchAllQueryBuilder()));

            response = internalClient.search(searchRequest).actionGet();
            assertSearchResult(response, 7);
        }

        //Dummy key
        final SecureRandom secRandom = SecureRandom.getInstance("SHA1PRNG");
        final KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128, secRandom);
        final SecretKey dummyKey = kg.generateKey();
        Map<String, String> dummyMap = new HashMap<>();
        dummyMap.put("armor_authenticated_transport_request", SecurityUtil.encryptAndSerializeObject("authorized", dummyKey));
        try (Client dummyClient = tc.filterWithHeader(dummyMap)) {
            SearchRequest searchRequest = new SearchRequest(indices);
            searchRequest.source(new SearchSourceBuilder().query(new MatchAllQueryBuilder()));

            dummyClient.search(searchRequest).actionGet();
            Assert.fail();
        } catch (final Exception e) {
            Assert.assertTrue(e.getClass().toString(), e instanceof ElasticsearchException);
            Assert.assertTrue(e.getMessage(), e.getMessage().contains("Given final block not properly padded"));
        }

        tc.close();
    }

    protected void assertSearchResult(final SearchResponse response, final int count) {
        Assert.assertNotNull(response);
        Assert.assertEquals(0, response.getFailedShards());
        Assert.assertEquals(count, response.getHits().getTotalHits());
        Assert.assertFalse(response.isTimedOut());
    }

    @Override
    protected boolean addMockTransportService() {
        return false;
    }


    private int returnTransportPort() {
        for (NodeInfo node : nodeInfos) {
            if (node.getInfo(HttpInfo.class) != null && node.getNode().isDataNode() && !node.getNode().isMasterNode()) {
                TransportAddress[] publishAddress = node.getInfo(TransportInfo.class).address().boundAddresses();
                InetSocketAddress address = publishAddress[0].address();
                return address.getPort();
            }
        }
        return -1;
    }
}