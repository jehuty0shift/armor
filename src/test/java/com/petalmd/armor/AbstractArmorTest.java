package com.petalmd.armor;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.petalmd.armor.tests.EmbeddedLDAPServer;
import com.petalmd.armor.util.ConfigConstants;
import com.petalmd.armor.util.SecurityUtil;
import joptsimple.internal.Strings;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.http.Header;
import org.apache.http.HttpHost;
import org.apache.http.auth.*;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.auth.NTLMSchemeFactory;
import org.apache.http.impl.auth.SPNegoSchemeFactory;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.nio.client.HttpAsyncClientBuilder;
import org.apache.http.nio.conn.ssl.SSLIOSessionStrategy;
import org.apache.http.ssl.SSLContexts;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.action.DocWriteResponse;
import org.elasticsearch.action.admin.cluster.node.info.NodeInfo;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.action.support.WriteRequest;
import org.elasticsearch.action.support.master.AcknowledgedResponse;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestClientBuilder;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.common.network.NetworkAddress;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.http.HttpInfo;
import org.elasticsearch.index.reindex.ReindexPlugin;
import org.elasticsearch.ingest.common.IngestCommonPlugin;
import org.elasticsearch.painless.PainlessPlugin;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.test.ESIntegTestCase;
import org.elasticsearch.transport.Netty4Plugin;
import org.elasticsearch.transport.nio.NioTransportPlugin;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

import javax.net.ssl.SSLContext;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.net.*;
import java.security.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;

@ESIntegTestCase.ClusterScope(scope = ESIntegTestCase.Scope.TEST, supportsDedicatedMasters = false)
public abstract class AbstractArmorTest extends ESIntegTestCase {

    public static boolean debugAll = false;
    private static final File keytab = new File("target/tmp/keytab.keytab");
    protected static final Gson prettyGson = AccessController.doPrivileged((PrivilegedAction<Gson>) () ->
             new GsonBuilder().setPrettyPrinting().create());
    protected final String clustername = "armor_testcluster";

    protected String username;
    protected String password;
    protected boolean useSpnego = false;
    protected boolean enableSSL = false;


    protected List<NodeInfo> nodeInfos;
    private Header[] headers = new Header[]{};
    protected RestHighLevelClient client;

    protected final Logger log = LogManager.getLogger(AbstractUnitTest.class);


    protected final int ldapServerPort = EmbeddedLDAPServer.ldapPort;
    protected final int ldapsServerPort = EmbeddedLDAPServer.ldapsPort;


    static {

        System.out.println("OS: " + System.getProperty("os.name") + " " + System.getProperty("os.arch") + " "
                + System.getProperty("os.version"));
        System.out.println("Java Version: " + System.getProperty("java.version") + " " + System.getProperty("java.vendor"));
        System.out.println("JVM Impl.: " + System.getProperty("java.vm.version") + " " + System.getProperty("java.vm.vendor") + " "
                + System.getProperty("java.vm.name"));

        if (debugAll) {
            System.setProperty("javax.net.debug", "all");
            System.setProperty("sun.security.krb5.debug", "true");
            System.setProperty("java.security.debug", "all");
        }

        try {

            AccessController.doPrivileged((PrivilegedExceptionAction<Void>) () -> {
                String loginconf = FileUtils.readFileToString(SecurityUtil.getAbsoluteFilePathFromClassPath("login.conf_template").toFile());
                loginconf = loginconf.replace("${debug}", String.valueOf(debugAll)).replace("${hostname}", getNonLocalhostAddress())
                        .replace("${keytab}", keytab.toURI().toString());

                final File loginconfFile = new File("target/tmp/login.conf");

                FileUtils.write(new File("target/tmp/login.conf"), loginconf);

                SecurityUtil.setSystemPropertyToAbsoluteFile("java.security.auth.login.config", loginconfFile.getAbsolutePath());
                SecurityUtil.setSystemPropertyToAbsoluteFilePathFromClassPath("java.security.krb5.conf", "krb5.conf");
                return null;
            });
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Rule
    public final TestWatcher testWatcher = new TestWatcher() {
        @Override
        protected void starting(final Description description) {
            final String methodName = description.getMethodName();
            String className = description.getClassName();
            className = className.substring(className.lastIndexOf('.') + 1);
            System.out.println("---------------- Starting JUnit-test: " + className + " " + methodName + " ----------------");
        }

        @Override
        protected void failed(final Throwable e, final Description description) {
            final String methodName = description.getMethodName();
            String className = description.getClassName();
            className = className.substring(className.lastIndexOf('.') + 1);
            System.out.println(">>>> " + className + " " + methodName + " FAILED due to " + e);
        }

        @Override
        protected void finished(final Description description) {
            //System.out.println("-----------------------------------------------------------------------------------------");
        }

    };


    @Override
    protected Collection<Class<? extends Plugin>> nodePlugins() {

        return List.of(
                getTestTransportPlugin(),
                ArmorPlugin.class,
                NioTransportPlugin.class,
                Netty4Plugin.class,
                ReindexPlugin.class,
                org.elasticsearch.analysis.common.CommonAnalysisPlugin.class,
                PainlessPlugin.class,
                IngestCommonPlugin.class);

    }

    @Override
    protected boolean addMockHttpTransport() {
        return false; // enable http
    }

    public final void startES(final Settings settings) throws Exception {
        //List<Settings> nodesSettings = IntStream.range(0,3).map(i -> getDefaultSettingsBuilder(i).put(settings).build()).collect(Collectors.toList());
        internalCluster().startNodes(3, getDefaultSettingsBuilder().put(settings).build());
        ensureGreen();

        NodesInfoResponse response = internalCluster().client().admin().cluster().prepareNodesInfo().get();
        assertFalse(response.hasFailures());
        nodeInfos = response.getNodes();
    }


    protected final IndexResponse executeIndex(final String file, final String index, final String id,
                                               final boolean mustBeSuccesfull, final boolean connectFromLocalhost) throws Exception {

        if (nodeInfos == null) {
            throw new Exception("Cluster not started");
        }

        List<HttpHost> hosts = new ArrayList<>();
        for (NodeInfo node : nodeInfos) {
            if (node.getInfo(HttpInfo.class) != null && node.getNode().isDataNode() && !node.getNode().isMasterNode()) {
                TransportAddress[] publishAddress = node.getInfo(HttpInfo.class).address().boundAddresses();
                InetSocketAddress address = publishAddress[0].address();
                hosts.add(new HttpHost(NetworkAddress.format(address.getAddress()), address.getPort(), "http"));
            }
        }

        RestClientBuilder clientBuilder;

        HttpHost httpHost;
        if (connectFromLocalhost) {
            httpHost = new HttpHost("127.0.0.1", hosts.get(0).getPort());
        } else {
            httpHost = new HttpHost(getNonLocalhostAddress(),hosts.get(0).getPort());
        }

        clientBuilder = RestClient.builder(httpHost).setHttpClientConfigCallback(hacb -> {
            try {
                return customizeHttpClient(hacb, enableSSL, useSpnego, username, password);
            } catch (Exception e) {
                log.error("Couldn't configure the HTTP Async Client !!!");
                e.printStackTrace();
            }
            return hacb;
        }).setDefaultHeaders(headers);

        client = new RestHighLevelClient(clientBuilder);

        try {

            IndexRequest iReq = new IndexRequest(index)
                    .id(id)
                    .timeout(TimeValue.timeValueMinutes(1))
                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                    .source(loadFile(file), XContentType.JSON);

            IndexResponse iResp = client.index(iReq, RequestOptions.DEFAULT);

            if (mustBeSuccesfull) {
                Assert.assertTrue(iResp.getResult().equals(DocWriteResponse.Result.CREATED));
            }

            return iResp;

        } catch (
                ElasticsearchException ex) {
            if (!mustBeSuccesfull) {
                Assert.assertTrue(!ex.status().equals(RestStatus.OK) && !ex.status().equals(RestStatus.CREATED));
                log.debug("Index operation result fails as expected: " + ex.getDetailedMessage());
            } else {
                log.error("Index operation result: {}", ex.getDetailedMessage());
                throw ex;
            }
        } catch (
                Exception ex) {
            log.error("Operation failed unexpectedly");
            throw ex;
        }

        return null;
    }

    protected final void setupTestData(final String armorConfig) throws Exception {

        executeIndex(armorConfig, "armor", "ac", true, true);


        executeIndex("dummy_content.json", "ceo", "tp_1", true, true);
        executeIndex("dummy_content.json", "cto", "tp_1", true, true);
        executeIndex("dummy_content.json", "marketing", "tp_2", true, true);
        executeIndex("dummy_content.json", "marketing", "tp_3", true, true);
        executeIndex("dummy_content.json", "marketing", "tp_4", true, true);
        executeIndex("dummy_content.json", "marketing_backup", "tp_0", true, true);
        executeIndex("dummy_content.json", "dev", "tp_1", true, true);
        executeIndex("dummy_content.json", "financial", "t2p_5", true, true);
        executeIndex("dummy_content.json", "financial", "t2p_6", true, true);
        executeIndex("dummy_content.json", "financial", "t2p_7", true, true);

        for (int i = 0; i < 30; i++) {
            executeIndex("dummy_content.json", "public", "t2pat_" + i, true, true);
        }

        executeIndex("dummy_content2.json", "future", "f_1", true, true);
        executeIndex("dummy_content2.json", "future", "f_2", true, true);

        AcknowledgedResponse alias1 = internalCluster().client().admin().indices()
                .prepareAliases()
                .addAlias(new String[]{"ceo", "financial"}, "crucial")
                .execute()
                .actionGet();
        Assert.assertTrue(alias1.isAcknowledged());
        AcknowledgedResponse alias2 = internalCluster().client().admin().indices()
                .prepareAliases()
                .addAlias(new String[]{"ceo", "financial", "marketing"}, "internal")
                .execute()
                .actionGet();
        Assert.assertTrue(alias2.isAcknowledged());
        AcknowledgedResponse alias3 = internalCluster().client().admin().indices()
                .prepareAliases()
                .addAlias(new String[]{"ceo", "cto"}, "cxo")
                .execute()
                .actionGet();
        Assert.assertTrue(alias3.isAcknowledged());

        log.info("Cluster Data has been setup");
    }

    protected HttpAsyncClientBuilder customizeHttpClient(HttpAsyncClientBuilder httpClientBuilder, boolean enableSSL, boolean useSpnego, final String username, final String password) throws Exception {
        // http://hc.apache.org/httpcomponents-client-ga/tutorial/html/authentication.html

        final CredentialsProvider credsProvider = new BasicCredentialsProvider();

        if (username != null) {
            credsProvider.setCredentials(new AuthScope(AuthScope.ANY), new UsernamePasswordCredentials(username, password));
        }

        if (useSpnego) {
            //SPNEGO/Kerberos setup
            log.debug("SPNEGO activated");
            final AuthSchemeProvider nsf = new SPNegoSchemeFactory(true, false);//  new NegotiateSchemeProvider();
            final Credentials jaasCreds = new AbstractArmorTest.JaasCredentials();
            credsProvider.setCredentials(new AuthScope(null, -1, null, AuthSchemes.SPNEGO), jaasCreds);
            credsProvider.setCredentials(new AuthScope(null, -1, null, AuthSchemes.NTLM), new NTCredentials("Guest", "Guest", "Guest",
                    "Guest"));
            final Registry<AuthSchemeProvider> authSchemeRegistry = RegistryBuilder.<AuthSchemeProvider>create()
                    .register(AuthSchemes.SPNEGO, nsf).register(AuthSchemes.NTLM, new NTLMSchemeFactory()).build();

            httpClientBuilder.setDefaultAuthSchemeRegistry(authSchemeRegistry);
        }

        httpClientBuilder.setDefaultCredentialsProvider(credsProvider);

        if (enableSSL) {
            log.debug("Configure Rest Client with SSL");

            final KeyStore myTrustStore = KeyStore.getInstance("JKS");
            myTrustStore.load(new FileInputStream(SecurityUtil.getAbsoluteFilePathFromClassPath("ArmorTS.jks").toFile()),
                    "changeit".toCharArray());

            final KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream(SecurityUtil.getAbsoluteFilePathFromClassPath("ArmorKS.jks").toFile()), "changeit".toCharArray());

            final SSLContext sslContext = SSLContexts.custom().loadKeyMaterial(keyStore, "changeit".toCharArray())
                    .loadTrustMaterial(myTrustStore, null).build();

            String[] protocols = SecurityUtil.getEnabledSslProtocols();

            httpClientBuilder.setSSLStrategy(new SSLIOSessionStrategy(sslContext, protocols, SecurityUtil.getEnabledSslCiphers(), NoopHostnameVerifier.INSTANCE));

        }

        httpClientBuilder.setDefaultRequestConfig(RequestConfig.custom().setConnectTimeout(60000).build());

        return httpClientBuilder;

    }


    protected RestHighLevelClient getRestClient(final boolean connectFromLocalhost, final String username, final String password) throws Exception {

        if (nodeInfos == null) {
            throw new Exception("Cluster not started");
        }

        List<HttpHost> hosts = new ArrayList<>();
        for (NodeInfo node : nodeInfos) {
            if (node.getInfo(HttpInfo.class) != null && node.getNode().isDataNode()) {
                TransportAddress publishAddress = node.getInfo(HttpInfo.class).address().publishAddress();
                InetSocketAddress address = publishAddress.address();

                hosts.add(new HttpHost(NetworkAddress.format(address.getAddress()), address.getPort(), "http"));
            }
        }

        HttpHost httpHost;
        if (connectFromLocalhost) {
            httpHost = new HttpHost("localhost", hosts.get(0).getPort());
        } else {
            httpHost = new HttpHost(getNonLocalhostAddress(), hosts.get(0).getPort());
        }

        RestClientBuilder clientBuilder = RestClient.builder(httpHost).setHttpClientConfigCallback(hacb -> {
            try {
                return customizeHttpClient(hacb, enableSSL, useSpnego, username, password);
            } catch (Exception e) {
                log.error("Couldn't configure the HTTP Async Client !!!");
                e.printStackTrace();
            }
            return hacb;
        }).setDefaultHeaders(headers);

        return new RestHighLevelClient(clientBuilder);

    }

    protected Settings getAuthSettings(final boolean wrongPassword, final String... roles) {
        return cacheEnabled(false)
                //.putList("armor.authentication.authorization.settingsdb.roles." + username, roles)
                .putList("armor.authentication.settingsdb.usercreds", username + "@" + Strings.join(roles, ",") + ":" + password + (wrongPassword ? "-wrong" : ""))
//                .put("armor.authentication.settingsdb.user." + username, password + (wrongPassword ? "-wrong" : ""))
                .put("armor.authentication.authorizer.impl",
                        "com.petalmd.armor.authorization.simple.SettingsBasedAuthorizator")
                .put("armor.authentication.authentication_backend.impl",
                        "com.petalmd.armor.authentication.backend.simple.SettingsBasedAuthenticationBackend").build();
    }

    protected Settings.Builder getDefaultSettingsBuilder() {
        //by default ES nodes have all roles (master, data(s),ingest, client cross-cluster-search)
        return Settings.builder()
                //.put("node.name", "armor_testnode_" + nodeNum)//.put("node.data", dataNode)
                .put("network.bind_host", "0.0.0.0")
                .putList("node.roles","data","ingest")
                .put("network.publish_host", "127.0.0.1")
                .put("cluster.name", this.clustername)
                .put(ConfigConstants.ARMOR_ENABLED, true)
                .put(ConfigConstants.ARMOR_KEY_PATH, ".")
                .put(ConfigConstants.ARMOR_ALLOW_ALL_FROM_LOOPBACK, true);

    }



    protected final String loadFile(final String file) throws IOException {

        final StringWriter sw = new StringWriter();
        IOUtils.copy(this.getClass().getResourceAsStream("/" + file), sw);
        return sw.toString();

    }

    protected Settings.Builder cacheEnabled(final boolean cache) {
        return Settings.builder()
                .put("armor.authentication.authorizer.cache.enable", cache)
                .put("armor.authentication.authentication_backend.cache.enable", cache);
    }

    public static String getNonLocalhostAddress() {
        try {
            for (final Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces(); en.hasMoreElements(); ) {
                final NetworkInterface intf = en.nextElement();

                if (intf.isLoopback() || !intf.isUp()) {
                    continue;
                }

                for (final Enumeration<InetAddress> enumIpAddr = intf.getInetAddresses(); enumIpAddr.hasMoreElements(); ) {

                    final InetAddress ia = enumIpAddr.nextElement();

                    if (ia.isLoopbackAddress() || ia instanceof Inet6Address) {
                        continue;
                    }

                    return ia.getHostAddress();
                }
            }
        } catch (final SocketException e) {
            throw new RuntimeException(e);

        }


        System.out.println("ERROR: No non-localhost address available, will use localhost");
        return "localhost";
    }

    private static class JaasCredentials implements Credentials {

        @Override
        public String getPassword() {
            return null;
        }

        @Override
        public Principal getUserPrincipal() {
            return null;
        }
    }
}
