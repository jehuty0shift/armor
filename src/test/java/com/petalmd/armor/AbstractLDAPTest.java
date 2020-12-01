package com.petalmd.armor;

import com.petalmd.armor.tests.EmbeddedLDAPServer;
import com.petalmd.armor.util.ConfigConstants;
import com.petalmd.armor.util.SecurityUtil;
import joptsimple.internal.Strings;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.http.Header;
import org.apache.http.auth.Credentials;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.admin.cluster.node.info.NodeInfo;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.transport.nio.MockNioTransportPlugin;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.security.AccessController;
import java.security.Principal;
import java.security.PrivilegedExceptionAction;
import java.util.Enumeration;
import java.util.List;

public abstract class AbstractLDAPTest {

    public static boolean debugAll = false;
    private static final File keytab = new File("target/tmp/keytab.keytab");
    protected final String clustername = "armor_testcluster";

    protected String username;
    protected String password;
    protected boolean useSpnego = false;
    protected boolean enableSSL = false;


    protected List<NodeInfo> nodeInfos;
    protected Header[] headers = new Header[]{};
    protected RestHighLevelClient client;

    protected final Logger log = LogManager.getLogger(AbstractLDAPTest.class);

    protected final int ldapServerPort = EmbeddedLDAPServer.ldapPort;
    protected final int ldapsServerPort = EmbeddedLDAPServer.ldapsPort;
    protected EmbeddedLDAPServer ldapServer;


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

    @Before
    public void setUpTest() throws Exception {

        headers = new Header[]{};
        username = password = null;
        enableSSL = false;

    }


    @After
    public void shutDownLDAPServer() throws Exception {

        if (ldapServer != null) {
            ldapServer.stop();
        }

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

    public final void startLDAPServer() throws Exception {

        log.debug("non localhost address: {}", getNonLocalhostAddress());
        AccessController.doPrivileged((PrivilegedExceptionAction<Void>) () -> {
            ldapServer = new EmbeddedLDAPServer();

            keytab.delete();
            ldapServer.createKeytab("krbtgt/EXAMPLE.COM@EXAMPLE.COM", "secret", keytab);
            ldapServer.createKeytab("HTTP/" + getNonLocalhostAddress() + "@EXAMPLE.COM", "httppwd", keytab);
            ldapServer.createKeytab("HTTP/localhost@EXAMPLE.COM", "httppwd", keytab);
            ldapServer.createKeytab("ldap/localhost@EXAMPLE.COM", "randall", keytab);

            ldapServer.start();
            return null;
        });
    }



    protected Settings getAuthSettings(final boolean wrongPassword, final String... roles) {
        return cacheEnabled(false)
                .putList("armor.authentication.settingsdb.usercreds", username + "@" + Strings.join(roles, ",") + ":" + password + (wrongPassword ? "-wrong" : ""))
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
                .putList("node.roles", "data", "ingest")
                .put("network.publish_host", "127.0.0.1")
                .put("cluster.name", this.clustername)
                .put("transport.type", MockNioTransportPlugin.MOCK_NIO_TRANSPORT_NAME)
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
