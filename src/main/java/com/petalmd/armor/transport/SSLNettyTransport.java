package com.petalmd.armor.transport;

import com.petalmd.armor.util.ConfigConstants;
import com.petalmd.armor.util.SecurityUtil;
import io.netty.channel.*;
import io.netty.handler.ssl.SslHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.Version;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.common.util.PageCacheRecycler;
import org.elasticsearch.indices.breaker.CircuitBreakerService;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.ConnectTransportException;
import org.elasticsearch.transport.SharedGroupFactory;
import org.elasticsearch.transport.TcpChannel;
import org.elasticsearch.transport.netty4.Netty4Transport;

import javax.net.ssl.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.KeyStore;

/**
 * Created by jehuty0shift on 04/12/17.
 */
public class SSLNettyTransport extends Netty4Transport {

    private final String keystoreType;
    private final String keystoreFilePath;
    private final String keystorePassword;
    private final boolean enforceClientAuth;

    private final String truststoreType;
    private final String truststoreFilePath;
    private final String truststorePassword;

    private final boolean verifyHostname;
    private final boolean resolveHostname;

    private static final Logger log = LogManager.getLogger(SSLNettyTransport.class);

    public static final String TRANSPORT_NAME = "armor_ssl_netty4transport";

    public SSLNettyTransport(Settings settings, Version version, ThreadPool threadPool, NetworkService networkService,
                             PageCacheRecycler pageCacheRecycler, NamedWriteableRegistry namedWriteableRegistry,
                             CircuitBreakerService circuitBreakerService, SharedGroupFactory sharedGroupFactory) {
        super(settings, Version.CURRENT, threadPool, networkService, pageCacheRecycler, namedWriteableRegistry, circuitBreakerService, sharedGroupFactory);
        enforceClientAuth = settings.getAsBoolean(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_ENFORCE_CLIENTAUTH, false);
        keystoreType = settings.get(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_KEYSTORE_TYPE, "JKS");
        keystoreFilePath = settings.get(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_KEYSTORE_FILEPATH, null);
        keystorePassword = settings.get(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_KEYSTORE_PASSWORD, "changeit");
        truststoreType = settings.get(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_TRUSTSTORE_TYPE, "JKS");
        truststoreFilePath = settings.get(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_TRUSTSTORE_FILEPATH, null);
        truststorePassword = settings.get(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_TRUSTSTORE_PASSWORD, "changeit");
        verifyHostname = settings.getAsBoolean(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_ENFORCE_HOSTNAME_VERIFICATION, false);
        resolveHostname = settings.getAsBoolean(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, false);
    }

    @Override
    protected ChannelHandler getServerChannelInitializer(String name) {
        return new SSLServerChannelInitializer(name, enforceClientAuth, keystoreType, keystoreFilePath, keystorePassword, truststoreType, truststoreFilePath, truststorePassword);
    }


    private class SSLServerChannelInitializer extends Netty4Transport.ServerChannelInitializer {

        private final boolean enforceClientAuth;
        private final String keystoreType;
        private final String keystoreFilePath;
        private final String keystorePassword;

        private final String truststoreType;
        private final String truststoreFilePath;
        private final String truststorePassword;

        public SSLServerChannelInitializer(String name, final boolean enforceClientAuth, final String keystoreType, final String keystoreFilePath, final String keystorePassword,
                                           final String truststoreType, final String truststoreFilePath, final String truststorePassword) {
            super(name);
            this.enforceClientAuth = enforceClientAuth;
            this.keystoreFilePath = keystoreFilePath;
            this.keystoreType = keystoreType;
            this.keystorePassword = keystorePassword;
            this.truststoreType = truststoreType;
            this.truststoreFilePath = truststoreFilePath;
            this.truststorePassword = truststorePassword;
        }

        @Override
        protected void initChannel(Channel ch) throws Exception {
            super.initChannel(ch);
            TrustManagerFactory tmf = null;

            if (enforceClientAuth) {

                final KeyStore ts = KeyStore.getInstance(truststoreType);
                try (FileInputStream fIS = new FileInputStream(new File(truststoreFilePath))) {

                    FileInputStream trustStoreFile = fIS;
                    ts.load(trustStoreFile, truststorePassword.toCharArray());
                } catch (IOException ex) {
                    log.warn("Problem during SSL Truststore initialization ", ex);
                }
                tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(ts);
            }

            final KeyStore ks = KeyStore.getInstance(keystoreType);
            try (FileInputStream fIS = new FileInputStream(new File(keystoreFilePath))) {
                ks.load(fIS, keystorePassword.toCharArray());
            } catch (IOException ex) {
                log.warn("Problem during SSL Truststore initialization ", ex);
            }

            final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, keystorePassword.toCharArray());

            final SSLContext serverContext = SSLContext.getInstance("TLS");
            serverContext.init(kmf.getKeyManagers(), tmf == null ? null : tmf.getTrustManagers(), null);
            final SSLEngine engine = serverContext.createSSLEngine();
            final SSLParameters sslParams = new SSLParameters();
            sslParams.setCipherSuites(SecurityUtil.getEnabledSslCiphers());
            sslParams.setProtocols(SecurityUtil.getEnabledSslProtocols());
            sslParams.setNeedClientAuth(enforceClientAuth);
            engine.setSSLParameters(sslParams);
            engine.setUseClientMode(false);

            final SslHandler sslHandler = new SslHandler(engine);
            ch.pipeline().addFirst("ssl_server", sslHandler);
        }
    }


    @Override
    protected ChannelHandler getClientChannelInitializer(DiscoveryNode node) {
        return new SSLClientChannelInitializer(node);
    }


    private class SSLClientChannelInitializer extends ClientChannelInitializer {

        private final SNIHostName sniServerName;

        public SSLClientChannelInitializer(DiscoveryNode node) {

            String advertisedNodeName = node.getAttributes().get("server_name"); //used for compatibility with Elasticsearch SSL conventions.

            if(advertisedNodeName != null && !advertisedNodeName.isEmpty()) {
                try {
                    sniServerName = new SNIHostName(advertisedNodeName);

                } catch (IllegalArgumentException e) {
                    log.error("Invalid server name configured at server_name node attribute or server name or hostname : [" + advertisedNodeName + "]");
                    throw new ConnectTransportException(node, "Invalid server name configured at server_name node attribute or server name or hostname : [" + advertisedNodeName + "]");
                }

            } else {
                sniServerName = null;
            }

        }

        @Override
        protected void initChannel(Channel ch) throws Exception {
            super.initChannel(ch);
            ch.pipeline().addFirst(new SSLClientHandlerInitializer(sniServerName,keystoreType,keystoreFilePath,keystorePassword,truststoreType,truststoreFilePath,truststorePassword,verifyHostname,resolveHostname));
        }
    }

    @Override
    public void onException(TcpChannel channel, Exception e) {
        super.onException(channel, e);
        log.warn("Error on SSL Channel ",e);
    }
}