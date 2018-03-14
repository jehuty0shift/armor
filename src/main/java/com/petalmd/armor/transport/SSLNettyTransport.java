package com.petalmd.armor.transport;

import com.petalmd.armor.util.ConfigConstants;
import com.petalmd.armor.util.SecurityUtil;
import io.netty.channel.Channel;
import io.netty.handler.ssl.SslHandler;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.indices.breaker.CircuitBreakerService;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.netty4.Netty4Transport;

import javax.net.ssl.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
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


    public SSLNettyTransport(final Settings settings, final ThreadPool threadPool,
                             final NetworkService networkService, final BigArrays bigArrays, final NamedWriteableRegistry namedWriteableRegistry,
                             final CircuitBreakerService circuitBreakerService) {
        super(settings, threadPool, networkService, bigArrays, namedWriteableRegistry, circuitBreakerService);
        keystoreType = settings.get(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_KEYSTORE_TYPE, "JKS");
        keystoreFilePath = settings.get(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_KEYSTORE_FILEPATH, null);
        keystorePassword = settings.get(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_KEYSTORE_PASSWORD, "changeit");
        enforceClientAuth = settings.getAsBoolean(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_ENFORCE_CLIENTAUTH, false);
        truststoreType = settings.get(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_TRUSTSTORE_TYPE, "JKS");
        truststoreFilePath = settings.get(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_TRUSTSTORE_FILEPATH, null);
        truststorePassword = settings.get(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_TRUSTSTORE_PASSWORD, "changeit");

    }


    protected class SSLServerChannelInilizer extends Netty4Transport.ServerChannelInitializer {

        public SSLServerChannelInilizer(String name, Settings settings) {
            super(name, settings);
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
                    logger.warn("Problem during SSL Truststore initialization ",ex);
                }
                tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(ts);
            }

            final KeyStore ks = KeyStore.getInstance(keystoreType);
            try (FileInputStream fIS = new FileInputStream(new File(keystoreFilePath))) {
                ks.load(fIS, keystorePassword.toCharArray());
            } catch (IOException ex) {
                logger.warn("Problem during SSL Truststore initialization ",ex);
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
            ch.pipeline().addFirst("ssl_server",sslHandler);
        }
    }

}