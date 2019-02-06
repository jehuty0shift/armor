package com.petalmd.armor.transport;

import com.petalmd.armor.filter.KibanaHelperFilter;
import com.petalmd.armor.util.SecurityUtil;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.handler.ssl.SslHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.KeyStore;

/**
 * Created by jehuty0shift on 28/01/19.
 */
public class SSLClientHandlerInitializer extends ChannelOutboundHandlerAdapter {

    private final String keystoreType;
    private final String keystoreFilePath;
    private final String keystorePassword;

    private final String truststoreType;
    private final String truststoreFilePath;
    private final String truststorePassword;

    private final boolean resolveHostname;
    private final boolean verifyHostname;

    protected final Logger logger = LogManager.getLogger(SSLClientHandlerInitializer.class);

    public SSLClientHandlerInitializer(SNIHostName sniServerName, final String keystoreType, final String keystoreFilePath, final String keystorePassword,
                                       final String truststoreType, final String truststoreFilePath, final String truststorePassword, final boolean verifyHostname, final boolean resolveHostname) {
        super();
        this.keystoreFilePath = keystoreFilePath;
        this.keystoreType = keystoreType;
        this.keystorePassword = keystorePassword;
        this.truststoreType = truststoreType;
        this.truststoreFilePath = truststoreFilePath;
        this.truststorePassword = truststorePassword;
        this.verifyHostname = verifyHostname;
        this.resolveHostname = resolveHostname;
    }

    @Override
    public void connect(ChannelHandlerContext ctx, SocketAddress remoteAddress, SocketAddress localAddress, ChannelPromise promise) throws Exception {
        TrustManagerFactory tmf = null;
        final SSLContext serverContext;
        if (truststoreFilePath != null && keystoreFilePath != null) {
            final KeyStore ts = KeyStore.getInstance(truststoreType);
            try (FileInputStream fIS = new FileInputStream(new File(truststoreFilePath))) {

                FileInputStream trustStoreFile = fIS;
                ts.load(trustStoreFile, truststorePassword.toCharArray());
            } catch (IOException ex) {
                logger.warn("Problem during SSL Truststore initialization ", ex);
            }
            tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ts);

            final KeyStore ks = KeyStore.getInstance(keystoreType);
            try (FileInputStream fIS = new FileInputStream(new File(keystoreFilePath))) {
                ks.load(fIS, keystorePassword.toCharArray());
            } catch (IOException ex) {
                logger.warn("Problem during SSL Truststore initialization ", ex);
            }

            final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, keystorePassword.toCharArray());


            serverContext = SSLContext.getInstance("TLS");
            serverContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        } else {
            serverContext = SSLContext.getDefault();
        }

        final SSLEngine engine;
        final SSLParameters sslParams = new SSLParameters();

        if (verifyHostname) {
            InetSocketAddress remoteInetSocketAddress = (InetSocketAddress) remoteAddress;
            String hostnameOrHostString = resolveHostname ? remoteInetSocketAddress.getHostName() : remoteInetSocketAddress.getHostString();
            engine = serverContext.createSSLEngine(hostnameOrHostString, remoteInetSocketAddress.getPort());
            if (hostnameOrHostString != null) {
                sslParams.setEndpointIdentificationAlgorithm("HTTPS");
            }
        } else {
            engine = serverContext.createSSLEngine();
        }
        sslParams.setCipherSuites(SecurityUtil.getEnabledSslCiphers());
        sslParams.setProtocols(SecurityUtil.getEnabledSslProtocols());
        engine.setSSLParameters(sslParams);
        engine.setUseClientMode(true);

        ctx.pipeline().replace(this, "ssl", new SslHandler(engine));
        super.connect(ctx, remoteAddress, localAddress, promise);
    }
}