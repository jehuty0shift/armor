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

package com.petalmd.armor.http.netty;

import com.petalmd.armor.util.ConfigConstants;
import com.petalmd.armor.util.SecurityUtil;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.ssl.SslHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.http.netty4.Netty4HttpServerTransport;
import org.elasticsearch.threadpool.ThreadPool;

import javax.net.ssl.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;

public class SSLNettyHttpServerTransport extends Netty4HttpServerTransport {

    private final Settings settings;
    private static Logger log = LogManager.getLogger(SSLNettyHttpServerTransport.class);

    @Inject
    public SSLNettyHttpServerTransport(Settings settings, NetworkService networkService, BigArrays bigArrays, ThreadPool threadPool, NamedXContentRegistry xContentRegistry, Dispatcher dispatcher) {
        super(settings, networkService, bigArrays, threadPool, xContentRegistry, dispatcher);
        this.settings = settings;
    }

    @Override
    public ChannelHandler configureServerChannelHandler() {
        return new SSLHttpChannelHandler(this, this.settings, this.detailedErrorsEnabled, threadPool);
    }

    @Override
    protected void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        if (this.lifecycle.started()) {
            log.error("Unexpected error with ArmorSSLNettyHttpServer ", cause);
            ctx.channel().close();
            return;
        }
        super.exceptionCaught(ctx, cause);
    }

    protected static class SSLHttpChannelHandler extends Netty4HttpServerTransport.HttpChannelHandler {

        protected final Logger log = LogManager.getLogger(this.getClass());

        private final String keystoreType;
        private final String keystoreFilePath;
        private final String keystorePassword;
        private final boolean enforceClientAuth;

        private final String truststoreType;
        private final String truststoreFilePath;
        private final String truststorePassword;
        private final ThreadContext threadContext;

        public SSLHttpChannelHandler(final Netty4HttpServerTransport transport, final Settings settings,
                                     final boolean detailedErrorsEnabled, final ThreadPool threadpool) {
            super(transport, detailedErrorsEnabled, threadpool.getThreadContext());
            keystoreType = settings.get(ConfigConstants.ARMOR_SSL_TRANSPORT_HTTP_KEYSTORE_TYPE, "JKS");
            keystoreFilePath = settings.get(ConfigConstants.ARMOR_SSL_TRANSPORT_HTTP_KEYSTORE_FILEPATH, null);
            keystorePassword = settings.get(ConfigConstants.ARMOR_SSL_TRANSPORT_HTTP_KEYSTORE_PASSWORD, "changeit");
            enforceClientAuth = settings.getAsBoolean(ConfigConstants.ARMOR_SSL_TRANSPORT_HTTP_ENFORCE_CLIENTAUTH, false);
            truststoreType = settings.get(ConfigConstants.ARMOR_SSL_TRANSPORT_HTTP_TRUSTSTORE_TYPE, "JKS");
            truststoreFilePath = settings.get(ConfigConstants.ARMOR_SSL_TRANSPORT_HTTP_TRUSTSTORE_FILEPATH, null);
            truststorePassword = settings.get(ConfigConstants.ARMOR_SSL_TRANSPORT_HTTP_TRUSTSTORE_PASSWORD, "changeit");
            this.threadContext = threadpool.getThreadContext();
        }


        @Override
        public void initChannel(Channel ch) throws Exception {

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


            ch.pipeline().addFirst("ssl_http", sslHandler);
            if (enforceClientAuth) {

                ch.pipeline().addBefore("handler", "mutual_ssl", new MutualSSLHandler(threadContext));
                log.debug("Enforce client auth enabled");
            }

            log.trace("SslHandler configured and added to netty pipeline");

        }
    }

}
