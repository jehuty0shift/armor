package com.petalmd.armor.http.netty;

import com.petalmd.armor.authentication.AuthException;
import com.petalmd.armor.util.ArmorConstants;
import io.netty.handler.ssl.SslHandler;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.http.netty4.Netty4HttpChannel;
import org.elasticsearch.http.netty4.Netty4HttpRequest;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;

import javax.net.ssl.SSLPeerUnverifiedException;
import java.security.Principal;

/**
 * Created by jehuty0shift on 06/10/17.
 */
public class SSLPrincipalExtractor {



    public static Principal extractPrincipalfromChannel(RestChannel channel, ThreadContext threadContext) throws AuthException {

        if (channel instanceof Netty4HttpChannel) {
            return null;
        }

        final Netty4HttpChannel netty4Channel = (Netty4HttpChannel)channel;

        final SslHandler sslHandler = (SslHandler)netty4Channel.getNettyChannel().pipeline().get("ssl_http");
        try {
            final Principal principal = sslHandler.engine().getSession().getPeerPrincipal();
            if (threadContext.getTransient(ArmorConstants.ARMOR_SSL_CERT_PRINCIPAL) == null) {
                threadContext.putTransient(ArmorConstants.ARMOR_SSL_CERT_PRINCIPAL, principal);
            }
            return principal;
        } catch (SSLPeerUnverifiedException ex) {
            throw new AuthException("Impossible to validate the peer certificate. aborting",ex);
        }
    }

}
