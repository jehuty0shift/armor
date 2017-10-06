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

import com.petalmd.armor.util.ArmorConstants;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.ssl.SslHandler;
import io.netty.util.ReferenceCountUtil;
import org.elasticsearch.common.util.concurrent.ThreadContext;

import java.security.Principal;

public class MutualSSLHandler extends SimpleChannelInboundHandler<Object> {

    private ThreadContext threadContext;

    MutualSSLHandler(ThreadContext threadContext) {
        super();
        this.threadContext = threadContext;
    }


    @Override
    protected void channelRead0(ChannelHandlerContext ctx, Object msg) throws Exception {
//        Object transientObj = threadContext.getTransient(ArmorConstants.ARMOR_SSL_CERT_PRINCIPAL);
//        if (transientObj == null) {
//            final SslHandler sslHandler = (SslHandler) ctx.channel().pipeline().get("ssl_http");
//            final Principal principal = sslHandler.engine().getSession().getPeerCertificateChain()[0].getSubjectDN();
//
//            threadContext.putTransient(ArmorConstants.ARMOR_SSL_CERT_PRINCIPAL, principal);
//        }
        ReferenceCountUtil.retain(msg);
        ctx.fireChannelRead(msg);
    }

}
