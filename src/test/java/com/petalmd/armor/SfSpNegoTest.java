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

package com.petalmd.armor;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.petalmd.armor.tests.DummyLoginModule;
import com.petalmd.armor.util.SecurityUtil;
import net.sourceforge.spnego.SpnegoHttpURLConnection;
import org.elasticsearch.action.admin.cluster.node.info.NodeInfo;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.http.HttpInfo;
import org.junit.Assert;
import org.junit.Test;

import java.net.InetSocketAddress;
import java.net.URL;

@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class SfSpNegoTest extends AbstractArmorTest {

    @Test
    public void sfSpNegoTest() throws Exception {

        final Settings settings = Settings
                .builder()
                .putList("armor.actionrequestfilter.names", "readonly")
                .putList("armor.actionrequestfilter.readonly.allowed_actions", "indices:data/read/search")

                .put("armor.authentication.http_authenticator.impl",
                        "com.petalmd.armor.authentication.http.spnego.HTTPSpnegoAuthenticator")
                        .put("armor.authentication.spnego.login_config_filepath", System.getProperty("java.security.auth.login.config"))
                        .put("armor.authentication.spnego.krb5_config_filepath", System.getProperty("java.security.krb5.conf"))

                        .put("armor.authentication.authorizer.impl", "com.petalmd.armor.authorization.ldap.LDAPAuthorizator")
                        .put("armor.authentication.authorizer.cache.enable", "false")
                        .put("armor.authentication.authentication_backend.impl",
                                "com.petalmd.armor.authentication.backend.simple.AlwaysSucceedAuthenticationBackend")
                                .put("armor.authentication.authentication_backend.cache.enable", "false")
                                .putList("armor.authentication.ldap.host", "localhost:" + ldapServerPort)
                                .put("armor.authentication.ldap.usersearch", "(uid={0})")
                                .put("armor.authentication.authorization.ldap.rolesearch", "(uniqueMember={0})")
                                .put("armor.authentication.authorization.ldap.rolename", "cn")
                                .build();

        startES(settings);

        setupTestData("ac_rules_1.json");

        startLDAPServer();
        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif").toFile());


        DummyLoginModule.username = "hnelson";
        DummyLoginModule.password = "secret".toCharArray();

        final net.sourceforge.spnego.SpnegoHttpURLConnection hcon = new SpnegoHttpURLConnection("com.sun.security.jgss.krb5.initiate",
                "hnelson@EXAMPLE.COM", "secret");

        hcon.requestCredDeleg(true);

        int port = 0;
        for (NodeInfo node : nodeInfos) {
            if (node.getInfo(HttpInfo.class) != null && node.getNode().isDataNode() && !node.getNode().isMasterNode()) {
                TransportAddress publishAddress = node.getInfo(HttpInfo.class).address().publishAddress();
                InetSocketAddress address = publishAddress.address();
                port = address.getPort();
                break;
            }
        }

        hcon.connect(new URL("http://localhost" +":"+ port + "/internal/_search"));

        Assert.assertEquals(200, hcon.getResponseCode());

    }

}
