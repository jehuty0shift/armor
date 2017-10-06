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

import javax.net.ssl.SSLHandshakeException;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.http.NoHttpResponseException;
import org.elasticsearch.common.settings.Settings;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.petalmd.armor.util.SecurityUtil;

@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class SslTest extends AbstractScenarioTest {

    @Rule
    public final ExpectedException thrown = ExpectedException.none();

    @Test
    public void testHttps() throws Exception {

        enableSSL = true;

        final Settings settings = Settings
                .builder()
                .put("http.type","armor_ssl_netty4")
                .putArray("armor.authentication.settingsdb.usercreds", "jacksonm@ceo:secret")
                .put("armor.authentication.authorizer.impl",
                        "com.petalmd.armor.authorization.simple.SettingsBasedAuthorizator")
                        .put("armor.authentication.authorizer.cache.enable", "false")
                        .put("armor.authentication.authentication_backend.impl",
                                "com.petalmd.armor.authentication.backend.simple.SettingsBasedAuthenticationBackend")
                                .put("armor.authentication.authentication_backend.cache.enable", "false")
                                .put("armor.ssl.transport.http.enabled", true)
                .put("armor.ssl.transport.http.enforce_clientauth", true)
                                .put("armor.ssl.transport.http.keystore_filepath", SecurityUtil.getAbsoluteFilePathFromClassPath("ArmorKS.jks"))
                                .put("armor.ssl.transport.http.truststore_filepath",
                        SecurityUtil.getAbsoluteFilePathFromClassPath("ArmorTS.jks")).build();

        username = "jacksonm";
        password = "secret";

        searchOnlyAllowed(settings, false);
    }

    @Test
    public void testHttpsFailSSLv3() throws Exception {
        thrown.expect(SSLHandshakeException.class);

        enableSSL = true;
        enableSSLv3Only = true;

        final Settings settings = Settings
                .builder()
                .put("http.type","armor_ssl_netty4")
                .putArray("armor.authentication.settingsdb.usercreds", "jacksonm@ceo:secret")
                .put("armor.authentication.authorizer.impl",
                        "com.petalmd.armor.authorization.simple.SettingsBasedAuthorizator")
                        .put("armor.authentication.authorizer.cache.enable", "false")
                        .put("armor.authentication.authentication_backend.impl",
                                "com.petalmd.armor.authentication.backend.simple.SettingsBasedAuthenticationBackend")
                                .put("armor.authentication.authentication_backend.cache.enable", "false")
                                .put("armor.ssl.transport.http.enabled", true)
                .put("armor.ssl.transport.http.enforce_clientauth", true)
                                .put("armor.ssl.transport.http.keystore_filepath", SecurityUtil.getAbsoluteFilePathFromClassPath("ArmorKS.jks"))
                                .put("armor.ssl.transport.http.truststore_filepath",
                        SecurityUtil.getAbsoluteFilePathFromClassPath("ArmorTS.jks")).build();

        username = "jacksonm";
        password = "secret";

        searchOnlyAllowed(settings, false);
    }

    @Test
    public void testHttpsFail() throws Exception {
        thrown.expect(NoHttpResponseException.class);

        enableSSL = false;

        final Settings settings = Settings
                .builder()
                .put("http.type","armor_ssl_netty4")
                .putArray("armor.authentication.settingsdb.usercreds", "jacksonm@ceo:secret")
                .put("armor.authentication.authorizer.impl",
                        "com.petalmd.armor.authorization.simple.SettingsBasedAuthorizator")
                        .put("armor.authentication.authorizer.cache.enable", "false")
                        .put("armor.authentication.authentication_backend.impl",
                                "com.petalmd.armor.authentication.backend.simple.SettingsBasedAuthenticationBackend")
                                .put("armor.authentication.authentication_backend.cache.enable", "false")
                                .put("armor.ssl.transport.http.enabled", true)
                .put("armor.ssl.transport.http.enforce_clientauth", true)
                                .put("armor.ssl.transport.http.keystore_filepath", SecurityUtil.getAbsoluteFilePathFromClassPath("ArmorKS.jks"))
                                .put("armor.ssl.transport.http.truststore_filepath",
                        SecurityUtil.getAbsoluteFilePathFromClassPath("ArmorTS.jks")).build();

        username = "jacksonm";
        password = "secret";

        searchOnlyAllowed(settings, false);
    }


    @Test
    public void mutualSSLAuthentication() throws Exception {

        enableSSL = true;

        final Settings settings = Settings
                .builder()
                .put("http.type","armor_ssl_netty4")
                .put("armor.authentication.http_authenticator.impl",
                    "com.petalmd.armor.authentication.http.clientcert.HTTPSClientCertAuthenticator")
                .putArray("armor.authentication.authorization.settingsdb.roles.localhost", "ceo")
                .put("armor.authentication.authorizer.impl",
                    "com.petalmd.armor.authorization.simple.SettingsBasedAuthorizator")
                .put("armor.authentication.authorizer.cache.enable", "false")
                .put("armor.authentication.authentication_backend.impl",
                    "com.petalmd.armor.authentication.backend.simple.AlwaysSucceedAuthenticationBackend")
                .put("armor.authentication.authentication_backend.cache.enable", "false")
                .put("armor.ssl.transport.http.enabled", true)
                .put("armor.ssl.transport.http.enforce_clientauth", true)
                .put("armor.ssl.transport.http.keystore_filepath",
                    SecurityUtil.getAbsoluteFilePathFromClassPath("ArmorKS.jks"))
                .put("armor.ssl.transport.http.truststore_filepath",
                    SecurityUtil.getAbsoluteFilePathFromClassPath("ArmorTS.jks"))
                .build();

        searchOnlyAllowed(settings, false);
    }
}
