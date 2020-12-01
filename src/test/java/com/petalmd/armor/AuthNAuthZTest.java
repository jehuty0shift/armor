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

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.petalmd.armor.util.SecurityUtil;
import org.apache.http.Header;
import org.apache.http.message.BasicHeader;
import org.elasticsearch.common.settings.Settings;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@RunWith(RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class AuthNAuthZTest extends AbstractScenarioTest {

    public boolean cacheEnabled;

    public boolean wrongPwd;


    @Test
    public void testLdapAuth_TT() throws Exception {
        cacheEnabled = true;
        wrongPwd = true;
        testLdapAuth();
    }

    @Test
    public void testLdapAuth_TF() throws Exception {
        cacheEnabled = true;
        wrongPwd = false;
        testLdapAuth();
    }


    @Test
    public void testLdapAuth_FF() throws Exception {
        cacheEnabled = false;
        wrongPwd = false;
        testLdapAuth();
    }

    @Test
    public void testLdapAuth_FT() throws Exception {
        cacheEnabled = false;
        wrongPwd = true;
        testLdapAuth();
    }

    @Test
    public void testProxyAuth_TF() throws Exception {
        cacheEnabled = true;
        wrongPwd = false;
        testProxyAuth();
    }

    @Test
    public void testProxyAuth_FF() throws Exception {
        cacheEnabled = false;
        wrongPwd = false;
        testProxyAuth();
    }

    public void testLdapAuth() throws Exception {
        //Basic/Ldap/Ldap
        startLDAPServer();
        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif").toFile());

        final Settings settings = cacheEnabled(cacheEnabled)
                .put("armor.authentication.authorizer.impl", "com.petalmd.armor.authorization.ldap.LDAPAuthorizator")
                .put("armor.authentication.authentication_backend.impl",
                        "com.petalmd.armor.authentication.backend.ldap.LDAPAuthenticationBackend")
                .putList("armor.authentication.ldap.host", "localhost:" + ldapServerPort)
                .put("armor.authentication.ldap.usersearch", "(uid={0})")
                .put("armor.authentication.ldap.username_attribute", "uid")
                .put("armor.authentication.authorization.ldap.rolesearch", "(uniqueMember={0})")
                .put("armor.authentication.authorization.ldap.rolename", "cn").build();

        username = "jacksonm";
        password = "secret" + (wrongPwd ? "-wrong" : "");

        searchOnlyAllowed(settings, wrongPwd);
    }

    public void testProxyAuth() throws Exception {
        //Proxy/Always/Ldap
        startLDAPServer();
        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif").toFile());

        final Settings settings = cacheEnabled(cacheEnabled)
                .put("armor.authentication.http_authenticator.impl", "com.petalmd.armor.authentication.http.proxy.HTTPProxyAuthenticator")
                .putList("armor.authentication.proxy.trusted_ips", "*")
                .put("armor.authentication.authorizer.impl", "com.petalmd.armor.authorization.ldap.LDAPAuthorizator")
                .put("armor.authentication.authentication_backend.impl",
                        "com.petalmd.armor.authentication.backend.simple.AlwaysSucceedAuthenticationBackend")
                .putList("armor.authentication.ldap.host", "localhost:" + ldapServerPort)
                .put("armor.authentication.ldap.usersearch", "(uid={0})")
                .put("armor.authentication.ldap.username_attribute", "uid")
                .put("armor.authentication.authorization.ldap.rolesearch", "(uniqueMember={0})")
                .put("armor.authentication.authorization.ldap.rolename", "cn").build();

        Header xAuthUser = new BasicHeader("X-Authenticated-User", "jacksonm" + (wrongPwd ? "-wrong" : ""));
        List<Header> headerList = new ArrayList<>(Arrays.asList(headers));
        headerList.add(xAuthUser);

        headers = headerList.toArray(new Header[headerList.size()]);

        searchOnlyAllowed(settings, wrongPwd);
    }


}
