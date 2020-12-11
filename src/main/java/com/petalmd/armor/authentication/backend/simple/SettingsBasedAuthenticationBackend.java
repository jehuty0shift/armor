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

package com.petalmd.armor.authentication.backend.simple;

import com.petalmd.armor.authentication.AuthCredentials;
import com.petalmd.armor.authentication.AuthException;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authentication.backend.NonCachingAuthenticationBackend;
import com.petalmd.armor.util.ConfigConstants;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.StringUtils;
import org.elasticsearch.common.settings.Settings;

import java.util.*;

public class SettingsBasedAuthenticationBackend implements NonCachingAuthenticationBackend {

    private final Settings settings;
    private List<AuthCredentials> authCredsList;

    public SettingsBasedAuthenticationBackend(final Settings settings) {
        this.settings = settings;
        authCredsList = new ArrayList<>();
        List<String> userCreds = settings.getAsList(ConfigConstants.ARMOR_AUTHENTICATION_SETTINGSDB_USERCREDS, Collections.emptyList());
        Settings userGroupSettings = settings.getByPrefix(ConfigConstants.ARMOR_AUTHENTICATION_SETTINGSDB_USER);
        Settings roleGroupSettings = settings.getByPrefix(ConfigConstants.ARMOR_AUTHENTICATION_AUTHORIZATION_SETTINGSDB_ROLES);
        for (String userKey : userGroupSettings.keySet()) {
            String username = userKey;
            String password = userGroupSettings.get(userKey);
            List<String> roles = roleGroupSettings.getAsList(username, Collections.emptyList());
            authCredsList.add(new AuthCredentials(username, roles, password.toCharArray()));
        }
        for (String userCred : userCreds) {
            String user = null;
            List<String> roles = null;
            String password = null;
            //user password roles String has the following syntax user@role1,role2,role3:password
            String[] userRolePassArray = userCred.split(":");
            if (userRolePassArray.length == 2) {
                String userRoles = userRolePassArray[0];
                if (userRoles.contains("@")) {
                    String[] userRoleArray = userRoles.split("@");
                    user = userRoleArray[0];
                    String roleArray = userRoleArray[1];
                    if (roleArray.contains(",")) {
                        roles = Arrays.asList(roleArray.split(","));
                    }
                } else {
                    user = userRoles;
                }
                password = userRolePassArray[1];
            }
            if (user != null && password != null) {
                authCredsList.add(new AuthCredentials(user, roles, password.toCharArray()));
            }
        }
    }

    @Override
    public User authenticate(final com.petalmd.armor.authentication.AuthCredentials authCreds) throws AuthException {
        final String user = authCreds.getUsername();
        final String clearTextPassword = authCreds.getPassword() == null ? null : new String(authCreds.getPassword());
        authCreds.clear();

        String digest = settings.get(ConfigConstants.ARMOR_AUTHENTICATION_SETTINGSDB_DIGEST, null);
        String storedPasswordOrDigest = null;
        for (AuthCredentials authCredentials : authCredsList) {
            if (authCredentials.getUsername().equals(user)) {
                storedPasswordOrDigest = new String(authCredentials.getPassword());
            }
        }

        if (!StringUtils.isEmpty(clearTextPassword) && !StringUtils.isEmpty(storedPasswordOrDigest)) {

            String passwordOrHash = clearTextPassword;

            if (digest != null) {

                digest = digest.toLowerCase(Locale.ENGLISH);

                switch (digest) {

                    case "sha":
                    case "sha1":
                        passwordOrHash = DigestUtils.sha1Hex(clearTextPassword);
                        break;
                    case "sha256":
                        passwordOrHash = DigestUtils.sha256Hex(clearTextPassword);
                        break;
                    case "sha384":
                        passwordOrHash = DigestUtils.sha384Hex(clearTextPassword);
                        break;
                    case "sha512":
                        passwordOrHash = DigestUtils.sha512Hex(clearTextPassword);
                        break;

                    default:
                        passwordOrHash = DigestUtils.md5Hex(clearTextPassword);
                        break;
                }

            }

            if (storedPasswordOrDigest.equals(passwordOrHash)) {
                return new User(user);
            }

        }

        throw new AuthException("No user " + user + " or wrong password (digest: " + (digest == null ? "plain/none" : digest) + ")", AuthException.ExceptionType.NOT_FOUND);
    }
}
