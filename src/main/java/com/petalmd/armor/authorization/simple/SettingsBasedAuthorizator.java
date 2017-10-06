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

package com.petalmd.armor.authorization.simple;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;

import com.petalmd.armor.authentication.AuthCredentials;
import com.petalmd.armor.authentication.AuthException;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authorization.NonCachingAuthorizator;
import com.petalmd.armor.util.ConfigConstants;

public class SettingsBasedAuthorizator implements NonCachingAuthorizator {

    private final Settings settings;
    private final List<AuthCredentials> authCredsList;

    @Inject
    public SettingsBasedAuthorizator(final Settings settings) {
        this.settings = settings;
        authCredsList = new ArrayList<>();
        String[] userCreds = settings.getAsArray(ConfigConstants.ARMOR_AUTHENTICATION_SETTINGSDB_USERCREDS, new String[]{});
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
                    roles = Arrays.asList(roleArray.split(","));
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
    public void fillRoles(final User user, final AuthCredentials optionalAuthCreds) throws AuthException {

        for (AuthCredentials authCredentials : authCredsList) {
            if (authCredentials.getUsername().equals(user.getName())) {
                user.addRoles(authCredentials.getRoles());
            }
        }

        final String[] roles = settings.getAsArray(ConfigConstants.ARMOR_AUTHENTICATION_AUTHORIZATION_SETTINGSDB_ROLES+user.getName());
        if (roles != null) {
            for(String role : roles) {
                user.addRole(role);
            }
        }


        if (optionalAuthCreds != null) {
            optionalAuthCreds.clear();
        }
    }
}
