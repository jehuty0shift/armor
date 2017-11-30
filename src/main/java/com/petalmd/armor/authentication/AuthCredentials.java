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

package com.petalmd.armor.authentication;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class AuthCredentials {

    private final String username;
    private final List<String> roles;
    private char[] password;
    private Object nativeCredentials;
    private final int hashCode;

    public AuthCredentials(final String username, final Object nativeCredentials) {
        this(username,new ArrayList<>(), null, nativeCredentials);
    }

    public AuthCredentials(final String username, String role, final char[] password) {
        this(username,Arrays.asList(role), password, null);
    }

    public AuthCredentials(final String username, List<String> roles, final char[] password) {
        this(username,roles, password, null);
    }

    public AuthCredentials(final String username, final char[] password) {
        this(username,new ArrayList<>(), password, null);
    }

    public AuthCredentials(final String username) {
        this(username, new ArrayList<>(), null, null);
    }

    private AuthCredentials(final String username, final List<String> roles, char[] password, Object nativeCredentials) {
        super();

        if (username == null || username.isEmpty()) {
            throw new IllegalArgumentException("username must not be null or empty");
        }

        if(roles == null){
            this.roles = new ArrayList<>();
        } else {
            this.roles = roles;
        }

        this.username = username;
        //make defensive copy
        this.password = password == null ? null : Arrays.copyOf(password, password.length);
        this.nativeCredentials = nativeCredentials;
        hashCode = hashCodeInternal();
    }

    public void clear() {
        if (password != null) {
            Arrays.fill(password, '\0');
            password = null;
        }

        nativeCredentials = null;
    }

    public String getUsername() {
        return username;
    }

    public char[] getPassword() {
        //make defensive copy
        return password == null ? null : Arrays.copyOf(password, password.length);
    }

    public List<String> getRoles() {
        return roles;
    }

    public Object getNativeCredentials() {
        return nativeCredentials;
    }

    @Override
    public int hashCode() {
        return hashCode;
    }

    private int hashCodeInternal() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((nativeCredentials == null) ? 0 : nativeCredentials.hashCode());
        result = prime * result + Arrays.hashCode(password);
        result = prime * result + roles.hashCode();
        result = prime * result + ((username == null) ? 0 : username.hashCode());
        return result;
    }


    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }

        return this.hashCode() == obj.hashCode();
    }

	@Override
	public String toString() {
		return "AuthCredentials [username=" + username + ", "
                + "roles=" + roles.toString() + ", "
                + "hash="+ this.hashCode() +", hasPassword="
                + (password != null) + ", hasNativeCredentials="
                + (nativeCredentials != null) + "]";
    }

}
