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

import org.apache.directory.api.ldap.model.entry.Entry;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class LdapUser extends User {

    private static final long serialVersionUID = 1L;
    private final Entry userEntry;
    private final Set<Entry> roleEntries = new HashSet<Entry>();

    public LdapUser(final String name, final Entry userEntry) {
        super(name);
        this.userEntry = userEntry;
    }

    public void addRoleEntry(final Entry entry) {
        roleEntries.add(entry);
    }

    public void addRoleEntries(final Collection<Entry> entries) {
        roleEntries.addAll(entries);
    }

    public Entry getUserEntry() {
        return userEntry;
    }

    public Set<Entry> getRoleEntries() {
        return Collections.unmodifiableSet(roleEntries);
    }

    @Override
    public void copyRolesFrom(final User user) {
        if(user instanceof LdapUser) {
            this.addRoleEntries(((LdapUser) user).getRoleEntries());
            super.copyRolesFrom(user);
        }
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;

        LdapUser ldapUser = (LdapUser) o;

        if (userEntry != null ? !userEntry.equals(ldapUser.userEntry) : ldapUser.userEntry != null) return false;
        return roleEntries != null ? roleEntries.equals(ldapUser.roleEntries) : ldapUser.roleEntries == null;
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + (userEntry != null ? userEntry.hashCode() : 0);
        result = 31 * result + (roleEntries != null ? roleEntries.hashCode() : 0);
        return result;
    }
}
