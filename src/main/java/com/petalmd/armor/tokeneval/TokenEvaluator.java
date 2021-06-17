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

package com.petalmd.armor.tokeneval;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.util.SecurityUtil;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;
import org.elasticsearch.common.bytes.BytesReference;

import java.net.InetAddress;
import java.security.AccessController;
import java.security.PrivilegedExceptionAction;
import java.util.*;

import static com.petalmd.armor.tokeneval.TokenUtil.*;

public class TokenEvaluator {

    private final static ObjectMapper mapper = new ObjectMapper();
    protected static final Logger log = LogManager.getLogger(TokenEvaluator.class);
    protected final BytesReference xSecurityConfiguration;
    protected ACRules acRules = null;

    static {
        mapper.configure(DeserializationFeature.READ_ENUMS_USING_TO_STRING, true);
        mapper.configure(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES, true);
        mapper.configure(DeserializationFeature.FAIL_ON_NUMBERS_FOR_ENUMS, true);
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
        mapper.configure(MapperFeature.CAN_OVERRIDE_ACCESS_MODIFIERS, false);
    }

    public enum FilterAction {

        EXECUTE, BYPASS

    }

    public TokenEvaluator(final BytesReference xSecurityConfiguration) {
        super();

        if (xSecurityConfiguration == null || xSecurityConfiguration.length() == 0) {
            throw new IllegalArgumentException("securityconfiguration must not be null or empty");
        }

        this.xSecurityConfiguration = xSecurityConfiguration;
        log.trace("Configuration: " + xSecurityConfiguration.utf8ToString());
    }

    public RulesEntities findEntitiesForUser(final User user) throws MalformedConfigurationException {
        RulesEntities entities = new RulesEntities();

        initializeACRulesIfNeeded();

        //retrieve entities

        for (ACRule acl : acRules.getAcl()) {
            log.trace("checking rule {}", acl.get__Comment__() != null ? acl.get__Comment__() : "unknown");
            log.trace("acl Users {}, acl Roles {}", acl.getUsers(), acl.getRoles());
            boolean shouldAddEntities = false;
            //check User names
            if (acl.getUsers() != null &&
                    acl.getUsers().stream().anyMatch(
                            (aclUN) -> (aclUN.equals(user.getName()) || (aclUN.contains("*") && SecurityUtil.isWildcardMatch(user.getName(), aclUN, false))))) {
                log.trace("rule user {} matches", acl.getUsers());
                shouldAddEntities = true;
            }
            //check roles
            if (shouldAddEntities == false && !user.getRoles().isEmpty() && acl.getRoles() != null) {
                if (acl.getRoles().stream().anyMatch((r) -> {
                    if (r.contains("*")) {
                        return user.getRoles().stream().anyMatch((ur) -> (SecurityUtil.isWildcardMatch(ur, r, false)));
                    } else {
                        return user.getRoles().contains(r);
                    }
                })) {
                    log.trace("rule roles {} matches", acl.getRoles());

                    shouldAddEntities = true;
                }
            }
            if (shouldAddEntities) {
                if (acl.getAliases() != null && !acl.getAliases().isEmpty()) {
                    entities.addAliases(acl.getAliases());
                }
                if (acl.getIndices() != null && !acl.getIndices().isEmpty()) {
                    entities.addIndices(acl.getIndices());
                }
            }

        }

        return entities;
    }

    protected void initializeACRulesIfNeeded() throws MalformedConfigurationException {
        if (acRules == null) {
            try {
                acRules = AccessController.doPrivileged(new PrivilegedExceptionAction<ACRules>() {

                    @Override
                    public ACRules run() throws Exception {
                        return mapper.readValue(xSecurityConfiguration.toBytesRef().bytes, ACRules.class);
                    }
                });
            } catch (final Exception e) {
                throw new MalformedConfigurationException(e);
            }
        }
    }

    public Evaluator getEvaluator(List<String> requestedIndices, List<String> requestedAliases, List<String> requestedTypes,
                                  final InetAddress requestedHostAddress, final User user) throws MalformedConfigurationException {
        return getEvaluator(requestedIndices, requestedAliases, requestedTypes, requestedHostAddress, user, false);
    }


    private ACRule acRuleIsCorrect(ACRule acRule) throws MalformedConfigurationException {
        if (acRule.getFilters_bypass() == null) {
            throw new MalformedConfigurationException("bypass filters missing");
        }

        if (acRule.getFilters_execute() == null) {
            throw new MalformedConfigurationException("execute filters missing");
        }
        return acRule;
    }

    private boolean acRuleCheckUserOrRole(ACRule acRule, User user) {
        //-- Users -------------------------------------------

        if (acRule.users != null) {
            if (!isStar(acRule.users)) {
                if (containsWildcardPattern(acRule.users, user.getName())) {
                    log.debug("    --> User " + user.getName() + " match");
                    return true;
                } else {
                    log.debug("    User " + user.getName() + " does not match");
                    //we have to check roles then
                }

            } else {
                log.debug("    --> User wildcard match");
                return true;
            }
        }

        //-- Roles -------------------------------------------
        if (acRule.roles != null) {
            if (!isStar(acRule.roles)) {
                for (final String role : acRule.roles) {
                    if (containsWildcardPattern(user.getRoles(), role)) {
                        log.debug("    --> User has role " + role + ", so we have a match");
                        return true;
                    } else {
                        log.debug("    User does not have role " + role);
                    }
                }
            } else {
                log.debug("    --> Role wildcard match");
                return true;
            }
        }
        log.debug("     --> No Users and No Role matched");
        //No user, and no roles matched
        return false;
    }


    private boolean acRuleCheckNetworkOrigin(ACRule acRule, String requestedClientHostName, String requestedClientHostIp) {
        //-- Hosts -------------------------------------------

        if (requestedClientHostIp != null && requestedClientHostName != null && !isNullEmptyStar(acRule.hosts)) {
            for (final String pInetAddress : acRule.hosts) {
                if (SecurityUtil.isWildcardMatch(requestedClientHostName, pInetAddress, false)
                        || SecurityUtil.isWildcardMatch(requestedClientHostIp, pInetAddress, false)) {
                    log.debug("    --> Host address " + pInetAddress + " match");
                    return true;
                }
            }
        } else {
            log.debug("    --> Host wildcard match");
            return true;
        }
        return false;
    }


    private ACRule acRuleMatchAliases(ACRule acRule, Evaluator evaluator, List<String> requestedAliases, boolean indicesLikeAliases) {
        //-- Aliases -------------------------------------------

        Set<String> aliasesToCheck = acRule.aliases != null ? new HashSet<>(acRule.aliases) : new HashSet<>();
        if (indicesLikeAliases) {
            if (acRule.indices != null && !acRule.indices.isEmpty()) {
                aliasesToCheck.addAll(acRule.indices);
            }
        }

        //if it's empty and we request alias, rule do not match, skipp this rule.
        if (aliasesToCheck.isEmpty() && !requestedAliases.isEmpty()) {
            log.debug("we skip alias check since alias(es) are requested but rule do not have alias");
            return acRule;
        }

        if (!isStar(aliasesToCheck)) {
            for (final String requestedAlias : requestedAliases) {
                for (final String pAlias : aliasesToCheck) {
                    if (SecurityUtil.isWildcardMatch(requestedAlias, pAlias, false)) {
                        log.debug("    --> Alias " + requestedAlias + " match " + pAlias + "");
                        evaluator.addAliasFilters(requestedAlias, new EntityFilters(acRule));
                    } else {
                        log.trace("    Alias " + requestedAlias + " does not match " + pAlias + "");
                    }
                }
            }
        } else {
            log.debug("    --> Alias wildcard match");
            log.debug("    ----> APPLY RULE for {} aliases <---- which means the following executeFilters: {}/bypassFilters: {}", requestedAliases.size(), acRule.getFilters_execute(), acRule.getFilters_bypass());
            requestedAliases.stream().forEach(alias -> evaluator.addAliasFilters(alias, new EntityFilters(acRule)));
        }

        return acRule;
    }

    private ACRule acRuleMatchIndices(ACRule acRule, Evaluator evaluator, List<String> requestedIndices) {
        //if it's empty and we request indices, rule do not match, skip this rule.

        if ((acRule.indices == null || acRule.indices.isEmpty()) && !requestedIndices.isEmpty()) {
            log.debug("we skip this rule since indices are requested but rule do not have indices");
            return acRule;
        }

        if (!isStar(acRule.indices)) {
            for (final String requestedIndex : requestedIndices) {

                for (final String pIndex : acRule.indices) {

                    if (SecurityUtil.isWildcardMatch(requestedIndex, pIndex, false)) {
                        log.debug("    -->Index " + requestedIndex + " match " + pIndex + "");
                        evaluator.addIndexFilters(requestedIndex, new EntityFilters(acRule));
                        log.debug("    ----> APPLY RULE for {} <---- which means the following executeFilters: {}/bypassFilters: {}", requestedIndex, acRule.getFilters_execute(), acRule.getFilters_bypass());
                        break;
                    } else {
                        log.trace("    Index " + requestedIndex + " does not match " + pIndex + "");
                    }
                }
            }

        } else {
            log.debug("    --> Index wildcard match");
            log.debug("    ----> APPLY RULE for {} indices <---- which means the following executeFilters: {}/bypassFilters: {}", requestedIndices.size(), acRule.getFilters_execute(), acRule.getFilters_bypass());
            requestedIndices.stream().forEach(index -> evaluator.addIndexFilters(index, new EntityFilters(acRule)));
        }

        return acRule;
    }

    private boolean acRuleFindDefault(ACRule acRule, Evaluator evaluator) {
        if (acRule.isDefault()) {
            evaluator.setDefaultFilter(new EntityFilters(acRule.getFilters_bypass(), acRule.getFilters_execute()));
            log.debug("found Default as rule {}", acRule);
            return false;
        }

        log.debug("will evaluate RULE : {}", acRule);
        return true;
    }

    public Evaluator getEvaluator(final List<String> requestedIndices, final List<String> requestedAliases, List<String> requestedTypes,
                                  final InetAddress requestedHostAddress, final User user, final boolean indicesLikeAliases) throws MalformedConfigurationException {

        final String requestedClientHostName = requestedHostAddress == null ? null : requestedHostAddress.getHostName();
        final String requestedClientHostIp = requestedHostAddress == null ? null : requestedHostAddress.getHostAddress();

        log.debug("user {}", user);
        log.debug("requestedHostAddress: {} OR {}", requestedClientHostIp, requestedClientHostName);
        log.debug("requestedAliases: {}", requestedAliases);
        log.debug("requestedIndices: {}", requestedIndices);
        log.debug("requestedTypes: {}", requestedTypes);

        //initialize ACRules.
        initializeACRulesIfNeeded();

        log.debug("Checking " + (acRules.getAcl().size() - 1) + " rules");

        final List<String> requestedIndicesExp = new ArrayList<>();
        final List<String> requestedAliasesExp = new ArrayList<>();

        if ((requestedIndices == null || requestedIndices.isEmpty()) && (requestedAliases == null || requestedAliases.isEmpty())) {
            log.debug("requestedAliases and requestedIndices are empty, adding '*' for both");
            requestedIndicesExp.add("*");
            requestedAliasesExp.add("*");
        } else {
            requestedIndicesExp.addAll(requestedIndices);
            requestedAliasesExp.addAll(requestedAliases);
        }

        final Evaluator evaluator = new Evaluator(requestedIndicesExp, requestedAliasesExp);

        long acRulesHandled = acRules.acl.stream()
                .map(acRule -> acRuleIsCorrect(acRule))
                .filter(acRule -> acRuleFindDefault(acRule, evaluator))
                .filter(acRule -> acRuleCheckUserOrRole(acRule, user))
                .filter(acRule -> acRuleCheckNetworkOrigin(acRule, requestedClientHostName, requestedClientHostIp))
                .map(acRule -> acRuleMatchAliases(acRule, evaluator, requestedAliasesExp, indicesLikeAliases))
                .map(acRule -> acRuleMatchIndices(acRule, evaluator, requestedIndicesExp)).count();

        if (evaluator.getDefaultFilters() == null) {
            throw new MalformedConfigurationException("No DEFAULT rule found !");
        }

        log.debug("we have examined {} rules", acRulesHandled);


        return evaluator;

    }

    private static boolean typeAndMatch(final String requested, final String granted, final List<String> requestedTypes) {

        log.debug("typeAndMatch(): request {}, granted {}, requestedTypes {}", requested, granted, requestedTypes);

        final String[] grantedA = granted.split(":");

        if (grantedA.length > 1 && (requestedTypes == null || requestedTypes.size() == 0 || requestedTypes.contains("*"))) {
            return false;
        }

        if (SecurityUtil.isWildcardMatch(requested, grantedA[0], false)) {

            log.debug("Wildcard indices/aliases: {} -> {}", requested, grantedA[0]);
            if (grantedA.length > 1) {
                for (final String requestedType : requestedTypes) {
                    if (!SecurityUtil.isWildcardMatch(requestedType, grantedA[1], false)) {
                        log.debug("Wildcard types: {} -> {}", requestedType, grantedA[1]);
                        return false;
                    }
                }

                return true;

            } else {
                //grantedA.length is 1
                log.debug("Wildcard without types: {} -> {}", requested, grantedA[0]);
                return true;
            }

        }

        return false;
    }

    @SuppressWarnings(value = {"unused"})
    public static class ACRules {

        private List<ACRule> acl;

        public final List<ACRule> getAcl() {
            return acl;
        }

        public final void setAcl(final List<ACRule> acl) {
            this.acl = acl;
        }
    }

    @SuppressWarnings(value = {"unused"})
    public static class ACRule {

        private String __Comment__;
        private Set<String> hosts;
        private Set<String> users;
        private Set<String> roles;
        private Set<String> indices;
        private Set<String> aliases;
        private Set<String> filters_execute;
        private Set<String> filters_bypass;

        @JsonIgnore
        public boolean isDefault() {

            return isNullEmptyStar(hosts) && isNullEmptyStar(users) && isNullEmptyStar(roles) && isNullEmptyStar(indices)
                    && isNullEmptyStar(aliases);

        }

        public final String get__Comment__() {
            return __Comment__;
        }

        public final void set__Comment__(final String __Comment__) {
            this.__Comment__ = __Comment__;
        }

        public final Set<String> getHosts() {
            return hosts;
        }

        public final void setHosts(final Set<String> hosts) {
            this.hosts = hosts;
        }

        public final Set<String> getUsers() {
            return users;
        }

        public final void setUsers(final Set<String> users) {
            this.users = users;
        }

        public final Set<String> getRoles() {
            return roles;
        }

        public final void setRoles(final Set<String> roles) {
            this.roles = roles;
        }

        public final Set<String> getIndices() {
            return indices;
        }

        public final void setIndices(final Set<String> indices) {
            this.indices = indices;
        }

        public final Set<String> getAliases() {
            return aliases;
        }

        public final void setAliases(final Set<String> aliases) {
            this.aliases = aliases;
        }

        public final Set<String> getFilters_execute() {
            return filters_execute;
        }

        public final void setFilters_execute(final Set<String> filters_execute) {
            this.filters_execute = filters_execute;
        }

        public final Set<String> getFilters_bypass() {
            return filters_bypass;
        }

        public final void setFilters_bypass(final Set<String> filters_bypass) {
            this.filters_bypass = filters_bypass;
        }

        @Override
        public String toString() {
            return "ACRule [hosts=" + hosts + ", users=" + users + ", roles=" + roles + ", indices=" + indices + ", aliases=" + aliases
                    + ", filters_execute=" + filters_execute + ", filters_bypass=" + filters_bypass + ", isDefault()=" + isDefault()
                    + ", __Comment__=\"" + __Comment__ + "\"]";
        }
    }
}
