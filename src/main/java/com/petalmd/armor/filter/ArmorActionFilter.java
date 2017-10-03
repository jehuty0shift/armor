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
package com.petalmd.armor.filter;

import com.petalmd.armor.ArmorPlugin;
import com.petalmd.armor.audit.AuditListener;
import com.petalmd.armor.authentication.AuthException;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authentication.backend.AuthenticationBackend;
import com.petalmd.armor.authorization.Authorizator;
import com.petalmd.armor.authorization.ForbiddenException;
import com.petalmd.armor.service.ArmorConfigService;
import com.petalmd.armor.service.ArmorService;
import com.petalmd.armor.tokeneval.RulesEntities;
import com.petalmd.armor.tokeneval.TokenEvaluator;
import com.petalmd.armor.tokeneval.TokenEvaluator.Evaluator;
import com.petalmd.armor.tokeneval.TokenEvaluator.FilterAction;
import com.petalmd.armor.util.ArmorConstants;
import com.petalmd.armor.util.ConfigConstants;
import com.petalmd.armor.util.SecurityUtil;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.CompositeIndicesRequest;
import org.elasticsearch.action.IndicesRequest;
import org.elasticsearch.action.bulk.BulkShardRequest;
import org.elasticsearch.action.support.ActionFilter;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.metadata.AliasMetaData;
import org.elasticsearch.cluster.metadata.AliasOrIndex;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLoggerFactory;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.index.IndexNotFoundException;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;

import java.io.Serializable;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

public class ArmorActionFilter implements ActionFilter {

    protected final Logger log = ESLoggerFactory.getLogger(this.getClass());
    private final AuditListener auditListener;
    protected final Authorizator authorizator = null;
    protected final AuthenticationBackend authenticationBackend = null;
    protected final Settings settings;
    private final ThreadPool threadpool;
    protected final ClusterService clusterService;
    protected final Client client;
    protected final ArmorConfigService armorConfigService;

    @Inject
    public ArmorActionFilter(final Settings settings, final Client client, final ClusterService clusterService,
                             final ThreadPool threadpool, final ArmorService armorService, final ArmorConfigService armorConfigService) {
        this.auditListener = armorService.getAuditListener();
        this.settings = settings;
        this.clusterService = clusterService;
        this.client = client;
        this.armorConfigService = armorConfigService;
        this.threadpool = threadpool;
    }

    @Override
    public int order() {
        return Integer.MIN_VALUE + 1;
    }

    @Override
    public void apply(Task task, final String action, final ActionRequest request, final ActionListener listener, final ActionFilterChain chain) {

        try {
            apply0(task, action, request, listener, chain);
        } catch (final ForbiddenException e) {
            log.error("Forbidden while apply() due to {} for action {}", e, e.toString(), action);
            throw e;
        } catch (IndexNotFoundException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error while apply() due to {} for action {}", e, e.toString(), action);
            throw new RuntimeException(e);

        }
    }

    private void copyContextToHeader(Map<String, Object> contextMap) {
//        if (ArmorPlugin.DLS_SUPPORTED) {
//
//            ThreadContext threadContext = threadpool.getThreadContext();
//
//            final Iterator<String> it = contextMap.keySet().iterator();
//
//
//            while (it.hasNext()) {
//                final String key = it.next();
//
//                if (key.toString().startsWith("armor")) {
//
//                    if (threadContext.getHeader(key) != null) {
//                        continue;
//                    }
//
//                    threadContext.putHeader(key.toString(),
//                            SecurityUtil.encryptAndSerializeObject((Serializable) contextMap.get(key), ArmorService.getSecretKey()));
//                    log.trace("Copy from context to header {}", key);
//
//                }
//
//            }
//
//        }
    }

    private void apply0(Task task, final String action, final ActionRequest request, final ActionListener listener, final ActionFilterChain chain)
            throws Exception {
        //proceeding for kibana field stats requests
        if (settings.getAsBoolean(ConfigConstants.ARMOR_ALLOW_KIBANA_ACTIONS, true) && (action.startsWith("cluster:monitor/") || action.contains("indices:data/read/field_stats"))) {
            chain.proceed(task, action, request, listener);
            return;
        }

        //copyContextToHeader(request);


        log.trace("action {} ({}) from {}", action, request.getClass(), request.remoteAddress() == null ? "INTRANODE" : request
                .remoteAddress().toString());

        ThreadContext threadContext = threadpool.getThreadContext();

        final User user = threadContext.getTransient(ArmorConstants.ARMOR_AUTHENTICATED_USER);
        final Object authHeader = threadContext.getTransient(ArmorConstants.ARMOR_AUTHENTICATED_TRANSPORT_REQUEST);

        if (request.remoteAddress() == null && user == null) {
            log.trace("INTRANODE request");
            try {
                chain.proceed(task, action, request, listener);
            } catch (IndexNotFoundException e) {
                log.warn("Missing internal Armor Index, access granted");
                return;
            }

            return;
        }
        AtomicBoolean isRequestExternal =  threadContext.getTransient(ArmorConstants.ARMOR_REQUEST_IS_EXTERNAL);
        if (isRequestExternal == null || isRequestExternal.get() == false) {
            log.debug("TYPE: inter node cluster request, skip filters");
            chain.proceed(task, action, request, listener);
            return;
        }


        if (user == null) {

            if (authHeader == null || !(authHeader instanceof String)) {
                log.error("not authenticated");
                listener.onFailure(new AuthException("not authenticated"));
            }

            final Object decrypted = SecurityUtil.decryptAnDeserializeObject((String) authHeader, ArmorService.getSecretKey());

            if (decrypted == null || !(decrypted instanceof String) || !decrypted.equals("authorized")) {
                log.error("bad authenticated");
                listener.onFailure(new AuthException("bad authenticated"));
            }


            log.trace("Authenticated INTERNODE (cluster) message, pass through");
            chain.proceed(task, action, request, listener);
            return;
        }

        log.trace("user {}", user);

        final boolean allowedForAllIndices = !SecurityUtil.isWildcardMatch(action, "*put*", false)
                && !SecurityUtil.isWildcardMatch(action, "*delete*", false)
                && !SecurityUtil.isWildcardMatch(action, "indices:data*", false)
                && !SecurityUtil.isWildcardMatch(action, "cluster:admin*", false)
                && !SecurityUtil.isWildcardMatch(action, "*close*", false) && !SecurityUtil.isWildcardMatch(action, "*open*", false)
                && !SecurityUtil.isWildcardMatch(action, "*update*", false) && !SecurityUtil.isWildcardMatch(action, "*create*", false);

        final TokenEvaluator evaluator = new TokenEvaluator(armorConfigService.getSecurityConfiguration());
        final Evaluator eval;

        if (threadContext.getTransient(ArmorConstants.ARMOR_TOKEN_EVALUATOR) == null) {
            threadContext.putTransient(ArmorConstants.ARMOR_TOKEN_EVALUATOR, evaluator);
        }

        final List<String> ci = new ArrayList<String>();
        final List<String> aliases = new ArrayList<String>();
        final List<String> types = new ArrayList<String>();
        boolean wildcardExpEnabled = settings.getAsBoolean(ConfigConstants.ARMOR_ACTION_WILDCARD_EXPANSION_ENABLED, false);

        //If we enable wildcard expansion the token Evaluator should be regenerated.
        if (threadContext.getTransient(ArmorConstants.ARMOR_AC_EVALUATOR) == null || wildcardExpEnabled) {

            RulesEntities userRulesEntities = null;
            if (wildcardExpEnabled) {
                userRulesEntities = evaluator.findEntitiesforUser(user);
            }

            if (request instanceof IndicesRequest) {
                final IndicesRequest ir = (IndicesRequest) request;
                addType(ir, types, action);
                log.trace("Indices {}", Arrays.toString(ir.indices()));
                log.trace("Indices opts allowNoIndices {}", ir.indicesOptions().allowNoIndices());
                log.trace("Indices opts expandWildcardsOpen {}", ir.indicesOptions().expandWildcardsOpen());
                if (wildcardExpEnabled && ir instanceof IndicesRequest.Replaceable) {
                    replaceWildcardOrAllIndices(ir, userRulesEntities, ci, aliases);
                } else {
                    ci.addAll(resolveAliases(Arrays.asList(ir.indices())));
                    aliases.addAll(getOnlyAliases(Arrays.asList(ir.indices())));
                }


                if (!allowedForAllIndices && (ir.indices() == null || Arrays.asList(ir.indices()).contains("_all") || ir.indices().length == 0)) {
                    log.error("Attempt from {} to _all indices for {} and {}", request.remoteAddress(), action, user);
                    auditListener.onMissingPrivileges(user == null ? "unknown" : user.getName(), request, threadContext);

                    listener.onFailure(new ForbiddenException("Attempt from {} to _all indices for {} and {}", request.remoteAddress(), action, user));
                    throw new ForbiddenException("Attempt from {} to _all indices for {} and {}", request.remoteAddress(), action, user);
                }

            }

            if (request instanceof CompositeIndicesRequest) {
                final RequestItemDetails cirDetails = RequestItemDetails.fromCompositeIndicesRequest((CompositeIndicesRequest) request);
                log.trace("Indices {}", cirDetails.getIndices().toString());
                ci.addAll(resolveAliases(cirDetails.getIndices()));
                aliases.addAll(getOnlyAliases(cirDetails.getIndices()));

                if (!allowedForAllIndices && (cirDetails.getIndices() == null || Arrays.asList(cirDetails.getIndices()).contains("_all") || cirDetails.getIndices().size() == 0)) {
                    log.error("Attempt from {} to _all indices for {} and {}", request.remoteAddress(), action, user);
                    auditListener.onMissingPrivileges(user == null ? "unknown" : user.getName(), request, threadContext);

                    listener.onFailure(new ForbiddenException("Attempt from {} to _all indices for {} and {}", request.remoteAddress(), action, user));
                    throw new ForbiddenException("Attempt from {} to _all indices for {} and {}", request.remoteAddress(), action, user);
                }

            }

            if (!settings.getAsBoolean(ConfigConstants.ARMOR_ALLOW_NON_LOOPBACK_QUERY_ON_ARMOR_INDEX, false) && ci.contains(settings.get(ConfigConstants.ARMOR_CONFIG_INDEX_NAME, ConfigConstants.DEFAULT_SECURITY_CONFIG_INDEX))) {
                log.error("Attempt from " + request.remoteAddress() + " on " + settings.get(ConfigConstants.ARMOR_CONFIG_INDEX_NAME, ConfigConstants.DEFAULT_SECURITY_CONFIG_INDEX));
                auditListener.onMissingPrivileges(user.getName(), request, threadContext);
                throw new ForbiddenException("Only allowed from localhost (loopback)");
            }

            if (ci.contains("_all")) {
                ci.clear();

                if (!allowedForAllIndices) {
                    ci.add("*");
                }

            }

            final InetAddress resolvedAddress = threadContext.getTransient(ArmorConstants.ARMOR_RESOLVED_REST_ADDRESS);

            if (resolvedAddress == null) {
                //not a rest request
                log.debug("Not a rest request, will ignore host rules");

            }

            eval = evaluator.getEvaluator(ci, aliases, types, resolvedAddress, user);

            if (threadContext.getTransient(ArmorConstants.ARMOR_AC_EVALUATOR) == null) {
                threadContext.putTransient(ArmorConstants.ARMOR_AC_EVALUATOR, eval);
            }
            //copyContextToHeader(request);
        } else {
            eval = threadContext.getTransient(ArmorConstants.ARMOR_AC_EVALUATOR);
        }

        List<String> filterList = threadContext.getTransient(ArmorConstants.ARMOR_FILTER);
        if (filterList == null) {
            filterList = Collections.EMPTY_LIST;
        }


        log.trace("filter {}", filterList);

        for (String fullFilter : filterList) {
            final String[] f = fullFilter.split(":");
            final String ft = f[0];
            final String fn = f[1];

            log.trace("Filter {}/{}", ft, fn);

            if (ft.contains("dlsfilter") || ft.contains("flsfilter")) {
                log.trace("    {} skipped here", ft);
                continue;
            }

            final FilterAction faction = eval.evaluateFilter(ft, fn);

            if (faction == FilterAction.BYPASS) {
                log.trace("will bypass");
                continue;
            }

            if ("actionrequestfilter".equals(ft)) {

                List<String> allowedActions = threadContext.getTransient("armor." + ft + "." + fn + ".allowed_actions");
                if (allowedActions == null) {
                    allowedActions = Collections.emptyList();
                }

                List<String> forbiddenActions = threadContext.getTransient("armor." + ft + "." + fn + ".forbidden_actions");
                if (forbiddenActions == null) {
                    forbiddenActions = Collections.emptyList();
                }

                for (final Iterator<String> iterator = forbiddenActions.iterator(); iterator.hasNext(); ) {
                    final String forbiddenAction = iterator.next();
                    if (SecurityUtil.isWildcardMatch(action, forbiddenAction, false)) {

                        log.warn("{}.{} Action '{}' is forbidden due to {}", ft, fn, action, forbiddenAction);
                        auditListener.onMissingPrivileges(user == null ? "unknown" : user.getName(), request, threadContext);
                        listener.onFailure(new ForbiddenException("Action '{}' is forbidden due to {}", action, forbiddenAction));
                        throw new ForbiddenException("Action '{}' is forbidden due to {}", action, forbiddenAction);
                    }
                }

                for (final Iterator<String> iterator = allowedActions.iterator(); iterator.hasNext(); ) {
                    final String allowedAction = iterator.next();
                    if (SecurityUtil.isWildcardMatch(action, allowedAction, false)) {
                        log.trace("Action '{}' is allowed due to {}", action, allowedAction);
                        chain.proceed(task, action, request, listener);
                        return;
                    }
                }

                log.warn("{}.{} Action '{}' is forbidden due to {}", ft, fn, action, "DEFAULT");

                auditListener.onMissingPrivileges(user == null ? "unknown" : user.getName(), request, threadContext);
                listener.onFailure(new ForbiddenException("Action '{}' is forbidden due to DEFAULT", action));
                throw new ForbiddenException("Action '{}' is forbidden due to DEFAULT", action);
            }

            //TODO : Delete ?
//            if ("restactionfilter".equals(ft)) {
//                final String simpleClassName = request.getFromContext("armor." + ft + "." + fn + ".class_name", null);
//
//                final List<String> allowedActions = request.getFromContext("armor." + ft + "." + fn + ".allowed_actions",
//                        Collections.EMPTY_LIST);
//                final List<String> forbiddenActions = request.getFromContext("armor." + ft + "." + fn + ".forbidden_actions",
//                        Collections.EMPTY_LIST);
//
//                for (final Iterator<String> iterator = forbiddenActions.iterator(); iterator.hasNext(); ) {
//                    final String forbiddenAction = iterator.next();
//                    if (SecurityUtil.isWildcardMatch(simpleClassName, forbiddenAction, false)) {
//                        throw new RuntimeException("[" + ft + "." + fn + "] Forbidden action " + simpleClassName + " . Allowed actions: "
//                                + allowedActions);
//
//                    }
//                }
//
//                boolean passall = false;
//
//                for (final Iterator<String> iterator = allowedActions.iterator(); iterator.hasNext(); ) {
//                    final String allowedAction = iterator.next();
//                    if (SecurityUtil.isWildcardMatch(simpleClassName, allowedAction, false)) {
//                        passall = true;
//                        break;
//                    }
//                }
//
//                if (!passall) {
//                    throw new ForbiddenException("Forbidden action {} . Allowed actions: {}", simpleClassName, allowedActions);
//                }
//
//            }

        }

        chain.proceed(task, action, request, listener);

    }

    private void replaceWildcardOrAllIndices(IndicesRequest ir, RulesEntities rulesEntities, List<String> ci, List<String> aliases) {

        List<String> irIndices = Arrays.asList(ir.indices());
        List<String> newIndices = new ArrayList<>();
        List<String> otherIndicesOrAliases = new ArrayList<>();
        log.debug("replace index for " + ir.indices());
        if (irIndices.size() == 0 || irIndices.contains("_all")) {
            log.debug("request target _all indices, we replace it with rulesEntities items");
            newIndices.addAll(rulesEntities.getIndices());
            ci.addAll(rulesEntities.getIndices());
            newIndices.addAll(rulesEntities.getAliases());
            aliases.addAll(rulesEntities.getAliases());
            log.debug("added " + newIndices.size() + " indices");

        } else {
            //search for wildcards
            log.debug("indices contains wildcard, we will change them if they are not in the rules");
            for (String indexOrAlias : irIndices) {
                if (indexOrAlias.contains("*")) {
                    log.debug("index contains a wildcard");
                    //if the index match no indices it will be silently removed (consistent with what ES does).
                    for (String reIndex : rulesEntities.getIndices()) {
                        //check if index match rulesEntity (if its the case, we keep the rulesEntity).
                        if (SecurityUtil.isWildcardMatch(reIndex, indexOrAlias, false)) {
                            log.debug("index " + indexOrAlias + " match an index contained in a rule: " + reIndex);
                            newIndices.add(reIndex);
                            ci.add(reIndex);
                            //check if rulesEntity match the index (if it is the case, we keep the indexOrAlias)
                        } else if (SecurityUtil.isWildcardMatch(indexOrAlias, reIndex, false)) {
                            log.debug("index " + indexOrAlias + "has been matched by a index contained in a rule " + reIndex);
                            newIndices.add(indexOrAlias);
                            ci.add(reIndex);
                        }
                    }
                    for (String reAlias : rulesEntities.getAliases()) {
                        //check if Alias match rulesEntity (if its the case, we keep the rulesEntity).
                        if (SecurityUtil.isWildcardMatch(reAlias, indexOrAlias, false)) {
                            log.debug("index " + indexOrAlias + " match an alias contained in a rule: " + reAlias);
                            newIndices.add(reAlias);
                            aliases.add(reAlias);
                            //check if rulesEntity match the alias (if it is the case, we keep the indexOrAlias)
                        } else if (SecurityUtil.isWildcardMatch(indexOrAlias, reAlias, false)) {
                            log.debug("index " + indexOrAlias + "has been matched by an alias contained in a rule " + reAlias);
                            newIndices.add(indexOrAlias);
                            aliases.add(reAlias);
                        }
                    }
                } else {
                    log.debug("this index is not a wildcard, we will just have to resolve it");
                    newIndices.add(indexOrAlias);
                    otherIndicesOrAliases.add(indexOrAlias);
                }
            }
        }

        ci.addAll(resolveAliases(otherIndicesOrAliases));
        aliases.addAll(getOnlyAliases(otherIndicesOrAliases));

        if (!newIndices.isEmpty()) {
            log.debug("replacing indices " + ir.indices() + " by " + newIndices.toString());
            IndicesRequest.Replaceable irNew = (IndicesRequest.Replaceable) ir;
            irNew.indices(newIndices.toArray(new String[newIndices.size()]));
        }
    }

    //works also with alias of an alias!
    private List<String> resolveAliases(final Collection<String> indices) {

        final List<String> result = new ArrayList<String>();

        final SortedMap<String, AliasOrIndex> aliases = clusterService.state().metaData().getAliasAndIndexLookup();

        for (String index : indices) {

            final AliasOrIndex indexAliases = aliases.get(index);

            if (indexAliases == null) {
                continue;
            }

            if (!indexAliases.isAlias()) {
                result.add(index);
                log.trace("{} is an concrete index", index);
                continue;
            }

            log.trace("{} is an alias and points to -> {}", index, indexAliases.getIndices());

            final Iterable<Tuple<String, AliasMetaData>> iterable = ((AliasOrIndex.Alias) indexAliases).getConcreteIndexAndAliasMetaDatas();

            for (final Iterator<Tuple<String, AliasMetaData>> iterator = iterable.iterator(); iterator.hasNext(); ) {
                final Tuple<String, AliasMetaData> entry = iterator.next();
                result.add(entry.v1());
            }

        }

        return result;

    }

    private List<String> getOnlyAliases(final Collection<String> indices) {

        final List<String> result = new ArrayList<String>();

        final SortedMap<String, AliasOrIndex> aliases = clusterService.state().metaData().getAliasAndIndexLookup();

        for (String index : indices) {

            final AliasOrIndex indexAliases = aliases.get(index);

            if (indexAliases == null) {
                continue;
            }

            if (indexAliases.isAlias()) {
                result.add(index);
            }
        }

        return result;

    }

    private void addType(final IndicesRequest request, final List<String> typesl, final String action) {

        try {
            final Method method = request.getClass().getDeclaredMethod("type");
            method.setAccessible(true);
            final String type = (String) method.invoke(request);
            typesl.add(type);
        } catch (final Exception e) {
            try {
                final Method method = request.getClass().getDeclaredMethod("types");
                method.setAccessible(true);
                final String[] types = (String[]) method.invoke(request);
                typesl.addAll(Arrays.asList(types));
            } catch (final Exception e1) {
                log.debug("Cannot determine types for {} ({}) due to type[s]() method not found", action, request.getClass());
            }
        }

    }

}
