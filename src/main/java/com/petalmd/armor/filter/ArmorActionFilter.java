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

import com.petalmd.armor.audit.AuditListener;
import com.petalmd.armor.authentication.AuthException;
import com.petalmd.armor.authentication.User;
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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.CompositeIndicesRequest;
import org.elasticsearch.action.IndicesRequest;
import org.elasticsearch.action.support.ActionFilter;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.cluster.metadata.AliasOrIndex;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.index.IndexNotFoundException;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

public class ArmorActionFilter implements ActionFilter {

    protected static final Logger log = LogManager.getLogger(ArmorActionFilter.class);
    private final AuditListener auditListener;
    protected final Settings settings;
    private final ThreadPool threadpool;
    protected final ClusterService clusterService;
    protected final ArmorService armorService;
    protected final ArmorConfigService armorConfigService;

    @Inject
    public ArmorActionFilter(final Settings settings, final ClusterService clusterService,
                             final ThreadPool threadpool, final ArmorService armorService, final ArmorConfigService armorConfigService) {
        this.auditListener = armorService.getAuditListener();
        this.settings = settings;
        this.clusterService = clusterService;
        this.armorService = armorService;
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

    private void apply0(Task task, final String action, final ActionRequest request, final ActionListener listener, final ActionFilterChain chain)
            throws Exception {
        //proceeding for kibana field stats requests
        if (settings.getAsBoolean(ConfigConstants.ARMOR_ALLOW_KIBANA_ACTIONS, true) && (action.startsWith("cluster:monitor/") || action.contains("indices:data/read/field_stats"))) {
            chain.proceed(task, action, request, listener);
            return;
        }

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

        AtomicBoolean isRequestExternal = threadContext.getTransient(ArmorConstants.ARMOR_REQUEST_IS_EXTERNAL);
        if (isRequestExternal == null || isRequestExternal.get() == false) {
            log.debug("TYPE: inter node cluster request, skip filters");
            chain.proceed(task, action, request, listener);
            return;
        }


        if (user == null) {

            if (authHeader == null || !(authHeader instanceof String)) {
                log.error("not authenticated");
                listener.onFailure(new AuthException("not authenticated"));
                return;
            }

            final Object decrypted = SecurityUtil.decryptAnDeserializeObject((String) authHeader, armorService.getSecretKey());

            if (decrypted == null || !(decrypted instanceof String) || !decrypted.equals("authorized")) {
                log.error("bad authenticated");
                listener.onFailure(new AuthException("bad authenticated"));
                return;
            }


            log.trace("Authenticated INTERNODE (cluster) message, pass through");
            chain.proceed(task, action, request, listener);
            return;
        }

        //ACTION FILTER BYPASS (set by previous filters)
        if (Boolean.TRUE.equals(threadpool.getThreadContext().getTransient(ArmorConstants.ARMOR_ACTION_FILTER_BYPASS))) {
            log.debug("bypass filter due to FILTER BYPASS");
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
        final SortedMap<String, AliasOrIndex> aliasesAndIndicesMap = clusterService.state().metaData().getAliasAndIndexLookup();
        final Evaluator eval;

        if (threadContext.getTransient(ArmorConstants.ARMOR_TOKEN_EVALUATOR) == null) {
            threadContext.putTransient(ArmorConstants.ARMOR_TOKEN_EVALUATOR, evaluator);
        }

        final List<String> ci = new ArrayList<String>();
        final List<String> aliases = new ArrayList<String>();
        final List<String> types = new ArrayList<String>();
        boolean wildcardExpEnabled = settings.getAsBoolean(ConfigConstants.ARMOR_ACTION_WILDCARD_EXPANSION_ENABLED, true);


        //If we enable wildcard expansion the token Evaluator should be regenerated.
        if (threadContext.getTransient(ArmorConstants.ARMOR_AC_EVALUATOR) == null || wildcardExpEnabled) {

            RulesEntities userRulesEntities = null;
            if (wildcardExpEnabled) {
                userRulesEntities = evaluator.findEntitiesforUser(user);
            }

            if (request instanceof IndicesRequest) {
                final IndicesRequest ir = (IndicesRequest) request;
                addType(ir, types, action);
                if (log.isTraceEnabled()) {
                    log.trace("Indices {}", Arrays.toString(ir.indices()));
                    log.trace("Indices opts allowNoIndices {}", ir.indicesOptions().allowNoIndices());
                    log.trace("Indices opts expandWildcardsOpen {}", ir.indicesOptions().expandWildcardsOpen());
                }
                if (wildcardExpEnabled && ir instanceof IndicesRequest.Replaceable) {
                    FilterHelper.replaceWildcardOrAllIndices(ir, userRulesEntities, ci, aliases, aliasesAndIndicesMap);
                } else {
                    ci.addAll(FilterHelper.getOnlyIndices(Arrays.asList(ir.indices()), aliasesAndIndicesMap));
                    aliases.addAll(FilterHelper.getOnlyAliases(Arrays.asList(ir.indices()), aliasesAndIndicesMap));
                }


                if (!allowedForAllIndices && (ir.indices() == null || Arrays.asList(ir.indices()).contains("_all") || ir.indices().length == 0)) {
                    log.error("Attempt from {} to _all indices for {} and {}", request.remoteAddress(), action, user);
                    threadContext.putTransient(AuditListener.AUDIT_ITEMS, Arrays.asList(ir.indices()));
                    auditListener.onMissingPrivileges(user.getName(), request, threadContext);

                    listener.onFailure(new ForbiddenException("Attempt from {} to _all indices for {} and {}", request.remoteAddress(), action, user));
                    throw new ForbiddenException("Attempt from {} to _all indices for {} and {}", request.remoteAddress(), action, user);
                }

            }

            if (request instanceof CompositeIndicesRequest) {
                final RequestItemDetails cirDetails;
                if (wildcardExpEnabled) {
                    FilterHelper.replaceWildcardOrAllIndicesComposite((CompositeIndicesRequest) request, userRulesEntities, ci, aliases, aliasesAndIndicesMap);
                    cirDetails = RequestItemDetails.fromCompositeIndicesRequest((CompositeIndicesRequest) request);
                } else {
                    cirDetails = RequestItemDetails.fromCompositeIndicesRequest((CompositeIndicesRequest) request);
                    log.trace("Indices {}", cirDetails.getIndices().toString());
                    ci.addAll(FilterHelper.getOnlyIndices(cirDetails.getIndices(), aliasesAndIndicesMap));
                    aliases.addAll(FilterHelper.getOnlyAliases(cirDetails.getIndices(), aliasesAndIndicesMap));
                }
                if (!allowedForAllIndices && (cirDetails.getIndices() == null || cirDetails.getIndices().contains("_all") || cirDetails.getIndices().size() == 0)) {
                    log.error("Attempt from {} to _all indices for {} and {}", request.remoteAddress(), action, user);
                    threadContext.putTransient(AuditListener.AUDIT_ITEMS, new ArrayList<>(cirDetails.getIndices()));
                    auditListener.onMissingPrivileges(user.getName(), request, threadContext);

                    listener.onFailure(new ForbiddenException("Attempt from {} to _all indices for {} and {}", request.remoteAddress(), action, user));
                    throw new ForbiddenException("Attempt from {} to _all indices for {} and {}", request.remoteAddress(), action, user);
                }
            }

            if (!settings.getAsBoolean(ConfigConstants.ARMOR_ALLOW_NON_LOOPBACK_QUERY_ON_ARMOR_INDEX, false) && ci.contains(settings.get(ConfigConstants.ARMOR_CONFIG_INDEX_NAME, ConfigConstants.DEFAULT_SECURITY_CONFIG_INDEX))) {
                final String armorIndex = settings.get(ConfigConstants.ARMOR_CONFIG_INDEX_NAME, ConfigConstants.DEFAULT_SECURITY_CONFIG_INDEX);
                log.error("Attempt from " + request.remoteAddress() + " on " + armorIndex);
                threadContext.putTransient(AuditListener.AUDIT_ITEMS, Arrays.asList(armorIndex));
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

            boolean indicesLikeAliases = settings.getAsBoolean(ConfigConstants.ARMOR_ACTION_INDICES_LIKE_ALIASES,true);
            eval = evaluator.getEvaluator(ci, aliases, types, resolvedAddress, user, indicesLikeAliases);

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

        List<String> additionalRights = new ArrayList<>();
        if (threadContext.getTransient(ArmorConstants.ARMOR_ADDITIONAL_RIGHTS) != null) {
            additionalRights.addAll((List<String>) threadContext.getTransient(ArmorConstants.ARMOR_ADDITIONAL_RIGHTS));
        }

        log.trace("filter {}", filterList);
        boolean filtered = false;

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

            //Action has been filtered once so if it is never allowed, it will be rejected to due DEFAULT reject behavior.
            filtered = true;

            if ("actionrequestfilter".equals(ft)) {

                List<String> allowedActions = threadContext.getTransient("armor." + ft + "." + fn + ".allowed_actions");
                if (allowedActions == null) {
                    allowedActions = Collections.emptyList();
                }

                List<String> forbiddenActions = threadContext.getTransient("armor." + ft + "." + fn + ".forbidden_actions");
                if (forbiddenActions == null) {
                    forbiddenActions = Collections.emptyList();
                }

                for (final String forbiddenAction : forbiddenActions) {
                    if (SecurityUtil.isWildcardMatch(action, forbiddenAction, false)) {

                        log.warn("{}.{} Action '{}' is forbidden due to {}", ft, fn, action, forbiddenAction);
                        //TODO change it to add only the index that fails
                        final List<String> itemLists = new ArrayList<>(ci);
                        itemLists.addAll(aliases);
                        threadContext.putTransient(AuditListener.AUDIT_ITEMS, itemLists);
                        auditListener.onMissingPrivileges(user.getName(), request, threadContext);
                        listener.onFailure(new ForbiddenException("Action '{}' is forbidden due to {}", action, forbiddenAction));
                        throw new ForbiddenException("Action '{}' is forbidden due to {}", action, forbiddenAction);
                    }
                }

                for (final String allowedAction : allowedActions) {
                    String allowedActionSpecial = allowedAction;
                    for (String additionalRight : additionalRights) {
                        if (allowedAction.startsWith(additionalRight)) {
                            allowedActionSpecial = allowedAction.substring(additionalRight.length() + 1); //escape also the ':' separator
                        }
                    }
                    if (SecurityUtil.isWildcardMatch(action, allowedActionSpecial, false)) {
                        log.trace("Action '{}' is allowed due to {}", action, allowedAction);
                        chain.proceed(task, action, request, listener);
                        return;
                    }
                }
            }
        }
        if (filtered) {
            log.warn("Action  is forbidden due to {}", "DEFAULT");
            final List<String> itemLists = new ArrayList<>(ci);
            itemLists.addAll(aliases);
            threadContext.putTransient(AuditListener.AUDIT_ITEMS, itemLists);
            auditListener.onMissingPrivileges(user.getName(), request, threadContext);
            listener.onFailure(new ForbiddenException("Action '{}' is forbidden due to DEFAULT", action));
            throw new ForbiddenException("Action '{}' is forbidden due to DEFAULT", action);
        }
        chain.proceed(task, action, request, listener);
    }

    private void addType(final IndicesRequest request, final List<String> typesl, final String action) {

        AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
            try {
                final Method method = request.getClass().getDeclaredMethod("type");
                method.setAccessible(true);
                final String type = (String) method.invoke(request);
                typesl.add(type);
            } catch (NoSuchMethodException | SecurityException | IllegalAccessException |
                    IllegalArgumentException | InvocationTargetException e) {
                try {
                    final Method method = request.getClass().getDeclaredMethod("types");
                    method.setAccessible(true);
                    final String[] types = (String[]) method.invoke(request);
                    typesl.addAll(Arrays.asList(types));
                } catch (final NoSuchMethodException | SecurityException | IllegalAccessException |
                        IllegalArgumentException | InvocationTargetException e1) {
                    log.debug("Cannot determine types for {} ({}) due to type[s]() method not found", action, request.getClass());
                }

            } finally {
                return null;
            }
        });
    }

}
