/*
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

import java.io.Serializable;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.CompositeIndicesRequest;
import org.elasticsearch.action.IndicesRequest;
import org.elasticsearch.action.support.ActionFilter;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.ClusterService;
import org.elasticsearch.cluster.metadata.AliasMetaData;
import org.elasticsearch.common.collect.ImmutableOpenMap;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;

import com.petalmd.armor.ArmorPlugin;
import com.petalmd.armor.audit.AuditListener;
import com.petalmd.armor.authentication.AuthException;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authentication.backend.AuthenticationBackend;
import com.petalmd.armor.authorization.Authorizator;
import com.petalmd.armor.authorization.ForbiddenException;
import com.petalmd.armor.service.ArmorConfigService;
import com.petalmd.armor.service.ArmorService;
import com.petalmd.armor.tokeneval.TokenEvaluator;
import com.petalmd.armor.tokeneval.TokenEvaluator.Evaluator;
import com.petalmd.armor.tokeneval.TokenEvaluator.FilterAction;
import com.petalmd.armor.util.ConfigConstants;
import com.petalmd.armor.util.SecurityUtil;
import java.util.HashSet;
import java.util.Set;
import org.apache.lucene.analysis.standard.StandardAnalyzer;
import org.apache.lucene.queryparser.classic.QueryParser;
import org.apache.lucene.search.BooleanClause;
import org.apache.lucene.search.BooleanQuery;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.TermQuery;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.search.lookup.SourceLookup;

public class ArmorActionFilter implements ActionFilter {

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private final AuditListener auditListener;
    protected final Authorizator authorizator = null;
    protected final AuthenticationBackend authenticationBackend = null;
    protected final Settings settings;
    protected final ClusterService clusterService;
    protected final Client client;
    protected final ArmorConfigService armorConfigService;

    @Inject
    public ArmorActionFilter(final Settings settings, final AuditListener auditListener, final ClusterService clusterService,
                             final Client client, final ArmorConfigService armorConfigService) {
        this.auditListener = auditListener;
        this.settings = settings;
        this.clusterService = clusterService;
        this.client = client;
        this.armorConfigService = armorConfigService;
    }

    @Override
    public int order() {
        return Integer.MIN_VALUE + 1;
    }

    @Override
    public void apply(final String action, final ActionRequest request, final ActionListener listener, final ActionFilterChain chain) {

        try {
            apply0(action, request, listener, chain);
        } catch (final ForbiddenException e){
            log.error("Forbidden while apply() due to {} for action {}", e, e.toString(), action);
            throw e;
        } catch (final Exception e) {
            log.error("Error while apply() due to {} for action {}", e, e.toString(), action);
            throw new RuntimeException(e);
        }
    }

    private void copyContextToHeader(final ActionRequest request) {
        if (ArmorPlugin.DLS_SUPPORTED) {

            final ImmutableOpenMap<Object, Object> map = request.getContext();

            final Iterator it = map.keysIt();

            while (it.hasNext()) {
                final Object key = it.next();

                if (key instanceof String && key.toString().startsWith("armor")) {

                    if (request.hasHeader(key.toString())) {
                        continue;
                    }

                    request.putHeader(key.toString(),
                            SecurityUtil.encryptAndSerializeObject((Serializable) map.get(key), ArmorService.getSecretKey()));
                    log.trace("Copy from context to header {}", key);

                }

            }

        }
    }

    private void apply0(final String action, final ActionRequest request, final ActionListener listener, final ActionFilterChain chain)
            throws Exception {

        if (settings.getAsBoolean(ConfigConstants.ARMOR_ALLOW_CLUSTER_MONITOR, true) && action.startsWith("cluster:monitor/")) {
            chain.proceed(action, request, listener);
            return;
        }

        copyContextToHeader(request);

        log.trace("action {} ({}) from {}", action, request.getClass(), request.remoteAddress() == null ? "INTRANODE" : request
                .remoteAddress().toString());

        final User user = request.getFromContext("armor_authenticated_user", null);
        final Object authHeader = request.getHeader("armor_authenticated_transport_request");

        if (request.remoteAddress() == null && user == null) {
            log.trace("INTRANODE request");
            chain.proceed(action, request, listener);
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
            chain.proceed(action, request, listener);
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
        request.putInContext("_armor_token_evaluator", evaluator);

        final List<String> ci = new ArrayList<String>();
        final List<String> aliases = new ArrayList<String>();
        final List<String> types = new ArrayList<String>();

        //analyse the request to find if it is a specific index query
        if (request instanceof SearchRequest) {
            log.debug("this is a searchRequest.");
            final SearchRequest sr = (SearchRequest) request;

            sr.validate();
            final SourceLookup sl = new SourceLookup();
            if (sr.extraSource() != null) {
                sl.setNextSource(sr.extraSource());
                try {
                    final String query = (String) (sl.extractValue("query.query_string.query"));

                    final QueryParser qp = new QueryParser("_id", new StandardAnalyzer());

                    Query luceneQuery = qp.parse(query);

                    Set<String> indexes = null;
                    if (luceneQuery instanceof TermQuery) {
                        TermQuery tq = (TermQuery)luceneQuery;
                        if(tq.getTerm().field().equals("_index")) {
                            indexes = new HashSet<String>();
                            indexes.add(tq.getTerm().text());
                        }
                    } else if (luceneQuery instanceof BooleanQuery) {
                        BooleanQuery bq = (BooleanQuery)luceneQuery;
                        indexes = validateBooleanQuery(bq, new HashSet<String>());
                    }
                    
                    if (indexes != null && !indexes.isEmpty()) {
                        log.debug(("find the following indexes to add: " + indexes));
                        indexes.addAll(Arrays.asList(sr.indices()));
                        indexes.remove("_all");
                        sr.indices(indexes.toArray(new String[indexes.size()]));
                    }
                } catch (Exception e) {
                    log.debug("there is no _index field in the Extra Source, we continue", e);
                    e.printStackTrace();
                }
            }
            
        }
        
        if (request instanceof IndicesRequest) {
            final IndicesRequest ir = (IndicesRequest) request;
            addType(ir, types, action);
            log.trace("Indices {}", Arrays.toString(ir.indices()));
            log.trace("Indices opts allowNoIndices {}", ir.indicesOptions().allowNoIndices());
            log.trace("Indices opts expandWildcardsOpen {}", ir.indicesOptions().expandWildcardsOpen());

            try {
                ci.addAll(resolveAliases(Arrays.asList(ir.indices())));
                aliases.addAll(getOnlyAliases(Arrays.asList(ir.indices())));
            } catch(java.lang.NullPointerException e) {}

            if (!allowedForAllIndices && (ir.indices() == null || Arrays.asList(ir.indices()).contains("_all") || ir.indices().length == 0)) {
                log.error("Attempt from " + request.remoteAddress() + " to _all indices for " + action + " and " + user);
                auditListener.onMissingPrivileges(user == null ? "unknown" : user.getName(), request);
                //This blocks?
                //listener.onFailure(new AuthException("Attempt from "+request.remoteAddress()+" to _all indices for " + action + "and "+user));
                throw new ForbiddenException("Attempt from {} to _all indices for {} and {}", request.remoteAddress(), action, user);

            }

        }

        if (request instanceof CompositeIndicesRequest) {
            final CompositeIndicesRequest irc = (CompositeIndicesRequest) request;
            final List irs = irc.subRequests();
            for (final Iterator iterator = irs.iterator(); iterator.hasNext();) {
                final IndicesRequest ir = (IndicesRequest) iterator.next();
                addType(ir, types, action);
                log.trace("C Indices {}", Arrays.toString(ir.indices()));
                log.trace("Indices opts allowNoIndices {}", ir.indicesOptions().allowNoIndices());
                log.trace("Indices opts expandWildcardsOpen {}", ir.indicesOptions().expandWildcardsOpen());

                ci.addAll(resolveAliases(Arrays.asList(ir.indices())));
                aliases.addAll(getOnlyAliases(Arrays.asList(ir.indices())));
                if (!allowedForAllIndices
                        && (ir.indices() == null || Arrays.asList(ir.indices()).contains("_all") || ir.indices().length == 0)) {
                    log.error("Attempt from " + request.remoteAddress() + " to _all indices for " + action + "and " + user);
                    auditListener.onMissingPrivileges(user == null ? "unknown" : user.getName(), request);

                    //This blocks?
                    //listener.onFailure(new AuthException("Attempt from "+request.remoteAddress()+" to _all indices for " + action + "and "+user));
                    //break;
                    throw new ForbiddenException("Attempt from {} to _all indices for {} and {}", request.remoteAddress(), action, user);
                }

            }
        }

        if (!settings.getAsBoolean(ConfigConstants.ARMOR_ALLOW_NON_LOOPBACK_QUERY_ON_ARMOR_INDEX, false) && ci.contains(settings.get(ConfigConstants.ARMOR_CONFIG_INDEX_NAME, ConfigConstants.DEFAULT_SECURITY_CONFIG_INDEX))) {
            log.error("Attemp from " + request.remoteAddress() + " on " + settings.get(ConfigConstants.ARMOR_CONFIG_INDEX_NAME, ConfigConstants.DEFAULT_SECURITY_CONFIG_INDEX));
            auditListener.onMissingPrivileges(user.getName(), request);
            throw new ForbiddenException("Only allowed from localhost (loopback)");
        }

        if (ci.contains("_all")) {
            ci.clear();

            if (!allowedForAllIndices) {
                ci.add("*");
            }

        }

        final InetAddress resolvedAddress = request.getFromContext("armor_resolved_rest_address");

        if (resolvedAddress == null) {
            //not a rest request
            log.debug("Not a rest request, will ignore host rules");

        }

        final Evaluator eval = evaluator.getEvaluator(ci, aliases, types, resolvedAddress, user);

        request.putInContext("armor_ac_evaluator", eval);

        copyContextToHeader(request);

        final List<String> filter = request.getFromContext("armor_filter", Collections.EMPTY_LIST);

        log.trace("filter {}", filter);

        for (int i = 0; i < filter.size(); i++) {
            final String[] f = filter.get(i).split(":");
            final String ft = f[0];
            final String fn = f[1];

            log.trace("Filter {}. {}/{}", i, ft, fn);

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

                final List<String> allowedActions = request.getFromContext("armor." + ft + "." + fn + ".allowed_actions",
                        Collections.EMPTY_LIST);
                final List<String> forbiddenActions = request.getFromContext("armor." + ft + "." + fn + ".forbidden_actions",
                        Collections.EMPTY_LIST);

                for (final Iterator<String> iterator = forbiddenActions.iterator(); iterator.hasNext();) {
                    final String forbiddenAction = iterator.next();
                    if (SecurityUtil.isWildcardMatch(action, forbiddenAction, false)) {

                        log.warn("{}.{} Action '{}' is forbidden due to {}", ft, fn, action, forbiddenAction);
                        auditListener.onMissingPrivileges(user == null ? "unknown" : user.getName(), request);
                        //This blocks?
                        //listener.onFailure(new AuthException("Action '" + action + "' is forbidden due to " + forbiddenAction));
                        //break outer;
                        throw new ForbiddenException("Action '{}' is forbidden due to {}", action, forbiddenAction);

                    }
                }

                for (final Iterator<String> iterator = allowedActions.iterator(); iterator.hasNext();) {
                    final String allowedAction = iterator.next();
                    if (SecurityUtil.isWildcardMatch(action, allowedAction, false)) {
                        log.trace("Action '{}' is allowed due to {}", action, allowedAction);
                        chain.proceed(action, request, listener);
                        return;
                    }
                }

                log.warn("{}.{} Action '{}' is forbidden due to {}", ft, fn, action, "DEFAULT");
                auditListener.onMissingPrivileges(user == null ? "unknown" : user.getName(), request);

                //This blocks?
                //listener.onFailure(new AuthException("Action '" + action + "' is forbidden due to DEFAULT"));
                //break outer;
                throw new ForbiddenException("Action '{}' is forbidden due to DEFAULT", action);
            }

            if ("restactionfilter".equals(ft)) {
                final String simpleClassName = request.getFromContext("armor." + ft + "." + fn + ".class_name", null);

                final List<String> allowedActions = request.getFromContext("armor." + ft + "." + fn + ".allowed_actions",
                        Collections.EMPTY_LIST);
                final List<String> forbiddenActions = request.getFromContext("armor." + ft + "." + fn + ".forbidden_actions",
                        Collections.EMPTY_LIST);

                for (final Iterator<String> iterator = forbiddenActions.iterator(); iterator.hasNext();) {
                    final String forbiddenAction = iterator.next();
                    if (SecurityUtil.isWildcardMatch(simpleClassName, forbiddenAction, false)) {
                        throw new RuntimeException("[" + ft + "." + fn + "] Forbidden action " + simpleClassName + " . Allowed actions: "
                                + allowedActions);

                    }
                }

                boolean passall = false;

                for (final Iterator<String> iterator = allowedActions.iterator(); iterator.hasNext();) {
                    final String allowedAction = iterator.next();
                    if (SecurityUtil.isWildcardMatch(simpleClassName, allowedAction, false)) {
                        passall = true;
                        break;
                    }
                }

                if (!passall) {
                    throw new ForbiddenException("Forbidden action {} . Allowed actions: {}", simpleClassName, allowedActions);
                }

            }

            //DLS/FLS stuff is not done here, its done on SearchCallback

        }

        chain.proceed(action, request, listener);

    }

    @Override
    public void apply(final String action, final ActionResponse response, final ActionListener listener, final ActionFilterChain chain) {
        chain.proceed(action, response, listener);
    }

    //works also with alias of an alias!
    private List<String> resolveAliases(final List<String> indices) {

        final List<String> result = new ArrayList<String>();

        final ImmutableOpenMap<String, ImmutableOpenMap<String, AliasMetaData>> aliases = clusterService.state().metaData().aliases();

        for (int i = 0; i < indices.size(); i++) {
            final String index = indices.get(i);

            final ImmutableOpenMap<String, AliasMetaData> indexAliases = aliases.get(index);

            if (indexAliases == null || indexAliases.size() == 0) {
                result.add(index);
                log.trace("{} is an concrete index", index);
                continue;
            }

            log.trace("{} is an alias and points to -> {}", index, indexAliases.keys());

            for (final Iterator<org.elasticsearch.common.hppc.cursors.ObjectObjectCursor<String, AliasMetaData>> iterator = indexAliases
                    .iterator(); iterator.hasNext();) {
                final org.elasticsearch.common.hppc.cursors.ObjectObjectCursor<String, AliasMetaData> entry = iterator.next();
                result.add(entry.key);
            }

        }

        return result;

    }

    private List<String> getOnlyAliases(final List<String> indices) {

        final List<String> result = new ArrayList<String>();

        final ImmutableOpenMap<String, ImmutableOpenMap<String, AliasMetaData>> aliases = clusterService.state().metaData().aliases();

        for (int i = 0; i < indices.size(); i++) {
            final String index = indices.get(i);

            final ImmutableOpenMap<String, AliasMetaData> indexAliases = aliases.get(index);

            if (indexAliases == null || indexAliases.size() == 0) {
                continue;
            } else {
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

    private Set<String> validateBooleanQuery(BooleanQuery query, Set<String> validIndices) {

        Set<String> newValidIndices = new HashSet<String>();

        for (BooleanClause clause : query.clauses()) {
            //check if the query is a term Query on _index. If there is no _index, we consider the query invalid. We also check if the query is a BooleanQuery 
            // if the query is a BooleanQuery. 
            Query cq = clause.getQuery();
            if (cq instanceof BooleanQuery) {
                Set<String> clauseValidIndices = validateBooleanQuery((BooleanQuery) cq, validIndices);
                if (clauseValidIndices != null && !clauseValidIndices.isEmpty()) {
                    //if the boolean query is valid, we add the new Indexes
                    newValidIndices.addAll(clauseValidIndices);
                } else //here we can consider the query invalid : SHOULD + no Index means the query try to search on _all
                {
                    if (clause.getOccur().equals(BooleanClause.Occur.SHOULD)) {
                        //here we can consider the query invalid : SHOULD + no Index means the query try to search on _all
                        return null;
                    }
                }
            } else if (cq instanceof TermQuery) {
                //we check here that the field searched is indeed an _index:, if not, we flag the Query as Invalid. 
                TermQuery tq = (TermQuery) cq;
                if (tq.getTerm().field().equals("_index")) {
                    newValidIndices.add(tq.getTerm().text());
                } else if (clause.getOccur().equals(BooleanClause.Occur.SHOULD)) {
                    //here we can consider the query invalid : SHOULD + no Index means the query try to search on _all
                    return null;
                }
            } else {
                //we don't analayze other type of Query, so we consider it invalid
                return null;
            }
        }

        validIndices.addAll(newValidIndices);

        return validIndices;
    }

}
