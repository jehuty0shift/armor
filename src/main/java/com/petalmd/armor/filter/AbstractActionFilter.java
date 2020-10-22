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
import com.petalmd.armor.authentication.AuthCredentials;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authentication.backend.AuthenticationBackend;
import com.petalmd.armor.authorization.Authorizator;
import com.petalmd.armor.authorization.ForbiddenException;
import com.petalmd.armor.service.ArmorConfigService;
import com.petalmd.armor.service.ArmorService;
import com.petalmd.armor.tokeneval.Evaluator;
import com.petalmd.armor.tokeneval.MalformedConfigurationException;
import com.petalmd.armor.tokeneval.TokenEvaluator;
import com.petalmd.armor.util.ArmorConstants;
import com.petalmd.armor.util.ConfigConstants;
import com.petalmd.armor.util.SecurityUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.action.*;
import org.elasticsearch.action.get.*;
import org.elasticsearch.action.get.MultiGetRequest.Item;
import org.elasticsearch.action.search.MultiSearchRequest;
import org.elasticsearch.action.search.MultiSearchResponse;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.action.support.ActionFilter;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.metadata.IndexAbstraction;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.index.get.GetResult;
import org.elasticsearch.index.query.IdsQueryBuilder;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

public abstract class AbstractActionFilter implements ActionFilter {

    private final Logger log = LogManager.getLogger(this.getClass());
    protected final Settings settings;
    protected final AuthenticationBackend authBackend;
    protected final AuditListener auditListener;
    protected final Authorizator authorizator;
    protected final ArmorService armorService;
    protected final ClusterService clusterService;
    protected final ArmorConfigService armorConfigService;
    protected final ThreadPool threadpool;

    @Override
    public int order() {
        return Integer.MIN_VALUE;
    }

    protected AbstractActionFilter(final Settings settings, final AuthenticationBackend authBackend, final Authorizator authorizator,
                                   final ClusterService clusterService, final ArmorService armorService, final ArmorConfigService armorConfigService, final AuditListener auditListener, final ThreadPool threadpool) {
        this.settings = settings;
        this.authorizator = authorizator;
        this.authBackend = authBackend;
        this.clusterService = clusterService;
        this.armorService = armorService;
        this.armorConfigService = armorConfigService;
        this.auditListener = auditListener;
        this.threadpool = threadpool;
    }

    @Override
    public final void apply(Task task, final String action, final ActionRequest request, final ActionListener listener, final ActionFilterChain chain) {
        log.trace("REQUEST on node {}: {} ({}) from {}", clusterService.localNode().getName(), action, request.getClass(),
                request.remoteAddress() == null ? "INTRANODE" : request.remoteAddress().toString());
        //log.debug("Context {}", request.getContext());
        ThreadContext threadContext = threadpool.getThreadContext();
        log.trace("Headers {}", threadContext.getHeaders());

        if (settings.getAsBoolean(ConfigConstants.ARMOR_ALLOW_KIBANA_ACTIONS, true) && (action.startsWith("cluster:monitor/") || action.contains("indices:data/read/field_stats"))) {
            chain.proceed(task, action, request, listener);
            return;
        }

        //allow all if request is coming from loopback
        Boolean isLoopback = threadContext.getTransient(ArmorConstants.ARMOR_IS_LOOPBACK);

        if (isLoopback != null && isLoopback == true) {
            log.debug("This is a connection from localhost/loopback, will allow all because of " + ConfigConstants.ARMOR_ALLOW_ALL_FROM_LOOPBACK + " setting.");
            chain.proceed(task, action, request, listener);
            return;
        }

        AtomicBoolean isRequestExternal = threadContext.getTransient(ArmorConstants.ARMOR_REQUEST_IS_EXTERNAL);


        //TODO: check that THIS is done properly ! !
        final boolean intraNodeRequest = request.remoteAddress() == null;

        if (intraNodeRequest && (isRequestExternal == null || isRequestExternal.get() == false)) {
            log.trace("TYPE: intra node request, skip filters");
            chain.proceed(task, action, request, listener);
            return;
        }

        final User restUser = threadContext.getTransient(ArmorConstants.ARMOR_AUTHENTICATED_USER);

        final boolean restAuthenticated = restUser != null;

        if (restAuthenticated) {
            log.debug("TYPE: rest authenticated request, apply filters");
            applySecure(task, action, request, listener, chain);
            return;
        }

        final String authHeader = threadContext.getHeader(ArmorConstants.ARMOR_AUTHENTICATED_TRANSPORT_REQUEST);
        boolean interNodeAuthenticated = false;

        if (authHeader != null) {
            final Object decrypted = SecurityUtil.decryptAnDeserializeObject(authHeader, ArmorService.getSecretKey());

            if (decrypted != null && (decrypted instanceof String) && decrypted.equals("authorized")) {
                interNodeAuthenticated = true;
            }

        }


        if (interNodeAuthenticated || isRequestExternal == null || isRequestExternal.get() == false) {
            log.trace("TYPE: inter node cluster request, skip filters");
            chain.proceed(task, action, request, listener);
            return;
        } else {
            log.debug("Request is external, evaluating filters.");
        }

        final String transportCreds = threadContext.getHeader(ArmorConstants.ARMOR_TRANSPORT_CREDS);
        User authenticatedTransportUser = null;
        if (transportCreds != null
                && settings.getAsBoolean(ConfigConstants.ARMOR_TRANSPORT_AUTH_ENABLED, false)) {

            try {

                final String decodedBasicHeader = new String(Base64.getDecoder().decode(transportCreds),
                        StandardCharsets.US_ASCII);

                final String username = decodedBasicHeader.split(":")[0];
                final char[] password = decodedBasicHeader.split(":")[1].toCharArray();

                authenticatedTransportUser = authBackend.authenticate(new AuthCredentials(username, password));
                authorizator.fillRoles(authenticatedTransportUser, new AuthCredentials(authenticatedTransportUser.getName(), null));
                threadContext.putTransient(ArmorConstants.ARMOR_AUTHENTICATED_USER, authenticatedTransportUser);
            } catch (final Exception e) {
                throw new RuntimeException("Transport authentication failed due to " + e, e);
            }

        }

        boolean transportAuthenticated = authenticatedTransportUser != null;

        if (transportAuthenticated) {
            log.debug("TYPE: transport authenticated request, apply filters");
            applySecure(task, action, request, listener, chain);
            return;
        }

        throw new RuntimeException("Unauthenticated request (ARMOR_UNAUTH_REQ) for action " + action);
    }

    public abstract void applySecure(Task task, final String action, final ActionRequest request, final ActionListener listener,
                                     final ActionFilterChain chain);


    protected <T> T getFromContextOrHeader(final String key, final ThreadContext threadContext, final T defaultValue) {

        if (threadContext.getTransient(key) != null) {
            return threadContext.getTransient(key);
        }

        if (threadContext.getHeader(key) != null) {
            return (T) SecurityUtil.decryptAnDeserializeObject(threadContext.getHeader(key), ArmorService.getSecretKey());
        }

        return defaultValue;
    }

    protected SearchRequest toSearchRequest(final GetRequest request) {

        final SearchRequest searchRequest = new SearchRequest();
        searchRequest.routing(request.routing());
        searchRequest.preference(request.preference());
        searchRequest.indices(request.indices());
        searchRequest.source(SearchSourceBuilder.searchSource().query(new IdsQueryBuilder().addIds(request.id())));
        return searchRequest;

    }

    protected MultiSearchRequest toMultiSearchRequest(final MultiGetRequest multiGetRequest) {

        final MultiSearchRequest msearch = new MultiSearchRequest();

        for (final Iterator<Item> iterator = multiGetRequest.iterator(); iterator.hasNext(); ) {
            final Item item = iterator.next();

            final SearchRequest st = new SearchRequest();
            st.routing(item.routing());
            st.indices(item.indices());
            st.preference(multiGetRequest.preference());
            st.source(SearchSourceBuilder.searchSource().query(new IdsQueryBuilder().types(item.type()).addIds(item.id())));
            msearch.add(st);
        }

        return msearch;

    }

    protected void doGetFromSearchRequest(final GetRequest getRequest, final SearchRequest searchRequest, final ActionListener listener, final Client client) {
        client.search(searchRequest, new SearchDelegatingActionListener(listener));
    }

    private static class SearchDelegatingActionListener<Response extends ActionResponse> implements ActionListener<Response> {

        private final ActionListener<GetResponse> privListener;

        public SearchDelegatingActionListener(ActionListener<GetResponse> listener) {
            this.privListener = listener;
        }

        @Override
        public void onResponse(final Response response) {
            if (response instanceof SearchResponse) {
                SearchResponse searchResponse = (SearchResponse) response;
                if (searchResponse.getHits().getTotalHits().value > 1) {
                    privListener.onFailure(new ElasticsearchException("An unexpected failure has happened during get"));
                } else {
                    final SearchHit sh = searchResponse.getHits().getHits()[0];
                    privListener.onResponse(new GetResponse(new GetResult(sh.getIndex(), sh.getType(), sh.getId(), 1, 0, sh.getVersion(), true, sh.getSourceRef(), sh.getFields(), Collections.emptyMap())));
                }
            }
        }

        @Override
        public void onFailure(Exception e) {
            privListener.onFailure(e);
        }
    }


    protected void doGetFromSearchRequest(final MultiGetRequest getRequest, final MultiSearchRequest searchRequest, final ActionListener listener, final Client client) {
        client.multiSearch(searchRequest, new MultiSearchDelegatingActionListener(listener));
    }

    private static class MultiSearchDelegatingActionListener<Response extends ActionResponse> implements ActionListener<Response> {

        private final ActionListener<MultiGetResponse> privListener;

        public MultiSearchDelegatingActionListener(ActionListener<MultiGetResponse> listener) {
            this.privListener = listener;
        }

        @Override
        public void onResponse(final Response response) {

            if (response instanceof MultiSearchResponse) {
                MultiSearchResponse searchResponse = (MultiSearchResponse) response;
                List<MultiGetItemResponse> mGetItemResponseList = new ArrayList<>();
                for (org.elasticsearch.action.search.MultiSearchResponse.Item item : searchResponse.getResponses()) {
                    final SearchHit sh = item.getResponse().getHits().getHits()[0];
                    MultiGetItemResponse itemResponse = new MultiGetItemResponse(new GetResponse(new GetResult(sh.getIndex(),
                            sh.getType(),
                            sh.getId(),
                            1, 0, sh.getVersion(), true, sh.getSourceRef(), sh.getFields(), Collections.emptyMap())), null);
                    mGetItemResponseList.add(itemResponse);
                }

                privListener.onResponse(new MultiGetResponse(mGetItemResponseList.toArray(new MultiGetItemResponse[mGetItemResponseList.size()])));
            }
        }

        @Override
        public void onFailure(Exception e) {
            privListener.onFailure(e);
        }

    }

    protected Evaluator getEvaluator(final ActionRequest request, final String action, final User user, final ThreadContext threadContext) {

        final List<String> ci = new ArrayList<String>();
        final List<String> aliases = new ArrayList<String>();
        final List<String> types = new ArrayList<String>();
        final TokenEvaluator evaluator = new TokenEvaluator(armorConfigService.getSecurityConfiguration());
        final SortedMap<String, IndexAbstraction> aliasesAndIndexMap = clusterService.state().metadata().getIndicesLookup();


        final boolean allowedForAllIndices = !SecurityUtil.isWildcardMatch(action, "*put*", false)
                && !SecurityUtil.isWildcardMatch(action, "*delete*", false)
                && !SecurityUtil.isWildcardMatch(action, "indices:data*", false)
                && !SecurityUtil.isWildcardMatch(action, "cluster:admin*", false)
                && !SecurityUtil.isWildcardMatch(action, "*close*", false) && !SecurityUtil.isWildcardMatch(action, "*open*", false)
                && !SecurityUtil.isWildcardMatch(action, "*update*", false) && !SecurityUtil.isWildcardMatch(action, "*create*", false);

        if (request instanceof IndicesRequest) {
            final IndicesRequest ir = (IndicesRequest) request;
            addType(ir, types, action);
            log.trace("Indices {}", Arrays.toString(ir.indices()));
            log.trace("Indices opts allowNoIndices {}", ir.indicesOptions().allowNoIndices());
            log.trace("Indices opts expandWildcardsOpen {}", ir.indicesOptions().expandWildcardsOpen());

            try {
                ci.addAll(FilterHelper.getOnlyIndices(Arrays.asList(ir.indices()), aliasesAndIndexMap));
                aliases.addAll(FilterHelper.getOnlyAliases(Arrays.asList(ir.indices()), aliasesAndIndexMap));
            } catch (java.lang.NullPointerException e) {
            }

            if (!allowedForAllIndices && (ir.indices() == null || Arrays.asList(ir.indices()).contains("_all") || ir.indices().length == 0)) {
                log.error("Attempt from {} to _all indices for {} and {}", request.remoteAddress(), action, user);
                threadContext.putTransient(AuditListener.AUDIT_ITEMS, Arrays.asList(ir.indices()));
                auditListener.onMissingPrivileges(user == null ? "unknown" : user.getName(), request, threadContext);
                throw new ForbiddenException("Attempt from {} to _all indices for {} and {}", request.remoteAddress(), action, user);
            }

        }


        if (request instanceof CompositeIndicesRequest) {
            final RequestItemDetails cirDetails = RequestItemDetails.fromCompositeIndicesRequest((CompositeIndicesRequest) request);
            log.trace("Indices {}", cirDetails.getIndices().toString());
            ci.addAll(FilterHelper.getOnlyIndices(cirDetails.getIndices(), aliasesAndIndexMap));
            aliases.addAll(FilterHelper.getOnlyAliases(cirDetails.getIndices(), aliasesAndIndexMap));

            if (!allowedForAllIndices && (cirDetails.getIndices() == null || Arrays.asList(cirDetails.getIndices()).contains("_all") || cirDetails.getIndices().size() == 0)) {
                log.error("Attempt from {} to _all indices for {} and {}", request.remoteAddress(), action, user);
                threadContext.putTransient(AuditListener.AUDIT_ITEMS, new ArrayList<>(cirDetails.getIndices()));
                auditListener.onMissingPrivileges(user == null ? "unknown" : user.getName(), request, threadContext);
                throw new ForbiddenException("Attempt from {} to _all indices for {} and {}", request.remoteAddress(), action, user);
            }


        }

        if (!settings.getAsBoolean(ConfigConstants.ARMOR_ALLOW_NON_LOOPBACK_QUERY_ON_ARMOR_INDEX, false) && ci.contains(settings.get(ConfigConstants.ARMOR_CONFIG_INDEX_NAME, ConfigConstants.DEFAULT_SECURITY_CONFIG_INDEX))) {
            log.error("Attempt from " + request.remoteAddress() + " on " + settings.get(ConfigConstants.ARMOR_CONFIG_INDEX_NAME, ConfigConstants.DEFAULT_SECURITY_CONFIG_INDEX));
            List<String> itemList = new ArrayList<>();
            itemList.addAll(ci);
            itemList.addAll(aliases);
            threadContext.putTransient(AuditListener.AUDIT_ITEMS, itemList);
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

        try {
            boolean indicesLikeAliases = settings.getAsBoolean(ConfigConstants.ARMOR_ACTION_INDICES_LIKE_ALIASES, true);
            final Evaluator eval = evaluator.getEvaluator(ci, aliases, types, resolvedAddress, user, indicesLikeAliases);
            if (threadContext.getTransient(ArmorConstants.ARMOR_AC_EVALUATOR) == null) {
                threadContext.putTransient(ArmorConstants.ARMOR_AC_EVALUATOR, eval);
            }
            //put aliases for Kefla Filter
            if (threadContext.getTransient(ArmorConstants.ARMOR_KEFLA_ALIASES) == null) {
                threadContext.putTransient(ArmorConstants.ARMOR_KEFLA_ALIASES, aliases);
            }
            return eval;
        } catch (MalformedConfigurationException ex) {
            log.warn("Error in configuration");
            return null;
        }
    }


    protected void addType(final IndicesRequest request, final List<String> typesl, final String action) {

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
