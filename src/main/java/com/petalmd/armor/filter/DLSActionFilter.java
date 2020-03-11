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

import com.petalmd.armor.authentication.LdapUser;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authorization.ForbiddenException;
import com.petalmd.armor.service.ArmorConfigService;
import com.petalmd.armor.service.ArmorService;
import com.petalmd.armor.tokeneval.EvalResult;
import com.petalmd.armor.tokeneval.Evaluator;
import com.petalmd.armor.tokeneval.TokenEvaluator;
import com.petalmd.armor.util.ArmorConstants;
import com.petalmd.armor.util.ConfigConstants;
import com.petalmd.armor.util.SecurityUtil;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.LogManager;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.get.GetRequest;
import org.elasticsearch.action.get.MultiGetRequest;
import org.elasticsearch.action.search.MultiSearchRequest;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.io.stream.BytesStreamOutput;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.index.query.BoolQueryBuilder;
import org.elasticsearch.index.query.ExistsQueryBuilder;
import org.elasticsearch.index.query.QueryBuilder;
import org.elasticsearch.index.query.TermQueryBuilder;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;

import java.io.IOException;
import java.util.*;
import java.util.Map.Entry;

public class DLSActionFilter extends AbstractActionFilter {

    private final String filterType = "dlsfilter";
    private final Logger log = LogManager.getLogger(DLSActionFilter.class);
    private final Map<String, List<String>> filterMap = new HashMap<String, List<String>>();
    private final Client client;
    protected final boolean rewriteGetAsSearch;

    @Inject
    public DLSActionFilter(final Settings settings, final Client client, final ClusterService clusterService, final ThreadPool threadPool, final ArmorService armorService, final ArmorConfigService armorConfigService) {
        super(settings, armorService.getAuthenticationBackend(), armorService.getAuthorizator(), clusterService, armorService, armorConfigService, armorService.getAuditListener(), threadPool);
        this.client = client;

        final List<String> arFilters = settings.getAsList(ConfigConstants.ARMOR_DLSFILTER);
        for (final String filterName : arFilters) {

            final List<String> filters = settings.getAsList("armor." + filterType + "." + filterName, Collections.emptyList());

            filterMap.put(filterName, filters);
        }

        this.rewriteGetAsSearch = settings.getAsBoolean(ConfigConstants.ARMOR_REWRITE_GET_AS_SEARCH, true);
    }


    @Override
    public int order() {
        return Integer.MIN_VALUE + 14;
    }

    @Override
    public void applySecure(Task task, final String action, final ActionRequest request, final ActionListener listener, final ActionFilterChain chain) {

        if (filterMap.size() == 0) {
            chain.proceed(task, action, request, listener);
            return;
        }

        ThreadContext threadContext = threadpool.getThreadContext();

        if (request instanceof SearchRequest || request instanceof MultiSearchRequest || request instanceof GetRequest
                || request instanceof MultiGetRequest) {

            final List<String> DLSFilters = new ArrayList<>();
            for (Map.Entry<String, List<String>> entry : filterMap.entrySet()) {

                final String filterName = entry.getKey();
                final List<String> documentsFiltered = entry.getValue();

                if (threadContext.getTransient(ArmorConstants.ARMOR_FILTER) != null) {
                    if (!((List<String>) threadContext.getTransient(ArmorConstants.ARMOR_FILTER)).contains(filterType + "." + filterName)) {
                        ((List<String>) threadContext.getTransient(ArmorConstants.ARMOR_FILTER)).add(filterType + "." + filterName);
                        DLSFilters.add(filterType + "." + filterName);
                    }
                } else {
                    DLSFilters.add(filterType + ":" + filterName);
                    threadContext.putTransient(ArmorConstants.ARMOR_FILTER, DLSFilters);
                }

                threadContext.putTransient("armor." + filterType + "." + filterName + ".filters", documentsFiltered);

                log.trace("armor." + filterType + "." + filterName + ".filters {}", documentsFiltered);
            }
            final User user = threadContext.getTransient(ArmorConstants.ARMOR_AUTHENTICATED_USER);
            final String authHeader = threadContext.getHeader(ArmorConstants.ARMOR_AUTHENTICATED_TRANSPORT_REQUEST);

            final Evaluator evaluator;

            try {
                evaluator = getFromContextOrHeader(ArmorConstants.ARMOR_AC_EVALUATOR, threadContext, getEvaluator(request, action, user, threadContext));
            } catch (ForbiddenException e) {
                listener.onFailure(e);
                log.error("forbidden action",e);
                return;
            }

            if (request.remoteAddress() == null && user == null) {
                log.trace("Return on INTERNODE request");
                return;
            }

            log.trace("user {}", user);

            if (user == null) {

                if (authHeader == null) {
                    log.error("not authenticated");
                    throw new ElasticsearchException("not authenticated");
                }

                final Object decrypted = SecurityUtil.decryptAnDeserializeObject((String) authHeader, armorService.getSecretKey());

                if (decrypted == null || !(decrypted instanceof String) || !decrypted.equals("authorized")) {
                    log.error("bad authenticated");
                    throw new ElasticsearchException("bad authentication");
                }

            }

            //here we know that we either have a non null user or an internally authenticated internode request
            log.trace("filter for {}", DLSFilters);
            EvalResult evalResult = evaluator.evaluateDLS(DLSFilters);

            if(evalResult.filters.isEmpty()) {
                chain.proceed(task,action,request,listener);
                return;
            }


            for (String executedFilter : evalResult.filters) {
                final String[] f = executedFilter.split("\\.");
                final String ft = f[0];
                final String fn = f[1];

                log.trace("Apply {}/{} for {}", ft, fn, request.getClass());

                if (rewriteGetAsSearch && request instanceof GetRequest) {
                    log.debug("Rewrite GetRequest as SearchRequest");
                    SearchRequest sr = toSearchRequest((GetRequest) request);
                    addFiltersToSearchRequest(sr, user, fn);
                    doGetFromSearchRequest((GetRequest) request, sr, listener, client);
                    return;
                }

                if (rewriteGetAsSearch && request instanceof MultiGetRequest) {
                    log.debug("Rewrite GetRequest as SearchRequest");
                    MultiGetRequest multiGetRequest = (MultiGetRequest) request;
                    MultiSearchRequest mSRequest = toMultiSearchRequest(multiGetRequest);
                    for (SearchRequest sr : mSRequest.requests()) {
                        addFiltersToSearchRequest(sr, user, fn);
                    }
                    this.doGetFromSearchRequest((MultiGetRequest) request, mSRequest, listener, client);
                    return;
                }

                if (request instanceof SearchRequest) {
                    log.debug("Search Request Rewrite");
                    addFiltersToSearchRequest((SearchRequest) request, user, fn);
                }

                if (request instanceof MultiSearchRequest) {
                    log.debug("MultiSearchRequestRewrite");
                    for (SearchRequest sr : ((MultiSearchRequest) request).requests()) {
                        addFiltersToSearchRequest(sr, user, fn);
                    }
                }
            }

        }
        chain.proceed(task, action, request, listener);
    }

    private SearchRequest addFiltersToSearchRequest(SearchRequest sr, final User user, String fn) {

        log.debug("Modifiy search filters for query {} and index {} requested from {} and {}/{}", "SearchRequest",
                Arrays.toString(sr.indices()), sr.remoteAddress(), "dlsfilter", fn);

        if (!filterMap.containsKey(fn)) {
            return sr;
        }

        final List<String> list = filterMap.get(fn);

        //log.trace("filterStrings {}", list);
        final List<QueryBuilder> qliste = new ArrayList<QueryBuilder>();

        if (list.isEmpty()) {
            return sr;
        }

        final String tfilterType = list.get(0);

        log.trace("DLS: {} {}", tfilterType, list);

        switch (tfilterType) {

            case "term": {

                final boolean negate = Boolean.parseBoolean(list.get(3));
                if (negate) {
                    qliste.add(new BoolQueryBuilder().mustNot(new TermQueryBuilder(list.get(1), list.get(2))));
                } else {
                    qliste.add(new BoolQueryBuilder().filter(new TermQueryBuilder(list.get(1), list.get(2))));
                }
            }

            break;
            case "user_name": {

                if (user == null) {
                    throw new ElasticsearchException("user is null");
                }

                final String field = list.get(1);
                final boolean negate = Boolean.parseBoolean(list.get(2));
                final String username = user.getName();
                if (negate) {
                    qliste.add(new BoolQueryBuilder().mustNot(new TermQueryBuilder(field, username)));
                } else {
                    qliste.add(new BoolQueryBuilder().filter(new TermQueryBuilder(field, username)));
                }
            }

            break;
            case "user_roles": {

                if (user == null) {
                    throw new ElasticsearchException("user is null");
                }

                final String field = list.get(1);
                final boolean negate = Boolean.parseBoolean(list.get(2));

                final List<QueryBuilder> inner = new ArrayList<QueryBuilder>();
                for (final Iterator iterator = user.getRoles().iterator(); iterator.hasNext(); ) {
                    final String role = (String) iterator.next();
                    if (negate) {
                        inner.add(new BoolQueryBuilder().mustNot(new TermQueryBuilder(field, role)));
                    } else {
                        inner.add(new TermQueryBuilder(field, role));
                    }
                }

                BoolQueryBuilder boolQueryBuilder = new BoolQueryBuilder();
                for (QueryBuilder innerFilter : inner) {
                    if (negate) {
                        boolQueryBuilder.filter(innerFilter);
                    } else {
                        boolQueryBuilder.should(innerFilter);
                    }
                }
                qliste.add(boolQueryBuilder);
            }

            break;
            case "ldap_user_attribute": {

                if (user == null) {
                    throw new ElasticsearchException("user is null");
                }

                if (!(user instanceof LdapUser)) {
                    throw new ElasticsearchException("user is not an ldapuser");
                }

                final LdapUser ldapUser = (LdapUser) user;

                final String field = list.get(1);
                final String attribute = list.get(2);
                final boolean negate = Boolean.parseBoolean(list.get(3));
                final Attribute attr = ldapUser.getUserEntry().get(attribute);

                if (attribute == null) {
                    break;
                }

                try {
                    if (negate) {
                        qliste.add(new BoolQueryBuilder().mustNot(new TermQueryBuilder(field, attr.getString())));
                    } else {
                        qliste.add(new BoolQueryBuilder().filter(new TermQueryBuilder(field, attr.getString())));
                    }
                } catch (final LdapInvalidAttributeValueException e) {
                    throw new RuntimeException("Error in ldap user attribute", e);
                }

            }
            break;
            case "ldap_user_roles": {

                if (user == null) {
                    throw new ElasticsearchException("user is null");
                }

                if (!(user instanceof LdapUser)) {
                    throw new ElasticsearchException("user is not an ldapuser");
                }

                final LdapUser ldapUser = (LdapUser) user;

                final String field = list.get(1);
                final String attribute = list.get(2);
                final boolean negate = Boolean.parseBoolean(list.get(3));

                final List<QueryBuilder> inner = new ArrayList<QueryBuilder>();
                for (final Iterator<org.apache.directory.api.ldap.model.entry.Entry> iterator = ldapUser.getRoleEntries().iterator(); iterator.hasNext(); ) {
                    final org.apache.directory.api.ldap.model.entry.Entry roleEntry = iterator.next();

                    try {

                        if (negate) {
                            qliste.add(new BoolQueryBuilder().mustNot(new TermQueryBuilder(field, roleEntry.get(attribute).getString())));
                        } else {
                            qliste.add(new BoolQueryBuilder().filter(new TermQueryBuilder(field, roleEntry.get(attribute).getString())));
                        }
                    } catch (final LdapInvalidAttributeValueException e) {
                        throw new RuntimeException("Error in ldap user attribute", e);
                    }

                }
                BoolQueryBuilder boolQueryBuilder = new BoolQueryBuilder();
                for (QueryBuilder innerFilter : inner) {
                    if (negate) {
                        boolQueryBuilder.filter(innerFilter);
                    } else {
                        boolQueryBuilder.should(innerFilter);
                    }
                }
                qliste.add(boolQueryBuilder);
            }

            break;
            case "exists": {
                final boolean negate = Boolean.parseBoolean(list.get(2));
                final ExistsQueryBuilder existQueryBuilder = new ExistsQueryBuilder(list.get(1));

                if (negate) {
                    qliste.add(new BoolQueryBuilder().mustNot(existQueryBuilder));
                } else {
                    qliste.add(new BoolQueryBuilder().filter(existQueryBuilder));
                }
            }
            break;
            default:
                break;
        }

        final BoolQueryBuilder dlsBoolQuery = new BoolQueryBuilder();
        for (QueryBuilder innerFilter : qliste) {
            dlsBoolQuery.filter(innerFilter);
        }

        if (!qliste.isEmpty()) {
            final BoolQueryBuilder sourceQueryBuilder = new BoolQueryBuilder();
            sourceQueryBuilder.filter(dlsBoolQuery);
            sourceQueryBuilder.must(sr.source().query());
            sr.source().query(sourceQueryBuilder);
        }
        if (log.isDebugEnabled()) {
            BytesStreamOutput sourceStream = new BytesStreamOutput();

            try {
                sr.source().writeTo(sourceStream);
                log.debug("Search request is now : \n" + sourceStream.bytes().utf8ToString());
            } catch (IOException e) {
                throw new IllegalStateException(e);
            } finally {
                sourceStream.close();
            }
        }

        return sr;

    }

}
