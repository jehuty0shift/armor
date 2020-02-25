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
import org.apache.logging.log4j.Logger;
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
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import org.elasticsearch.search.fetch.StoredFieldsContext;
import org.elasticsearch.search.fetch.subphase.FetchSourceContext;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;

import java.util.*;
import java.util.Map.Entry;

public class FLSActionFilter extends AbstractActionFilter {

    private final String filterType = "flsfilter";
    private final Logger log = LogManager.getLogger(FLSActionFilter.class);
    private final Map<String, Tuple<List<String>, List<String>>> filterMap = new HashMap<String, Tuple<List<String>, List<String>>>();
    private final Client client;
    protected final boolean rewriteGetAsSearch;

    @Inject
    public FLSActionFilter(final Settings settings, final Client client, final ClusterService clusterService, final ThreadPool threadPool, final ArmorService armorService, final ArmorConfigService armorConfigService) {
        super(settings, armorService.getAuthenticationBackend(), armorService.getAuthorizator(), clusterService, armorService, armorConfigService, armorService.getAuditListener(), threadPool);

        this.client = client;

        final List<String> arFilters = settings.getAsList(ConfigConstants.ARMOR_FLSFILTER);
        for (String filterName : arFilters) {

            final List<String> sourceIncludes = settings.getAsList("armor." + filterType + "." + filterName
                    + ".source_includes", Collections.emptyList());
            final List<String> sourceExcludes = settings.getAsList("armor." + filterType + "." + filterName
                    + ".source_excludes", Collections.emptyList());

            filterMap.put(filterName, new Tuple<>(sourceIncludes, sourceExcludes));
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

        final List<String> FLSfilters = new ArrayList<>();
        for (final Iterator<Entry<String, Tuple<List<String>, List<String>>>> it = filterMap.entrySet().iterator(); it.hasNext(); ) {

            final Entry<String, Tuple<List<String>, List<String>>> entry = it.next();

            final String filterName = entry.getKey();
            final List<String> sourceIncludes = entry.getValue().v1();
            final List<String> sourceExcludes = entry.getValue().v2();

            threadContext.putTransient("armor." + filterType + "." + filterName + ".source_includes", sourceIncludes);
            threadContext.putTransient("armor." + filterType + "." + filterName + ".source_excludes", sourceExcludes);

            if (threadContext.getTransient(ArmorConstants.ARMOR_FILTER) != null && filterType != null) {
                if (!((List<String>) threadContext.getTransient(ArmorConstants.ARMOR_FILTER)).contains(filterType + "." + filterName)) {
                    ((List<String>) threadContext.getTransient(ArmorConstants.ARMOR_FILTER)).add(filterType + "." + filterName);
                    FLSfilters.add(filterType + "." + filterName);
                }
            } else if (filterType != null) {
                FLSfilters.add(filterType + "." + filterName);
                threadContext.putTransient(ArmorConstants.ARMOR_FILTER, FLSfilters);
            }

            log.trace("armor." + filterType + "." + filterName + ".source_includes", sourceIncludes);
            log.trace("armor." + filterType + "." + filterName + ".source_excludes", sourceExcludes);

        }
        final User user = threadContext.getTransient(ArmorConstants.ARMOR_AUTHENTICATED_USER);
        final String authHeader = threadContext.getHeader(ArmorConstants.ARMOR_AUTHENTICATED_TRANSPORT_REQUEST);

        final Evaluator evaluator;

        try {
            evaluator = getFromContextOrHeader(ArmorConstants.ARMOR_AC_EVALUATOR, threadContext, getEvaluator(request, action, user, threadContext));
        } catch (ForbiddenException e) {
            listener.onFailure(e);
            log.error("forbidden action", e);
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
        log.trace("filter for {}", FLSfilters);
        List<String> sourceIncludes = new ArrayList<>();
        List<String> sourceExcludes = new ArrayList<>();
        EvalResult evalResult = evaluator.evaluateFLS(FLSfilters);

        if(evalResult.filters.isEmpty()) {
            chain.proceed(task,action,request,listener);
            return;
        }

        //add the sourceInclude/Exclude for filters.
        for (String filter : evalResult.filters) {
            final String[] f = filter.split("\\.");
            final String ft = f[0];
            final String fn = f[1];

            log.trace("Apply {}/{} for {}", ft, fn, request.getClass());
            sourceIncludes.addAll(filterMap.get(fn).v1());
            sourceExcludes.addAll(filterMap.get(fn).v2());
        }

        if (rewriteGetAsSearch && request instanceof GetRequest) {
            SearchRequest sr = toSearchRequest((GetRequest) request);
            if (addFiltersToSearchRequest(sr, user, sourceIncludes, sourceExcludes) != null) {
                this.doGetFromSearchRequest((GetRequest) request, sr, listener, client);
            } else {
                log.warn("Error during the parsing of the SearchRequest, aborting the request");
            }
            return;

        } else if (rewriteGetAsSearch && request instanceof MultiGetRequest) {
            log.debug("Rewrite GetRequest as SearchRequest");
            MultiGetRequest multiGetRequest = (MultiGetRequest) request;
            MultiSearchRequest mSRequest = toMultiSearchRequest(multiGetRequest);
            for (SearchRequest sr : mSRequest.requests()) {
                if (addFiltersToSearchRequest(sr, user, sourceIncludes, sourceExcludes) == null) {
                    log.warn("Couldn't parse this request in MultiSearch Request, aborting the Request");
                    return;
                }
            }
            this.doGetFromSearchRequest((MultiGetRequest) request, toMultiSearchRequest((MultiGetRequest) request), listener, client);
            return;
        }

        if (request instanceof SearchRequest) {
            log.debug("Search Request Rewrite");
            if (addFiltersToSearchRequest((SearchRequest) request, user, sourceIncludes, sourceExcludes) == null) {
                log.warn("couldn't rewrite the search, Aborting the request");
                return;
            }
        } else if (request instanceof MultiSearchRequest) {
            log.debug("MultiSearchRequestRewrite");
            for (SearchRequest sr : ((MultiSearchRequest) request).requests()) {
                if (addFiltersToSearchRequest(sr, user, sourceIncludes, sourceExcludes) == null) {
                    log.warn("Couldn't parse this multiSearchRequest, aborting the request");
                    return;
                }
            }
        }

        chain.proceed(task, action, request, listener);
    }

    private SearchRequest addFiltersToSearchRequest(SearchRequest sr, final User user, final List<String> sourceIncludes, final List<String> sourceExcludes) {

        if (log.isDebugEnabled()) {
            log.debug("Modifiy search filters for query {} and index {} requested from {} and {}/[Includes: {}, Excludes: {}]", "SearchRequest",
                    Arrays.toString(sr.indices()), sr.remoteAddress(), filterType, Arrays.toString(sourceIncludes.toArray()), Arrays.toString(sourceExcludes.toArray()));
        }

        if (sourceIncludes.isEmpty() && sourceExcludes.isEmpty()) {
            return sr;
        }

        SearchSourceBuilder source = sr.source();
        if (source.docValueFields() != null && !source.docValueFields().isEmpty()) {
            source.docValueFields().clear();
        }
        if (source.scriptFields() != null && !source.scriptFields().isEmpty()) {
            source.scriptFields().clear();
        }
        if (source.storedFields() != null) {
            //remove script Fields and doc_values fields;

            //fields parameter
            StoredFieldsContext storedFieldsContext = source.storedFields();
            if (storedFieldsContext != null && (storedFieldsContext.fetchFields() == true || !storedFieldsContext.fieldNames().isEmpty())) {
                final List<String> survivingFields = new ArrayList(storedFieldsContext.fieldNames());
                for (String field : storedFieldsContext.fieldNames()) {
                    for (final Iterator<String> iteratorExcludes = sourceExcludes.iterator(); iteratorExcludes.hasNext(); ) {
                        final String exclude = iteratorExcludes.next();
                        if (field.startsWith("_source.") || SecurityUtil.isWildcardMatch(field, exclude, false)) { //we remove any field request starting with '_source.' since it should not be used (If the field is legit, it works without prefixing by '_source.').
                            survivingFields.remove(field);
                        }
                    }
                }
                log.trace("survivingFields with stored Fields {}", survivingFields.toString());

                source.storedFields(StoredFieldsContext.fromList(survivingFields));
            }
        } else {

            //fields parameter
            FetchSourceContext fetchSourceContext = source.fetchSource();
            if (fetchSourceContext == null) {
                //fetch source if sourceExclude does not contains source
                //if sourceIncludes is empty, then  add "*"
                if (sourceIncludes.isEmpty()) {
                    sourceIncludes.add("*");
                }
                source.fetchSource(new FetchSourceContext(!sourceExcludes.contains("_source"), sourceIncludes.toArray(new String[sourceIncludes.size()]), sourceExcludes.toArray(new String[sourceExcludes.size()])));
            } else {
                if (fetchSourceContext.fetchSource() == true || (fetchSourceContext.includes() != null && fetchSourceContext.includes().length > 0)) {
                    final String[] fields = fetchSourceContext.includes();
                    final List<String> survivingFields = new ArrayList(Arrays.asList(fields));

                    for (String field : fields) {
                        for (final Iterator<String> iteratorExcludes = sourceExcludes.iterator(); iteratorExcludes.hasNext(); ) {
                            final String exclude = iteratorExcludes.next();
                            if (field.startsWith("_source.") || SecurityUtil.isWildcardMatch(field, exclude, false)) { //we remove any field request starting with '_source.' since it should not be used (If the field is legit, it works without prefixing by '_source.').
                                survivingFields.remove(field);
                            }
                        }
                    }
                    log.trace("survivingFields with FetchSource {}", survivingFields.toString());

                    List<String> finalSourceExcludes = new ArrayList(sourceExcludes);
                    finalSourceExcludes.addAll(Arrays.asList(fetchSourceContext.excludes()));
                    source.fetchSource(new FetchSourceContext(true, survivingFields.toArray(new String[survivingFields.size()]), finalSourceExcludes.toArray(new String[finalSourceExcludes.size()])));

                }
            }
        }
        sr.source(source);
        return sr;
    }
}
