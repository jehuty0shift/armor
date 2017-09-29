package com.petalmd.armor.filter;

import com.petalmd.armor.authentication.User;
import com.petalmd.armor.service.ArmorConfigService;
import com.petalmd.armor.service.ArmorService;
import com.petalmd.armor.util.ArmorConstants;
import com.petalmd.armor.util.ConfigConstants;
import com.petalmd.armor.util.SecurityUtil;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ElasticsearchParseException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.search.MultiSearchRequest;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLoggerFactory;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.search.aggregations.AggregationBuilder;
import org.elasticsearch.search.aggregations.AggregatorFactories;
import org.elasticsearch.search.aggregations.bucket.significant.SignificantTermsAggregationBuilder;
import org.elasticsearch.search.aggregations.bucket.terms.TermsAggregationBuilder;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;

import java.util.List;

/**
 * Created by bdiasse on 20/02/17.
 */
public class AggregationFilter extends AbstractActionFilter {

    protected final Logger log = ESLoggerFactory.getLogger(this.getClass());
    private final boolean enabled;

    private static final String MIN_DOC_COUNT_KEY = "min_doc_count";


    @Inject
    public AggregationFilter(final Settings settings, final ClusterService clusterService, final ThreadPool threadPool, final ArmorService armorService, final ArmorConfigService armorConfigService ) {
        super(settings, armorService.getAuthenticationBackend(), armorService.getAuthorizator(), clusterService, armorConfigService, armorService.getAuditListener(), threadPool);
        enabled = settings.getAsBoolean(ConfigConstants.ARMOR_AGGREGATION_FILTER_ENABLED, false);

    }


    public void applySecure(Task task, final String action, final ActionRequest request, final ActionListener listener, final ActionFilterChain chain) {

        if (!enabled) {
            chain.proceed(task, action, request, listener);
            return;
        }

        final ThreadContext threadContext = threadpool.getThreadContext();

        final User user = threadContext.getTransient(ArmorConstants.ARMOR_AUTHENTICATED_USER);
        final Object authHeader = threadContext.getHeader(ArmorConstants.ARMOR_AUTHENTICATED_TRANSPORT_REQUEST);

        log.trace("user {}", user);

        if (user == null) {

            if (authHeader == null || !(authHeader instanceof String)) {
                log.error("not authenticated");
                throw new ElasticsearchException("not authenticated");
            }

            final Object decrypted = SecurityUtil.decryptAnDeserializeObject((String) authHeader, ArmorService.getSecretKey());

            if (decrypted == null || !(decrypted instanceof String) || !decrypted.equals("authorized")) {
                log.error("bad authenticated");
                throw new ElasticsearchException("bad authentication");
            }

        }

        //here we know that we either have a non null user or an internally authenticated internode request
        //this filter does not evaluate the token (this is done in armor action filter).

        if (request instanceof SearchRequest) {
            filterSearchRequest((SearchRequest) request);
        }

        if (request instanceof MultiSearchRequest) {
            MultiSearchRequest msr = (MultiSearchRequest) request;
            for (SearchRequest sr : msr.requests()) {
                filterSearchRequest(sr);
            }
        }


        chain.proceed(task, action, request, listener);

    }


    private void filterSearchRequest(SearchRequest sr) {
        try {
            log.debug("applying SearchRequest");
            SearchSourceBuilder searchSourceBuilder;
            searchSourceBuilder = sr.source();
            AggregatorFactories.Builder aggregations = searchSourceBuilder.aggregations();
            List<AggregationBuilder> aggBuilders = aggregations.getAggregatorFactories();
            for (AggregationBuilder aggBuilder : aggBuilders) {
                switch (aggBuilder.getType()) {
                    case "terms":
                        TermsAggregationBuilder termsAggs = (TermsAggregationBuilder) aggBuilder;
                        termsAggs.minDocCount(1);
                        break;
                    case "significant_terms":
                        SignificantTermsAggregationBuilder sigTermsAggsBuilder = (SignificantTermsAggregationBuilder) aggBuilder;
                        sigTermsAggsBuilder.minDocCount(1);
                        break;
                    default:
                        break;
                }
            }
//            for (int i = 0; i < 2; i++) {
//                final SourceLookup sl = new SourceLookup();
//                if (i == 0) {
//                    source = sr.source();
//                } else {
//                    source = sr.extraSource();
//                }
//                if (source != null && source.length() > 0) {
//                    sl.setSource(source);
//                    if (sl.isEmpty()) { //WARNING : this also initialize the sourceLookup for following sl.source() call, so DO NOT REMOVE.
//                        continue;
//                    }
//                    Map<String, Object> sourceMap = sl.source();
//                    if (sourceMap.containsKey("aggregations")) {
//                        Map<String, Object> aggregations = (Map<String, Object>) sourceMap.get("aggregations");
//                        replaceMinDocsCount(aggregations);
//                        sourceMap.put("aggregations", aggregations);
//                    }
//                    if (sourceMap.containsKey("aggs")) {
//                        Map<String, Object> aggs = (Map<String, Object>) sourceMap.get("aggs");
//                        replaceMinDocsCount(aggs);
//                        sourceMap.put("aggs", aggs);
//                    }
//                    if (i == 0) {
//                        sr.source(XContentFactory.jsonBuilder().map(sourceMap).bytes());
//                    } else {
//                        sr.extraSource(XContentFactory.jsonBuilder().map(sourceMap).bytes());
//                    }
//                }
//            }

            } catch(Exception e){
                e.printStackTrace();
                throw new ElasticsearchParseException("Unable to filter min_docs_count", e);
            }


        }

//    private void replaceMinDocsCount(Map<String, Object> aggTree) {
//        if (aggTree == null) {
//            return;
//        }
//        Iterator<Map.Entry<String, Object>> it = aggTree.entrySet().iterator();
//        while (it.hasNext()) {
//            Map.Entry<String, Object> entry = it.next();
//            if (entry.getKey().equals("terms") || entry.getKey().equals("significant_terms")) {
//                if (entry.getValue() instanceof Map) {
//                    Map<String, Object> termsAggs = (Map<String, Object>) entry.getValue();
//                    if (termsAggs != null && termsAggs.containsKey(MIN_DOC_COUNT_KEY) && termsAggs.get(MIN_DOC_COUNT_KEY) instanceof Integer && (Integer) termsAggs.get(MIN_DOC_COUNT_KEY) == 0) {
//                        termsAggs.put(MIN_DOC_COUNT_KEY, 1);
//                        continue;
//                    }
//                }
//            }
//            if (entry.getValue() instanceof Map) {
//                replaceMinDocsCount((Map<String, Object>) entry.getValue());
//            }
//        }
//    }

}
