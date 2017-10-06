package com.petalmd.armor.filter;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.elasticsearch.cluster.ClusterModule;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLoggerFactory;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.json.JsonXContent;
import org.elasticsearch.index.query.QueryParseContext;
import org.elasticsearch.search.SearchModule;
import org.elasticsearch.search.aggregations.AggregationBuilder;
import org.elasticsearch.search.aggregations.AggregatorFactories;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import org.elasticsearch.search.rescore.RescoreBuilder;
import org.elasticsearch.search.sort.SortBuilder;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * Created by bdiasse on 20/02/17.
 */
public class AggregationFilter extends AbstractActionFilter {

    protected final Logger log = ESLoggerFactory.getLogger(this.getClass());
    private final boolean enabled;
    private NamedXContentRegistry xContentRegistry;
    private static final String MIN_DOC_COUNT_KEY = "min_doc_count";


    @Inject
    public AggregationFilter(final Settings settings, final ClusterService clusterService, final ThreadPool threadPool, final ArmorService armorService, final ArmorConfigService armorConfigService, final NamedXContentRegistry xContentRegistry) {
        super(settings, armorService.getAuthenticationBackend(), armorService.getAuthorizator(), clusterService, armorConfigService, armorService.getAuditListener(), threadPool);
        enabled = settings.getAsBoolean(ConfigConstants.ARMOR_AGGREGATION_FILTER_ENABLED, false);
        this.xContentRegistry = xContentRegistry;
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
            if(aggregations == null){
                return;
            }
            XContentBuilder jsonContent = JsonXContent.contentBuilder();
            jsonContent.generator();
            jsonContent = aggregations.toXContent(jsonContent,null);
            jsonContent.close();
            String aggregationString = jsonContent.string();
            ObjectMapper mapper = new ObjectMapper();
            TypeReference<HashMap<String,Object>> typeRef = new TypeReference<HashMap<String,Object>>(){};
            HashMap<String,Object> aggregationMap = mapper.readValue(aggregationString,(TypeReference)typeRef);
            replaceMinDocsCount(aggregationMap);
            XContentParser aggParser = JsonXContent.contentBuilder().generator().contentType().xContent().createParser(xContentRegistry,mapper.writeValueAsBytes(aggregationMap));
            QueryParseContext qpc = new QueryParseContext(aggParser);
            //this is done to skip the START_OBJECT FIELD in the aggregation builder.
            qpc.parser().nextToken();
            AggregatorFactories.Builder newAggsBuilder = AggregatorFactories.parseAggregators(qpc);
            SearchSourceBuilder rewrittenBuilder = copySearchSourceBuilder(searchSourceBuilder);
            for (AggregationBuilder aggBuilder : newAggsBuilder.getAggregatorFactories()) {
                rewrittenBuilder.aggregation(aggBuilder);
            }
            sr.source(rewrittenBuilder);
            log.info(searchSourceBuilder.toString());
        } catch (Exception e) {
            e.printStackTrace();
            throw new ElasticsearchParseException("Unable to filter min_docs_count", e);
        }
    }

    private void replaceMinDocsCount(Map<String, Object> aggTree) {
        if (aggTree == null) {
            return;
        }
        Iterator<Map.Entry<String, Object>> it = aggTree.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, Object> entry = it.next();
            if (entry.getKey().equals("terms") || entry.getKey().equals("significant_terms")) {
                if (entry.getValue() instanceof Map) {
                    Map<String, Object> termsAggs = (Map<String, Object>) entry.getValue();
                    if (termsAggs != null && termsAggs.containsKey(MIN_DOC_COUNT_KEY) && termsAggs.get(MIN_DOC_COUNT_KEY) instanceof Integer && (Integer) termsAggs.get(MIN_DOC_COUNT_KEY) == 0) {
                        termsAggs.put(MIN_DOC_COUNT_KEY, 1);
                        continue;
                    }
                }
            }
            if (entry.getValue() instanceof Map) {
                replaceMinDocsCount((Map<String, Object>) entry.getValue());
            }
        }
    }


    private SearchSourceBuilder copySearchSourceBuilder(SearchSourceBuilder sBuilder) {
        SearchSourceBuilder rewrittenBuilder = new SearchSourceBuilder();

        rewrittenBuilder.explain(sBuilder.explain());
        if (sBuilder.ext() != null) {
            rewrittenBuilder.ext(sBuilder.ext());
        }
        rewrittenBuilder.fetchSource(sBuilder.fetchSource());
        if(sBuilder.docValueFields() != null) {
            for (String docValueField : sBuilder.docValueFields()) {
                rewrittenBuilder.docValueField(docValueField);
            }
        }
        rewrittenBuilder.storedFields(sBuilder.storedFields());
        if(sBuilder.from() >= 0) {
            rewrittenBuilder.from(sBuilder.from());
        }
        rewrittenBuilder.highlighter(sBuilder.highlighter());
        if (sBuilder.indexBoosts() != null ) {
            for (SearchSourceBuilder.IndexBoost indexBoost : sBuilder.indexBoosts()) {
                rewrittenBuilder.indexBoost(indexBoost.getIndex(), indexBoost.getBoost());
            }
        }
        if(sBuilder.minScore() != null) {
            rewrittenBuilder.minScore(sBuilder.minScore());
        }
        rewrittenBuilder.postFilter(sBuilder.postFilter());
        rewrittenBuilder.profile(sBuilder.profile());
        rewrittenBuilder.query(sBuilder.query());
        if(sBuilder.rescores() != null) {
            for (RescoreBuilder rb : sBuilder.rescores()) {
                rewrittenBuilder.addRescorer(rb);
            }
        }
        if (sBuilder.scriptFields() != null) {
            for (SearchSourceBuilder.ScriptField sf : sBuilder.scriptFields()) {
                rewrittenBuilder.scriptField(sf.fieldName(), sf.script(), sf.ignoreFailure());
            }
        }
        if(sBuilder.searchAfter() != null) {
            rewrittenBuilder.searchAfter(sBuilder.searchAfter());
        }
        rewrittenBuilder.slice(sBuilder.slice());
        rewrittenBuilder.size(sBuilder.size());
        if (sBuilder.sorts() != null) {
            for (SortBuilder sb : sBuilder.sorts()) {
                rewrittenBuilder.sort(sb);
            }
        }
        rewrittenBuilder.stats(sBuilder.stats());
        rewrittenBuilder.suggest(sBuilder.suggest());
        rewrittenBuilder.terminateAfter(sBuilder.terminateAfter());
        rewrittenBuilder.timeout(sBuilder.timeout());
        rewrittenBuilder.trackScores(sBuilder.trackScores());
        rewrittenBuilder.version(sBuilder.version());
        rewrittenBuilder.collapse(sBuilder.collapse());
        return rewrittenBuilder;
    }

}
