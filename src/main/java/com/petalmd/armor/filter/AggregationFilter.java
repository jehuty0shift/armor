package com.petalmd.armor.filter;

import com.petalmd.armor.audit.AuditListener;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authentication.backend.AuthenticationBackend;
import com.petalmd.armor.authorization.Authorizator;
import com.petalmd.armor.authorization.ForbiddenException;
import com.petalmd.armor.service.ArmorConfigService;
import com.petalmd.armor.service.ArmorService;
import com.petalmd.armor.tokeneval.TokenEvaluator;
import com.petalmd.armor.util.ConfigConstants;
import com.petalmd.armor.util.SecurityUtil;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ElasticsearchParseException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.search.MultiSearchRequest;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.cluster.ClusterService;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.search.lookup.SourceLookup;
import org.elasticsearch.tasks.Task;

import java.util.Iterator;
import java.util.Map;

/**
 * Created by bdiasse on 20/02/17.
 */
public class AggregationFilter extends AbstractActionFilter {

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private final boolean enabled;

    private static final String MIN_DOC_COUNT_KEY = "min_doc_count";


    @Inject
    public AggregationFilter(final Settings settings, final AuthenticationBackend backend, final Authorizator authorizator,
                             final ClusterService clusterService, final ArmorConfigService armorConfigService, final AuditListener auditListener) {
        super(settings, backend, authorizator, clusterService, armorConfigService, auditListener);
        enabled = settings.getAsBoolean(ConfigConstants.ARMOR_AGGREGATION_FILTER_ENABLED,false);

    }


    public void applySecure(Task task, final String action, final ActionRequest request, final ActionListener listener, final ActionFilterChain chain) {

        if (!enabled) {
            chain.proceed(task, action, request, listener);
            return;
        }

        final User user = request.getFromContext("armor_authenticated_user", null);
        final Object authHeader = request.getHeader("armor_authenticated_transport_request");

        final TokenEvaluator.Evaluator evaluator;

        try {
            evaluator = getFromContextOrHeader("armor_ac_evaluator", request, getEvaluator(request, action, user));
        } catch (ForbiddenException e) {
            listener.onFailure(e);
            throw e;
        }

        request.putInContext("_armor_token_evaluator", evaluator);
//

        if (request.remoteAddress() == null && user == null) {
            log.trace("Return on INTERNODE request");
            return;
        }

        if (evaluator.getBypassAll() && user != null) {
            log.trace("Return on WILDCARD for " + user);
            return;
        }

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
            BytesReference source;
            for (int i = 0; i < 2; i++) {
                final SourceLookup sl = new SourceLookup();
                if (i == 0) {
                    source = sr.source();
                } else {
                    source = sr.extraSource();
                }
                if (source != null && source.length() > 0) {
                    sl.setSource(source);
                    if (sl.isEmpty()) { //WARNING : this also initialize the sourceLookup for following sl.source() call, so DO NOT REMOVE.
                        continue;
                    }
                    Map<String, Object> sourceMap = sl.source();
                    if (sourceMap.containsKey("aggregations")) {
                        Map<String, Object> aggregations = (Map<String, Object>) sourceMap.get("aggregations");
                        replaceMinDocsCount(aggregations);
                        sourceMap.put("aggregations", aggregations);
                    }
                    if (sourceMap.containsKey("aggs")) {
                        Map<String, Object> aggs = (Map<String, Object>) sourceMap.get("aggs");
                        replaceMinDocsCount(aggs);
                        sourceMap.put("aggs", aggs);
                    }
                    if (i == 0) {
                        sr.source(XContentFactory.jsonBuilder().map(sourceMap).bytes());
                    } else {
                        sr.extraSource(XContentFactory.jsonBuilder().map(sourceMap).bytes());
                    }
                }
            }
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

}
