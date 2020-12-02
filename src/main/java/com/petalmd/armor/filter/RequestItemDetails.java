package com.petalmd.armor.filter;

import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;
import org.elasticsearch.action.CompositeIndicesRequest;
import org.elasticsearch.action.DocWriteRequest;
import org.elasticsearch.action.IndicesRequest;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.delete.DeleteRequest;
import org.elasticsearch.action.get.MultiGetRequest;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.search.MultiSearchRequest;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.termvectors.MultiTermVectorsRequest;
import org.elasticsearch.action.termvectors.TermVectorsRequest;
import org.elasticsearch.index.reindex.ReindexRequest;
import org.elasticsearch.index.reindex.UpdateByQueryRequest;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Created by jehuty0shift on 26/09/17.
 */
public class RequestItemDetails {

    private final Set<String> indices;
    protected static final Logger log = LogManager.getLogger(RequestItemDetails.class);


    private RequestItemDetails(Set<String> indices) {
        this.indices = indices;
    }

    public Set<String> getIndices() {
        return indices;
    }


    public static RequestItemDetails fromIndiceRequest(IndicesRequest ir) {
        Set<String> indices = new HashSet<>(Arrays.asList(ir.indices()));

        return new RequestItemDetails(indices);
    }

    public static RequestItemDetails fromCompositeIndicesRequest(CompositeIndicesRequest cir) {

        Set<String> indices = new HashSet<>();
        if (cir instanceof IndexRequest) {
            IndexRequest ir = (IndexRequest) cir;
            indices.add(ir.index());
        } else if (cir instanceof BulkRequest) {
            log.debug("composite is BulkRequest");
            BulkRequest br = (BulkRequest) cir;
            for(DocWriteRequest dwr : br.requests()) {
                indices.add(dwr.index());
            }
        } else if (cir instanceof MultiSearchRequest) {
            MultiSearchRequest msr = (MultiSearchRequest) cir;
            log.debug("composite is MultiSearchRequest");
            for (SearchRequest sr : msr.requests()) {
                indices.addAll(Arrays.asList(sr.indices()));
            }
        } else if (cir instanceof ReindexRequest) {
            log.debug("composite is ReindexRequest");
            ReindexRequest rr = (ReindexRequest) cir;
            IndexRequest iR = rr.getDestination();
            indices.addAll(Arrays.asList(iR.indices()));

            SearchRequest sr = rr.getSearchRequest();
            indices.addAll(Arrays.asList(sr.indices()));
        } else if (cir instanceof MultiTermVectorsRequest) {
            log.debug("composite is MultiTermVector");
            MultiTermVectorsRequest mtvr = (MultiTermVectorsRequest) cir;
            for (TermVectorsRequest tvr : mtvr.getRequests()) {
                indices.addAll(Arrays.asList(tvr.indices()));

            }
        } else if (cir instanceof DeleteRequest) {
            log.debug("composite is DeleteRequest");
            DeleteRequest dr = (DeleteRequest) cir;
            indices.addAll(Arrays.asList(dr.indices()));
        } else if (cir instanceof UpdateByQueryRequest) {
            log.debug("composite is UpdateByQueryRequest");
            UpdateByQueryRequest ubqr = (UpdateByQueryRequest) cir;
            indices.addAll(Arrays.asList(ubqr.getSearchRequest().indices()));
        } else if (cir instanceof MultiGetRequest) {
            log.debug("composite is MultiGetRequest");
            MultiGetRequest mgr = (MultiGetRequest) cir;
            for (MultiGetRequest.Item item : mgr.getItems()) {
                indices.addAll(Arrays.asList(item.indices()));

            }
        }

        if(indices.contains("*") || indices.contains("_all") || indices.isEmpty()) {
            indices.clear();
            indices.add("_all");
        }

        log.debug("final indices list is: " +indices.toString());

        return new RequestItemDetails(indices);
    }

}
