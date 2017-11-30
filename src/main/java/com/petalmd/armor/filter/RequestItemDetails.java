package com.petalmd.armor.filter;

import org.apache.logging.log4j.Logger;
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
import org.elasticsearch.common.logging.ESLoggerFactory;
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
    private final Set<String> types;
    protected static final Logger log = ESLoggerFactory.getLogger(RequestItemDetails.class);


    private RequestItemDetails(Set<String> indices, Set<String> types) {
        this.indices = indices;
        this.types = types;
    }

    public Set<String> getIndices() {
        return indices;
    }

    public Set<String> getTypes() {
        return types;
    }


    public static RequestItemDetails fromIndiceRequest(IndicesRequest ir) {
        Set<String> indices = new HashSet<>(Arrays.asList(ir.indices()));
        Set<String> types = new HashSet<>();
        addType(ir,types);

        return new RequestItemDetails(indices,types);
    }

    public static RequestItemDetails fromCompositeIndicesRequest(CompositeIndicesRequest cir) {

        Set<String> indices = new HashSet<>();
        Set<String> types = new HashSet<>();
        if (cir instanceof IndexRequest) {
            IndexRequest ir = (IndexRequest) cir;
            indices.add(ir.index());
            types.add(ir.type());
        } else if (cir instanceof BulkRequest) {
            log.debug("composite is BulkRequest");
            BulkRequest br = (BulkRequest) cir;
            for(DocWriteRequest dwr : br.requests()) {
                indices.add(dwr.index());
                if(dwr.type() != null && !"".equals(dwr.type())) {
                    types.add(dwr.type());
                } else {
                    types.add("*");
                }
            }
        } else if (cir instanceof MultiSearchRequest) {
            MultiSearchRequest msr = (MultiSearchRequest) cir;
            log.debug("composite is MultiSearchRequest");
            for (SearchRequest sr : msr.requests()) {
                indices.addAll(Arrays.asList(sr.indices()));
                if(sr.types() != null && sr.types().length > 0) {
                    types.addAll(Arrays.asList(sr.types()));
                } else {
                    types.add("*");
                }
            }
        } else if (cir instanceof ReindexRequest) {
            log.debug("composite is ReindexRequest");
            ReindexRequest rr = (ReindexRequest) cir;
            IndexRequest iR = rr.getDestination();
            indices.addAll(Arrays.asList(iR.indices()));
            types.addAll(Arrays.asList(iR.type()));

            SearchRequest sr = rr.getSearchRequest();
            indices.addAll(Arrays.asList(sr.indices()));
            types.addAll(Arrays.asList(sr.types()));
        } else if (cir instanceof MultiTermVectorsRequest) {
            log.debug("composite is MultiTermVector");
            MultiTermVectorsRequest mtvr = (MultiTermVectorsRequest) cir;
            for (TermVectorsRequest tvr : mtvr.getRequests()) {
                indices.addAll(Arrays.asList(tvr.indices()));
                if (!"".equals(tvr.type())) {
                    types.add(tvr.type());
                } else {
                    types.add("*");
                }
            }
        } else if (cir instanceof DeleteRequest) {
            log.debug("composite is DeleteRequest");
            DeleteRequest dr = (DeleteRequest) cir;
            indices.addAll(Arrays.asList(dr.indices()));
            types.add(dr.type());
        } else if (cir instanceof UpdateByQueryRequest) {
            log.debug("composite is UpdateByQueryRequest");
            UpdateByQueryRequest ubqr = (UpdateByQueryRequest) cir;
            indices.addAll(Arrays.asList(ubqr.getSearchRequest().indices()));
            types.addAll(Arrays.asList(ubqr.getSearchRequest().types()));
        } else if (cir instanceof MultiGetRequest) {
            log.debug("composite is MultiGetRequest");
            MultiGetRequest mgr = (MultiGetRequest) cir;
            for (MultiGetRequest.Item item : mgr.getItems()) {
                indices.addAll(Arrays.asList(item.indices()));
                if(item.type() != null && !"".equals(item.type())) {
                    types.add(item.type());
                } else {
                    types.add("*");
                }
            }
        }


        if(types.isEmpty() || types.contains("*")) {
            types.clear();
            types.add("*");
        }

        if(indices.contains("*") || indices.contains("_all") || indices.isEmpty()) {
            indices.clear();
            indices.add("_all");
        }

        log.debug("final indices list is: " +indices.toString());
        log.debug("final types list is: " + types.toString());

        return new RequestItemDetails(indices, types);
    }

    private static void addType(final IndicesRequest request, final Set<java.lang.String> types) {

        AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
            try {
                final Method method = request.getClass().getDeclaredMethod("type");
                method.setAccessible(true);
                final String type = (String) method.invoke(request);
                types.add(type);
            } catch (NoSuchMethodException | SecurityException | IllegalAccessException |
                    IllegalArgumentException | InvocationTargetException e) {
                try {
                    final Method method = request.getClass().getDeclaredMethod("types");
                    method.setAccessible(true);
                    final String[] typesA = (String[]) method.invoke(request);
                    types.addAll(Arrays.asList(typesA));
                } catch (final NoSuchMethodException | SecurityException | IllegalAccessException |
                        IllegalArgumentException | InvocationTargetException e1) {
                    types.clear();
                    types.add("*");
                    log.debug("Cannot determine types for({}) due to type[s]() method not found", request.getClass());
                }

            } finally {
                return null;
            }
        });

    }

}
