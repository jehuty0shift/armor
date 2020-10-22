package com.petalmd.armor.filter;

import com.petalmd.armor.tokeneval.RulesEntities;
import com.petalmd.armor.util.SecurityUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchParseException;
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
import org.elasticsearch.cluster.metadata.IndexAbstraction;
import org.elasticsearch.index.reindex.ReindexRequest;
import org.elasticsearch.index.reindex.UpdateByQueryRequest;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Created by jehuty0shift on 30/01/19.
 */
public class FilterHelper {

    private static Logger log = LogManager.getLogger(FilterHelper.class);

    public static void replaceWildcardOrAllIndices(IndicesRequest ir, RulesEntities rulesEntities, final List<String> ci, final List<String> aliases, final Map<String, IndexAbstraction> indicesAbstractionMap) {

        List<String> irIndices = ir.indices() == null? new ArrayList<>():Arrays.asList(ir.indices());
        List<String> newIndices = new ArrayList<>();
        List<String> otherIndicesOrAliases = new ArrayList<>();
        if (log.isDebugEnabled()) {
            log.debug("replace index for {}", irIndices);
        }
        if (irIndices.size() == 0 || irIndices.contains("_all")) {
            log.debug("request target _all indices, we replace it with rulesEntities items");
            newIndices.addAll(rulesEntities.getIndices());
            ci.addAll(rulesEntities.getIndices());
            newIndices.addAll(rulesEntities.getAliases());
            aliases.addAll(rulesEntities.getAliases());
            log.debug("added " + newIndices.size() + " indices");

        } else {
            //search for wildcards
            log.debug("indices contains wildcard, we will change them if they are not in the rules");
            for (String indexOrAlias : irIndices) {
                if (indexOrAlias.contains("*")) {
                    log.debug("index contains a wildcard");
                    //if the index match no indices it will be silently removed (consistent with what ES does).
                    for (String reIndex : rulesEntities.getIndices()) {
                        //check if index match rulesEntity (if its the case, we keep the rulesEntity).
                        if (SecurityUtil.isWildcardMatch(reIndex, indexOrAlias, false)) {
                            log.debug("index " + indexOrAlias + " match an index contained in a rule: " + reIndex);
                            newIndices.add(reIndex);
                            ci.add(reIndex);
                            //check if rulesEntity match the index (if it is the case, we keep the indexOrAlias)
                        } else if (SecurityUtil.isWildcardMatch(indexOrAlias, reIndex, false)) {
                            log.debug("index " + indexOrAlias + "has been matched by a index contained in a rule " + reIndex);
                            newIndices.add(indexOrAlias);
                            ci.add(reIndex);
                        }
                    }
                    for (String reAlias : rulesEntities.getAliases()) {
                        //check if Alias match rulesEntity (if its the case, we keep the rulesEntity).
                        if (SecurityUtil.isWildcardMatch(reAlias, indexOrAlias, false)) {
                            log.debug("index " + indexOrAlias + " match an alias contained in a rule: " + reAlias);
                            newIndices.add(reAlias);
                            aliases.add(reAlias);
                            //check if rulesEntity match the alias (if it is the case, we keep the indexOrAlias)
                        } else if (SecurityUtil.isWildcardMatch(indexOrAlias, reAlias, false)) {
                            log.debug("index " + indexOrAlias + "has been matched by an alias contained in a rule " + reAlias);
                            newIndices.add(indexOrAlias);
                            aliases.add(reAlias);
                        }
                    }
                } else {
                    log.debug("this index is not a wildcard, we will just have to resolve it");
                    newIndices.add(indexOrAlias);
                    otherIndicesOrAliases.add(indexOrAlias);
                }
            }
        }

        ci.addAll(getOnlyIndices(otherIndicesOrAliases, indicesAbstractionMap));
        aliases.addAll(getOnlyAliases(otherIndicesOrAliases, indicesAbstractionMap));

        if (!newIndices.isEmpty()) {
            log.debug("replacing indices " + irIndices + " by " + String.valueOf(newIndices));
            if (ir instanceof IndicesRequest.Replaceable) {
                IndicesRequest.Replaceable irNew = (IndicesRequest.Replaceable) ir;
                irNew.indices(newIndices.toArray(new String[newIndices.size()]));
            } else {
                //check that all newIndices are inside irIndices.
                if (irIndices.stream().filter(i -> {
                    return newIndices.contains(i);
                }).count() != newIndices.size()) {
                    throw new ElasticsearchParseException("the indices requested are not valid");
                }
            }
        }
    }


    public static void replaceWildcardOrAllIndicesComposite(CompositeIndicesRequest cir, RulesEntities rulesEntities, final List<String> ci, final List<String> aliases, final Map<String, IndexAbstraction> indicesAbstractionMap) {

        if (cir instanceof IndexRequest) {
            IndexRequest ir = (IndexRequest) cir;
            replaceWildcardOrAllIndices(ir, rulesEntities, ci, aliases, indicesAbstractionMap);
        } else if (cir instanceof BulkRequest) {
            log.debug("composite is BulkRequest");
            BulkRequest br = (BulkRequest) cir;
            for (DocWriteRequest dwr : br.requests()) {
                replaceWildcardOrAllIndices(dwr, rulesEntities, ci, aliases, indicesAbstractionMap);
            }
        } else if (cir instanceof MultiSearchRequest) {
            MultiSearchRequest msr = (MultiSearchRequest) cir;
            log.debug("composite is MultiSearchRequest");
            for (SearchRequest sr : msr.requests()) {
                replaceWildcardOrAllIndices(sr, rulesEntities, ci, aliases, indicesAbstractionMap);
            }
        } else if (cir instanceof ReindexRequest) {
            log.debug("composite is ReindexRequest");
            ReindexRequest rr = (ReindexRequest) cir;
            IndexRequest iR = rr.getDestination();
            replaceWildcardOrAllIndices(iR, rulesEntities, ci, aliases, indicesAbstractionMap);

            SearchRequest sr = rr.getSearchRequest();
            replaceWildcardOrAllIndices(sr, rulesEntities, ci, aliases, indicesAbstractionMap);
        } else if (cir instanceof MultiTermVectorsRequest) {
            log.debug("composite is MultiTermVector");
            MultiTermVectorsRequest mtvr = (MultiTermVectorsRequest) cir;
            for (TermVectorsRequest tvr : mtvr.getRequests()) {
                replaceWildcardOrAllIndices(tvr, rulesEntities, ci, aliases, indicesAbstractionMap);
            }
        } else if (cir instanceof DeleteRequest) {
            log.debug("composite is DeleteRequest");
            DeleteRequest dr = (DeleteRequest) cir;
            replaceWildcardOrAllIndices(dr, rulesEntities, ci, aliases, indicesAbstractionMap);
        } else if (cir instanceof UpdateByQueryRequest) {
            log.debug("composite is UpdateByQueryRequest");
            UpdateByQueryRequest ubqr = (UpdateByQueryRequest) cir;
            replaceWildcardOrAllIndices(ubqr, rulesEntities, ci, aliases, indicesAbstractionMap);
        } else if (cir instanceof MultiGetRequest) {
            log.debug("composite is MultiGetRequest");
            MultiGetRequest mgr = (MultiGetRequest) cir;
            for (MultiGetRequest.Item item : mgr.getItems()) {
                replaceWildcardOrAllIndices(item, rulesEntities, ci, aliases, indicesAbstractionMap);
            }
        }


    }

    public static List<String> getOnlyIndices(final Collection<String> indices, final Map<String, IndexAbstraction> indicesAbstractionMap) {

        final List<String> result = new ArrayList<String>();

        for (String index : indices) {

            final IndexAbstraction indexAbstraction = indicesAbstractionMap.get(index);

            //it doesn't exist or is a unhandled word* , we still add it as an index
            if (indexAbstraction == null) {
                result.add(index);
            } else if (!indexAbstraction.getType().equals(IndexAbstraction.Type.CONCRETE_INDEX)) {
                result.add(index);
            }
        }

        return result;
    }

    public static List<String> getOnlyAliases(final Collection<String> indices, final Map<String, IndexAbstraction> indicesAbstractionMap) {

        final List<String> result = new ArrayList<String>();

        for (String index : indices) {

            final IndexAbstraction indexAbstraction = indicesAbstractionMap.get(index);

            if (indexAbstraction != null && indexAbstraction.getType().equals(IndexAbstraction.Type.ALIAS)) {
                result.add(index);
            }
        }

        return result;
    }

}
