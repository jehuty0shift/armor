package com.petalmd.armor.filter.kefla;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.fieldcaps.FieldCapabilities;
import org.elasticsearch.action.fieldcaps.FieldCapabilitiesResponse;
import org.elasticsearch.common.io.stream.BytesStreamOutput;
import org.elasticsearch.common.io.stream.StreamOutput;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Created by jehuty0shift on 04/11/19.
 */
public class KeflaFieldCapabilitiesResponse extends ActionResponse implements KeflaResponse {

    private static final Logger log = LogManager.getLogger(KeflaGetFieldMappingsResponse.class);
    private FieldCapabilitiesResponse kFcr;
    private Map<String, Map<String, FieldCapabilities>> newResponseMap;
    private String[] newIndices;

    public KeflaFieldCapabilitiesResponse(FieldCapabilitiesResponse fcr, Map<String, Map<String, Map<String, KeflaRestType>>> streamIndexFieldsMap) {

        Map<String, Map<String, KeflaRestType>> allowedIndexMap = KeflaUtils.streamIndexMapToIndexMapFlattened(streamIndexFieldsMap);
        Map<String, Map<String, FieldCapabilities>> responseMap = fcr.get();
        newResponseMap = new HashMap<>();
        newIndices = Arrays.stream(fcr.getIndices()).filter(allowedIndexMap::containsKey).toArray(String[]::new);

        log.debug("got the following fieldCap response Map ({} entries) {}", responseMap.size(), responseMap);

        for (Map.Entry<String, Map<String, FieldCapabilities>> respMapEntry : responseMap.entrySet()) {
            final String fieldName = respMapEntry.getKey();
            final Map<String, FieldCapabilities> newFCapMap = new HashMap<>();
            for (Map.Entry<String, FieldCapabilities> fCapMap : respMapEntry.getValue().entrySet()) {
                final List<String> newIndicesForFCap = new ArrayList<>();
                final String type = fCapMap.getKey();
                FieldCapabilities fCap = fCapMap.getValue();
                String[] indices = fCap.indices();
                boolean shouldAddForAll = true;
                // handle null case by checking all indices :-)
                // if the field is present in all allowed indices, we add it with the same null values for indices,
                // if not, we only add it for the indices that contain the field.
                if (indices == null) {
                    log.debug("indices is null, checking all indices one by one");
                    List<String> tempNewIndices = new ArrayList<>();
                    for (String index : allowedIndexMap.keySet()) {
                        if (!allowedIndexMap.get(index).containsKey(fieldName)) {
                            log.debug("field {} is not present in index {}", fieldName, index);
                            //the field is not present in all indices. but we continue to check the others
                            shouldAddForAll = false;
                        } else {
                            log.debug("field {} is present in index {}", fieldName, index);
                            //we add it in this list in case we cannot add it in all indices.
                            tempNewIndices.add(index);
                        }
                    }
                    if (!shouldAddForAll && !tempNewIndices.isEmpty()) {
                        log.debug("we added {} new indices", tempNewIndices.size());
                        newIndicesForFCap.addAll(tempNewIndices);
                    }
                } else {
                    log.debug("the indices list is not null, checking only these indices");
                    for (String index : indices) {
                        if (allowedIndexMap.containsKey(index)
                                && allowedIndexMap.get(index).containsKey(fieldName)) {
                            log.debug("we add the field {} for index {}", fieldName, index);
                            newIndicesForFCap.add(index);
                        }
                    }
                }
                //we add the field uniquely for indices where it should be present
                //even if it was present in other indices (because it was likely for different streams).
                if (!newIndicesForFCap.isEmpty()) {
                    log.debug("adding a non available field cap for field {}", fieldName);
                    List<String> nonAggregatables = fCap.nonAggregatableIndices() == null ? null : Arrays.asList(fCap.nonAggregatableIndices()).stream().filter(s -> newIndicesForFCap.contains(s)).collect(Collectors.toList());
                    List<String> nonSearchables = fCap.nonSearchableIndices() == null ? null : Arrays.asList(fCap.nonSearchableIndices()).stream().filter(s -> newIndicesForFCap.contains(s)).collect(Collectors.toList());
                    FieldCapabilities newFCap = new FieldCapabilities(
                            fieldName,
                            type,
                            fCap.isSearchable(),
                            fCap.isAggregatable(),
                            newIndicesForFCap.toArray(new String[newIndicesForFCap.size()]),
                            nonAggregatables == null ? null : nonAggregatables.toArray(new String[nonAggregatables.size()]),
                            nonSearchables == null ? null : nonSearchables.toArray(new String[nonSearchables.size()]),
                            fCap.meta());
                    newFCapMap.put(type, newFCap);
                } else if (indices == null && shouldAddForAll) {
                    log.debug("adding a all available FieldCap for field {}", fieldName);
                    FieldCapabilities newFCap = new FieldCapabilities(fieldName, type, fCap.isSearchable(), fCap.isAggregatable(), new String[]{}, new String[]{}, new String[]{}, Collections.emptyMap());
                    newFCapMap.put(type, newFCap);
                }

            }
            if (!newFCapMap.isEmpty()) {
                log.debug("fieldCap map is {}", newFCapMap.size());
                newResponseMap.put(fieldName, newFCapMap);
            }
        }


        kFcr = fcr;
    }


    @Override
    public ActionResponse getActionResponse() {
        BytesStreamOutput bso = new BytesStreamOutput();
        try {
            writeTo(bso);
            return new FieldCapabilitiesResponse(bso.bytes().streamInput());
        } catch (IOException e) {
            log.error("fatal error when deserializing field Caps ", e);
            throw new ElasticsearchException("IO Exception in KeflaFieldCapabilitiesResponse");
        }
    }

    public void writeTo(StreamOutput out) throws IOException {
        out.writeStringArray(newIndices);
        out.writeMap(newResponseMap, StreamOutput::writeString, KeflaFieldCapabilitiesResponse::innerWriteTo);
        out.writeList(Collections.emptyList());
    }

    public static void innerWriteTo(StreamOutput out, Map<String, FieldCapabilities> fCapMap) throws IOException {
        out.writeMap(fCapMap, StreamOutput::writeString, (sOut, fc) -> fc.writeTo(sOut));
    }
}
