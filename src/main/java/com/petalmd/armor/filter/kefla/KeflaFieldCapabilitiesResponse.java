package com.petalmd.armor.filter.kefla;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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

    public KeflaFieldCapabilitiesResponse(FieldCapabilitiesResponse fcr, Map<String, Map<String, Map<String, KeflaRestType>>> streamIndexFieldsMap) {

        Map<String, Map<String, KeflaRestType>> allowedIndexMap = KeflaUtils.streamIndexMapToIndexMap(streamIndexFieldsMap);
        Map<String, Map<String, FieldCapabilities>> responseMap = fcr.get();
        newResponseMap = new HashMap<>();

        for (Map.Entry<String, Map<String, FieldCapabilities>> respMapEntry : responseMap.entrySet()) {
            final String fieldName = respMapEntry.getKey();
            final Map<String, FieldCapabilities> newFCapMap = new HashMap<>();
            for (Map.Entry<String, FieldCapabilities> fCapMap : respMapEntry.getValue().entrySet()) {
                final List<String> newIndices = new ArrayList<>();
                final String type = fCapMap.getKey();
                FieldCapabilities fCap = fCapMap.getValue();
                String[] indices = fCap.indices();
                boolean shouldAddField = true;
                // handle null case by checking all indices :-)
                // if the field is present in all allowed indices, we add it with the same null values for indices,
                // if not, we only add it for the indices that contain the field.
                if (indices == null) {
                    List<String> tempNewIndices = new ArrayList<>();
                    for (String index : allowedIndexMap.keySet()) {
                        if (!allowedIndexMap.get(index).containsKey(fieldName)) {
                            //the field is not present in all indices. but we continue to check the others
                            shouldAddField = false;
                        } else {
                            //we add it in this list in case we cannot add it in all indices.
                            tempNewIndices.add(index);
                        }
                    }
                    if (!shouldAddField && !tempNewIndices.isEmpty()) {
                        newIndices.addAll(tempNewIndices);
                    }
                } else {
                    for (String index : indices) {
                        if (allowedIndexMap.containsKey(index)
                                && allowedIndexMap.get(index).containsKey(fieldName)) {
                            newIndices.add(index);
                        }
                    }
                }
                if (!newIndices.isEmpty() && indices != null) {
                    List<String> nonAggregatables = fCap.nonAggregatableIndices() == null ? null : Arrays.asList(fCap.nonAggregatableIndices()).stream().filter(s -> newIndices.contains(s)).collect(Collectors.toList());
                    List<String> nonSearchables = fCap.nonSearchableIndices() == null ? null : Arrays.asList(fCap.nonSearchableIndices()).stream().filter(s -> newIndices.contains(s)).collect(Collectors.toList());
                    FieldCapabilities newFCap = new FieldCapabilities(
                            fieldName,
                            type,
                            fCap.isSearchable(),
                            fCap.isAggregatable(),
                            newIndices.toArray(new String[newIndices.size()]),
                            nonAggregatables == null ? null : nonAggregatables.toArray(new String[nonAggregatables.size()]),
                            nonSearchables == null ? null : nonSearchables.toArray(new String[nonSearchables.size()]));
                    newFCapMap.put(type, newFCap);
                } else if (indices == null && shouldAddField) {
                    FieldCapabilities newFCap = new FieldCapabilities(fieldName, type, fCap.isSearchable(), fCap.isAggregatable());
                    newFCapMap.put(type, newFCap);
                }

            }
            if (!newFCapMap.isEmpty()) {
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
            kFcr.readFrom(bso.bytes().streamInput());

        } catch (IOException e) {
            log.error("fatal error when deserializing field Caps ", e);
        }
        return kFcr;
    }

    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeMap(newResponseMap, StreamOutput::writeString, KeflaFieldCapabilitiesResponse::innerWriteTo);
        out.writeList(Collections.emptyList());
    }

    public static void innerWriteTo(StreamOutput out, Map<String, FieldCapabilities> fCapMap) throws IOException {
        out.writeMap(fCapMap, StreamOutput::writeString, (sOut, fc) -> fc.writeTo(sOut));
    }
}
