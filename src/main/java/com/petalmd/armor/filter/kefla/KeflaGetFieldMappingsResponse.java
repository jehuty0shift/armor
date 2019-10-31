package com.petalmd.armor.filter.kefla;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.admin.indices.mapping.get.GetFieldMappingsResponse;

import java.io.IOException;
import java.util.*;

import static org.elasticsearch.action.admin.indices.mapping.get.GetFieldMappingsResponse.FieldMappingMetaData;

/**
 * Created by jehuty0shift on 25/10/19.
 */
public class KeflaGetFieldMappingsResponse implements KeflaResponse {

    private static final Logger log = LogManager.getLogger(KeflaGetFieldMappingsResponse.class);
    private final GetFieldMappingsResponse kGfmr;

    public KeflaGetFieldMappingsResponse(final GetFieldMappingsResponse response, Map<String, Map<String, Map<String, KeflaRestType>>> streamIndexFieldsMap) throws IOException {

        //flatten streamIndexFieldMap by index
        log.debug("GetFieldsMappingsResponse is allowed for {} streams", streamIndexFieldsMap.size());
        Map<String, Map<String, KeflaRestType>> allowedIndexMap = KeflaUtils.streamIndexMapToIndexMap(streamIndexFieldsMap);
        log.debug("streamIndexMap has been flatten for {} indices", allowedIndexMap.size());

        //we modify directly the mapping (since it is not immutable)
        Map<String, Map<String, Map<String, FieldMappingMetaData>>> mappings = response.mappings();
        List<String> indexToRemove = new ArrayList<>();
        for (Map.Entry<String, Map<String, Map<String, FieldMappingMetaData>>> indexMapping : mappings.entrySet()) {
            final String index = indexMapping.getKey();
            if (allowedIndexMap.containsKey(indexMapping)) {
                Set<String> allowedFields = allowedIndexMap.get(index).keySet();
                for (Map.Entry<String, Map<String, FieldMappingMetaData>> typeMapping : indexMapping.getValue().entrySet()) {
                    List<String> fieldsToRemove = new ArrayList<>();
                    for (Map.Entry<String, FieldMappingMetaData> fMappingEntry : typeMapping.getValue().entrySet()) {
                        if (!allowedFields.contains(fMappingEntry.getKey())) {
                            fieldsToRemove.add(fMappingEntry.getKey());
                        }
                    }
                    for (String fieldToRemove : fieldsToRemove) {
                        typeMapping.getValue().remove(fieldToRemove);
                    }
                    log.debug("we added {} fields to the type {} of index {}", typeMapping.getValue().size(), typeMapping.getKey(), index);
                }
            } else {
                //remove mapping
                indexToRemove.add(index);
            }
        }
        for(String index : indexToRemove) {
            mappings.remove(index);
        }

        log.debug("we added {} index mappings to the final response", mappings.size());
        kGfmr = response;

    }


    @Override
    public ActionResponse getActionResponse() {
        return kGfmr;
    }
}
