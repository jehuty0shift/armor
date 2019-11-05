package com.petalmd.armor.filter.kefla;

import com.carrotsearch.hppc.cursors.ObjectObjectCursor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.admin.indices.mapping.get.GetMappingsResponse;
import org.elasticsearch.cluster.metadata.MappingMetaData;
import org.elasticsearch.common.collect.ImmutableOpenMap;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by jehuty0shift on 25/10/19.
 */
public class KeflaGetMappingsResponse implements KeflaResponse {

    private static final Logger log = LogManager.getLogger(KeflaGetMappingsResponse.class);
    private final GetMappingsResponse kGmr;

    public KeflaGetMappingsResponse(final GetMappingsResponse response, Map<String, Map<String, Map<String, KeflaRestType>>> streamIndexFieldsMap) throws IOException {

        //flatten streamIndexFieldMap by index
        log.debug("GetMappingsResponse is allowed for {} streams", streamIndexFieldsMap.size());
        Map<String, Map<String, KeflaRestType>> allowedIndexMap = KeflaUtils.streamIndexMapToIndexMap(streamIndexFieldsMap);
        log.debug("streamIndexMap has been flatten for {} indices", allowedIndexMap.size());

        ImmutableOpenMap<String, ImmutableOpenMap<String, MappingMetaData>> mappings = response.getMappings();
        ImmutableOpenMap.Builder<String, ImmutableOpenMap<String, MappingMetaData>> kGmrBuilder = ImmutableOpenMap.builder(mappings.size());

        //Iter over { "index : { "type" :  { "properties : {...} }
        for (ObjectObjectCursor<String, ImmutableOpenMap<String, MappingMetaData>> indMappCursor : mappings) {
            String index = indMappCursor.key;
            if (allowedIndexMap.containsKey(index)) {
                log.trace("adding mapping for index {}", index);
                ImmutableOpenMap.Builder<String, MappingMetaData> newTypesMapping = ImmutableOpenMap.builder(indMappCursor.value.size());
                //Iter over { "type" :  { "properties : {...} }
                for (ObjectObjectCursor<String, MappingMetaData> mappCursor : indMappCursor.value) {
                    MappingMetaData typeMapping = mappCursor.value;
                    Map<String, Object> propertiesMap = (Map<String, Object>) typeMapping.sourceAsMap().get("properties");
                    Map<String, KeflaRestType> allowedMapping = allowedIndexMap.get(index);
                    Map<String, Object> filteredTypeMapping = new HashMap<>();
                    //create properties object
                    Map<String, Object> newPropertiesMap = new HashMap<>();
                    newPropertiesMap.put("properties", filteredTypeMapping);
                    //Iter over {"properties" : { ... }}
                    for (Map.Entry<String, Object> propField : propertiesMap.entrySet()) {
                        if (allowedMapping.containsKey(propField.getKey())) {
                            log.trace("mapping for field {} is allowed for type {} of index {}", propField.getKey(), mappCursor.key, index);
                            filteredTypeMapping.put(propField.getKey(), propField.getValue());
                        }
                    }
                    newTypesMapping.put(mappCursor.key, new MappingMetaData(mappCursor.key, newPropertiesMap));
                }
                //add the newMapping for Index
                kGmrBuilder.put(index, newTypesMapping.build());
            }
        }
        log.debug("we added {} mappings to the final response", kGmrBuilder.size());
        kGmr = new GetMappingsResponse(kGmrBuilder.build());

    }


    @Override
    public ActionResponse getActionResponse() {
        return kGmr;
    }
}
