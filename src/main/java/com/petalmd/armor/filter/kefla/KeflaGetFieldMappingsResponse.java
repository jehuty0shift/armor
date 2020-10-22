package com.petalmd.armor.filter.kefla;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.admin.indices.mapping.get.GetFieldMappingsResponse;
import org.elasticsearch.common.xcontent.*;
import org.elasticsearch.common.xcontent.json.JsonXContent;
import org.elasticsearch.index.mapper.MapperService;
import org.elasticsearch.rest.BaseRestHandler;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.elasticsearch.rest.BaseRestHandler.DEFAULT_INCLUDE_TYPE_NAME_POLICY;

/**
 * Created by jehuty0shift on 25/10/19.
 */
public class KeflaGetFieldMappingsResponse implements KeflaResponse {

    private static final Logger log = LogManager.getLogger(KeflaGetFieldMappingsResponse.class);
    private final Map<String, Map<String, Map<String, GetFieldMappingsResponse.FieldMappingMetadata>>> newMappings;

    public KeflaGetFieldMappingsResponse(final GetFieldMappingsResponse response, Map<String, Map<String, Map<String, KeflaRestType>>> streamIndexFieldsMap) throws IOException {
        //flatten streamIndexFieldMap by index
        log.debug("GetFieldsMappingsResponse is allowed for {} streams", streamIndexFieldsMap.size());
        Map<String, Map<String, KeflaRestType>> allowedIndexMap = KeflaUtils.streamIndexMapToIndexMap(streamIndexFieldsMap);
        log.debug("streamIndexMap has been flatten for {} indices", allowedIndexMap.size());

        //we modify directly the mapping (since it is not immutable)
        Map<String, Map<String, Map<String, GetFieldMappingsResponse.FieldMappingMetadata>>> mappings = response.mappings();
        newMappings = new HashMap<>();

        for (Map.Entry<String, Map<String, Map<String, GetFieldMappingsResponse.FieldMappingMetadata>>> indexMapping : mappings.entrySet()) {
            final String index = indexMapping.getKey();
            if (allowedIndexMap.containsKey(index)) {
                Set<String> allowedFields = allowedIndexMap.get(index).keySet();
                Map<String, Map<String, GetFieldMappingsResponse.FieldMappingMetadata>> newTypeMapping = new HashMap<>();
                for (Map.Entry<String, Map<String, GetFieldMappingsResponse.FieldMappingMetadata>> typeMapping : indexMapping.getValue().entrySet()) {
                    Map<String, GetFieldMappingsResponse.FieldMappingMetadata> newFieldMappings = new HashMap<>();
                    for (Map.Entry<String, GetFieldMappingsResponse.FieldMappingMetadata> fMappingEntry : typeMapping.getValue().entrySet()) {
                        if (allowedFields.contains(fMappingEntry.getKey())) {
                            newFieldMappings.put(fMappingEntry.getKey(), fMappingEntry.getValue());
                        }
                    }
                    if (!newFieldMappings.isEmpty()) {
                        newTypeMapping.put(typeMapping.getKey(), newFieldMappings);
                    }
                    log.debug("we added {} fields to the type {} of index {}", newFieldMappings.size(), typeMapping.getKey(), index);
                }
                if (!newTypeMapping.isEmpty()) {
                    newMappings.put(index, newTypeMapping);
                }
            } else {
                //do nothing
                //add default mapping
            }
        }

        log.debug("we added {} index mappings to the final response", newMappings.size());
    }


    @Override
    public ActionResponse getActionResponse() {

        try {
            XContentBuilder cBuilder = JsonXContent.contentBuilder();
            ToXContent.Params params = new ToXContent.MapParams(Map.of(BaseRestHandler.INCLUDE_TYPE_NAME_PARAMETER, "false"));
            XContentBuilder content = toXContent(cBuilder, params);
            ByteArrayOutputStream baos = (ByteArrayOutputStream) content.getOutputStream();
            ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
            XContentParser parser = JsonXContent.jsonXContent.createParser(NamedXContentRegistry.EMPTY, DeprecationHandler.THROW_UNSUPPORTED_OPERATION, bais);
            GetFieldMappingsResponse gfmResp = GetFieldMappingsResponse.fromXContent(parser);
            return gfmResp;
        } catch (IOException ex) {
            log.error("Couldn't generate keflaGetFieldMappingsResponse");
        }

        throw new ElasticsearchException("unexpected error happened");
    }

    public XContentBuilder toXContent(XContentBuilder builder, ToXContent.Params params) throws IOException {
        boolean includeTypeName = params.paramAsBoolean(BaseRestHandler.INCLUDE_TYPE_NAME_PARAMETER,
                DEFAULT_INCLUDE_TYPE_NAME_POLICY);

        builder.startObject();
        for (Map.Entry<String, Map<String, Map<String, GetFieldMappingsResponse.FieldMappingMetadata>>> indexEntry : newMappings.entrySet()) {
            builder.startObject(indexEntry.getKey());
            builder.startObject("mappings");

            if (includeTypeName == false) {
                Map<String, GetFieldMappingsResponse.FieldMappingMetadata> mappings = null;
                for (Map.Entry<String, Map<String, GetFieldMappingsResponse.FieldMappingMetadata>> typeEntry : indexEntry.getValue().entrySet()) {
                    if (typeEntry.getKey().equals(MapperService.DEFAULT_MAPPING) == false) {
                        assert mappings == null;
                        mappings = typeEntry.getValue();
                    }
                }
                if (mappings != null) {
                    addFieldMappingsToBuilder(builder, params, mappings);
                }
            } else {
                for (Map.Entry<String, Map<String, GetFieldMappingsResponse.FieldMappingMetadata>> typeEntry : indexEntry.getValue().entrySet()) {
                    builder.startObject(typeEntry.getKey());
                    addFieldMappingsToBuilder(builder, params, typeEntry.getValue());
                    builder.endObject();
                }
            }

            builder.endObject();
            builder.endObject();
        }
        builder.endObject();
        return builder;
    }

    private void addFieldMappingsToBuilder(XContentBuilder builder,
                                           ToXContent.Params params,
                                           Map<String, GetFieldMappingsResponse.FieldMappingMetadata> mappings) throws IOException {
        for (Map.Entry<String, GetFieldMappingsResponse.FieldMappingMetadata> fieldEntry : mappings.entrySet()) {
            builder.startObject(fieldEntry.getKey());
            fieldEntry.getValue().toXContent(builder, params);
            builder.endObject();
        }
    }


}
