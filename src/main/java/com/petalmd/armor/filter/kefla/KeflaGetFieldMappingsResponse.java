package com.petalmd.armor.filter.kefla;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.admin.indices.mapping.get.GetFieldMappingsResponse;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.io.stream.BytesStreamOutput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.json.JsonXContent;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.elasticsearch.action.admin.indices.mapping.get.GetFieldMappingsResponse.FieldMappingMetaData;

/**
 * Created by jehuty0shift on 25/10/19.
 */
public class KeflaGetFieldMappingsResponse extends ActionResponse implements KeflaResponse {

    private static final Logger log = LogManager.getLogger(KeflaGetFieldMappingsResponse.class);
    private final GetFieldMappingsResponse kGfmr;
    private final Map<String, Map<String, Map<String, FieldMappingMetaData>>> newMappings;

    public KeflaGetFieldMappingsResponse(final GetFieldMappingsResponse response, Map<String, Map<String, Map<String, KeflaRestType>>> streamIndexFieldsMap) throws IOException {
        //flatten streamIndexFieldMap by index
        log.debug("GetFieldsMappingsResponse is allowed for {} streams", streamIndexFieldsMap.size());
        Map<String, Map<String, KeflaRestType>> allowedIndexMap = KeflaUtils.streamIndexMapToIndexMap(streamIndexFieldsMap);
        log.debug("streamIndexMap has been flatten for {} indices", allowedIndexMap.size());

        //we modify directly the mapping (since it is not immutable)
        Map<String, Map<String, Map<String, FieldMappingMetaData>>> mappings = response.mappings();
        newMappings = new HashMap<>();

        for (Map.Entry<String, Map<String, Map<String, FieldMappingMetaData>>> indexMapping : mappings.entrySet()) {
            final String index = indexMapping.getKey();
            if (allowedIndexMap.containsKey(index)) {
                Set<String> allowedFields = allowedIndexMap.get(index).keySet();
                Map<String, Map<String, FieldMappingMetaData>> newTypeMapping = new HashMap<>();
                for (Map.Entry<String, Map<String, FieldMappingMetaData>> typeMapping : indexMapping.getValue().entrySet()) {
                    Map<String, FieldMappingMetaData> newFieldMappings = new HashMap<>();
                    for (Map.Entry<String, FieldMappingMetaData> fMappingEntry : typeMapping.getValue().entrySet()) {
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
        kGfmr = response;

    }


    @Override
    public ActionResponse getActionResponse() {


        BytesStreamOutput bso = new BytesStreamOutput();
        try {
            writeTo(bso);
            bso.close();
            kGfmr.readFrom(bso.bytes().streamInput());
        } catch (IOException e) {
            log.error("fatal error when deserializing mappings", e);
        }

        return kGfmr;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeVInt(newMappings.size());
        for (Map.Entry<String, Map<String, Map<String, FieldMappingMetaData>>> indexEntry : newMappings.entrySet()) {
            out.writeString(indexEntry.getKey());
            out.writeVInt(indexEntry.getValue().size());
            for (Map.Entry<String, Map<String, FieldMappingMetaData>> typeEntry : indexEntry.getValue().entrySet()) {
                out.writeString(typeEntry.getKey());
                out.writeVInt(typeEntry.getValue().size());
                for (Map.Entry<String, FieldMappingMetaData> fieldEntry : typeEntry.getValue().entrySet()) {
                    out.writeString(fieldEntry.getKey());
                    FieldMappingMetaData fieldMapping = fieldEntry.getValue();
                    out.writeString(fieldMapping.fullName());
                    XContentBuilder builder = JsonXContent.contentBuilder();
                    builder.map(fieldMapping.sourceAsMap());
                    BytesReference source = BytesReference.bytes(builder);
                    out.writeBytesReference(source);
                    //Map<String, Object> fmMap = fieldMapping.sourceAsMap();
//                    XContentGenerator generator = JsonXContent.jsonXContent.createGenerator(out);
//                    XContentHelper.
//                    out.writeMap(fmMap);
                }
            }
        }
    }


}
