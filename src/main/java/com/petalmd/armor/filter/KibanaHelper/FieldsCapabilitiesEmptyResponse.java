package com.petalmd.armor.filter.KibanaHelper;

import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.fieldcaps.FieldCapabilities;
import org.elasticsearch.action.fieldcaps.FieldCapabilitiesIndexResponse;
import org.elasticsearch.action.fieldcaps.FieldCapabilitiesResponse;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentBuilder;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Created by jehuty0shift on 25/10/18.
 */
public class FieldsCapabilitiesEmptyResponse {

//    private Map<String, Map<String, FieldCapabilities>> responseMap;
//    private List<FieldCapabilitiesIndexResponse> indexResponses;
//
//    private FieldCapabilitiesResponse response;
//
//    public FieldsCapabilitiesEmptyResponse(FieldCapabilitiesResponse response) {
//        this.response = response;
//    }
//
//    public void readFrom(StreamInput in) throws IOException {
//        super.readFrom(in);
//    }
//
//    public void writeTo(StreamOutput out) throws IOException {
//        super.writeTo(out);
//        out.writeMap(Collections.emptyMap(),StreamOutput::writeString,StreamOutput::writeString);
//    }
//
//
//
//    @Override
//    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
//        builder.field("fields", Collections.emptyMap());
//        return builder;
//    }
}
