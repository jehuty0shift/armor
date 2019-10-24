package com.petalmd.armor.filter.kefla;

import org.json.JSONObject;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by jehuty0shift on 23/10/19.
 */
public class KeflaUtils {

    private static final Map<String, KeflaRestType> DEFAULT_FIELD_MAP = Map.of(
            "message", new KeflaRestType("message"),
            "version", new KeflaRestType("version"),
            "source", new KeflaRestType("source"),
            "timestamp", new KeflaRestType("timestamp"),
            "streams", new KeflaRestType("streams")
    );


    public static Map<String, Map<String, Map<String, KeflaRestType>>> strFieldMapFromJsonObject(JSONObject jsonObj) {
        Map<String, Map<String, Map<String, KeflaRestType>>> streamFieldMap = new HashMap<>();
        if(!jsonObj.has("indices_stream_fields"));
        JSONObject indicesObj = jsonObj.getJSONObject("indices_stream_fields");
        for (String index : indicesObj.keySet()) {
            JSONObject indexMap = indicesObj.getJSONObject(index);
            for (String stream : indexMap.keySet()) {
                Map<String, Map<String, KeflaRestType>> indexFieldType = streamFieldMap.computeIfAbsent(stream, str -> new HashMap<>());
                Map<String, KeflaRestType> krtMap = indexFieldType.computeIfAbsent(index, i -> new HashMap<>());
                for (String field: indexMap.keySet()) {
                    if(field.equals("_id")) {
                        continue;
                    }
                    krtMap.put(field, new KeflaRestType(field));
                }
            }
        }

        return streamFieldMap;
    }

    public static Map<String, Map<String, KeflaRestType>> buildDefaultMapping(String index) {
        return Map.of(index, DEFAULT_FIELD_MAP);
    }
}
