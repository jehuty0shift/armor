package com.petalmd.armor.filter.kefla;

import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.common.compress.CompressedXContent;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.json.JSONObject;

import java.util.ArrayList;
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
        if (!jsonObj.has("indices_stream_fields")) ;
        JSONObject indicesObj = jsonObj.getJSONObject("indices_stream_fields");
        for (String index : indicesObj.keySet()) {
            JSONObject indexMap = indicesObj.getJSONObject(index);
            for (String stream : indexMap.keySet()) {
                Map<String, Map<String, KeflaRestType>> indexFieldType = streamFieldMap.computeIfAbsent(stream, str -> new HashMap<>());
                Map<String, KeflaRestType> krtMap = indexFieldType.computeIfAbsent(index, i -> new HashMap<>());
                JSONObject fieldMap = indexMap.getJSONObject(stream);
                for (String field : fieldMap.keySet()) {
                    if (field.equals("_id")) {
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


    public static List<String> streamFromFilters(CompressedXContent filter) {
        List<String> streamList = new ArrayList<>();
        //deprecated but used in Elastic code (true comes from usages in es code)
        Map<String, Object> filterMap = XContentHelper.convertToMap(new BytesArray(filter.uncompressed()), true).v2();
        Map<String, Object> boolMap = (Map<String, Object>) filterMap.get("bool");
        List<Map<String, Object>> shouldList = (List<Map<String, Object>>) boolMap.get("should");
        for (Map<String, Object> termItem : shouldList) {
            Map<String, String> streamField = (Map<String, String>) termItem.get("term");
            streamList.add(streamField.get("streams"));
        }

        return streamList;
    }


    public static Map<String, Map<String, KeflaRestType>> streamIndexMapToIndexMap(Map<String, Map<String, Map<String, KeflaRestType>>> streamIndexMap) {
        //we fuse fields without comparing indices number (mapping is stable across streams).
        Map<String, Map<String, KeflaRestType>> indexMap = new HashMap<>();

        for (Map.Entry<String, Map<String, Map<String, KeflaRestType>>> strIndEntry : streamIndexMap.entrySet()) {
            for (Map.Entry<String, Map<String, KeflaRestType>> indexEntry : strIndEntry.getValue().entrySet()) {
                Map<String, KeflaRestType> typeMap = indexMap.computeIfAbsent(indexEntry.getKey(), k -> new HashMap<>());
                typeMap.putAll(indexEntry.getValue());
            }
        }

        return indexMap;
    }
}
