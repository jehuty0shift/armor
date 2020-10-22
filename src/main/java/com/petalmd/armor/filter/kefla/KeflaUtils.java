package com.petalmd.armor.filter.kefla;

import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.common.compress.CompressedXContent;
import org.elasticsearch.common.xcontent.XContentHelper;
import kong.unirest.json.JSONObject;

import java.util.*;
import java.util.stream.Collector;
import java.util.stream.Collectors;

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
        if (jsonObj.has("indices_stream_fields")) {
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
                    //add default fields and meta-fields.
                    krtMap.put("streams",new KeflaRestType("streams"));
                    krtMap.put("_all",new KeflaRestType("_all"));
                    krtMap.put("_field_names",new KeflaRestType("_field_names"));
                    krtMap.put("_id",new KeflaRestType("_id"));
                    krtMap.put("_index",new KeflaRestType("_index"));
                    krtMap.put("_ignored",new KeflaRestType("_ignored"));
                    krtMap.put("_parent",new KeflaRestType("_parent"));
                    krtMap.put("_routing",new KeflaRestType("_routing"));
                    krtMap.put("_seq_no",new KeflaRestType("_seq_no"));
                    krtMap.put("_source",new KeflaRestType("_source"));
                    krtMap.put("_type",new KeflaRestType("_type"));
                    krtMap.put("_uid",new KeflaRestType("_uid"));
                    krtMap.put("_version",new KeflaRestType("_version"));
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
            String streamId = streamField.get("streams");
            if(streamId != null) {
                streamList.add(streamId);
            }
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

    public static Map<String, Map<String, KeflaRestType>> streamIndexMapToIndexMapFlattened(Map<String, Map<String, Map<String, KeflaRestType>>> streamIndexMap) {
        // we fuse fields without comparing indices number (mapping is stable across streams).
        // this version add
        Map<String, Map<String, KeflaRestType>> indexMap = new HashMap<>();

        for (Map.Entry<String, Map<String, Map<String, KeflaRestType>>> strIndEntry : streamIndexMap.entrySet()) {
            for (Map.Entry<String, Map<String, KeflaRestType>> indexEntry : strIndEntry.getValue().entrySet()) {
                Map<String, KeflaRestType> typeMap = indexMap.computeIfAbsent(indexEntry.getKey(), k -> new HashMap<>());
                typeMap.putAll(indexEntry.getValue());
            }
        }
        //flatten here the indexMap
        for(Map.Entry<String, Map<String, KeflaRestType>> indexMapEntry : indexMap.entrySet()) {
            Set<String> geoValues = indexMapEntry.getValue().entrySet().stream()
                    .filter(e -> (e.getValue().fields != null && e.getValue().fields.containsKey("geo")))
                    .map(e-> e.getKey() +".geo")
                    .collect(Collectors.toSet());
            for(String geoKey : geoValues) {
                indexMapEntry.getValue().put(geoKey, new KeflaRestType(geoKey));
            }
        }

        return indexMap;
    }
}
