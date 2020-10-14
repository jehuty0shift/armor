package com.petalmd.armor.filter.kefla;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.collect.ImmutableMap;

import java.util.Map;

/**
 * Created by jehuty0shift on 03/10/19.
 */

@JsonAutoDetect
public class KeflaRestType {

    @JsonProperty
    public String type;

    @JsonProperty
    public Map<String, KeflaRestType> fields;

    @JsonProperty
    public Boolean ignore_malformed;

    @JsonProperty
    public Boolean index;

    @JsonProperty
    public String format;

    @JsonProperty
    public Boolean norms;

    @JsonProperty
    public Boolean fielddata;

    @JsonProperty
    public String analyzer;

    public enum ESType {
        ALL("_all"),
        BOOL("boolean"),
        DOUBLE("double"),
        DATE("date"),
        FIELD_NAMES("_field_names"),
        GEO("geo_point"),
        ID("_id"),
        INDEX("_index"),
        IGNORED("_ignored"),
        INTEGER("integer"),
        IP("ip"),
        KEYWORD("keyword"),
        LONG("long"),
        PARENT("_parent"),
        ROUTING("_routing"),
        SEQ_NO("_seq_no"),
        SOURCE("_source"),
        TEXT("text"),
        TYPE("_type"),
        UID("_uid"),
        VERSION("_version");

        public final String value;

        ESType(final String value) {
            this.value = value;
        }

    }

    public KeflaRestType() {
    }

    public KeflaRestType(String fieldName) {
        //Handle geo
        switch (fieldName) {

            case "source":
                this.type = ESType.TEXT.value;
                this.norms = false;
                this.analyzer = "analyzer_keyword";
                this.fielddata = true;
                break;
            case "message":
            case "full_message":
                this.type = ESType.TEXT.value;
                this.norms = false;
                this.analyzer = "standard";
                break;
            case "timestamp":
                this.type = ESType.DATE.value;
                this.format = "yyyy-MM-dd HH:mm:ss.SS";
                break;
            case "X-OVH-TOKEN":
                this.type = ESType.DATE.value;
                break;
            case "version":
                this.type = ESType.KEYWORD.value;
                this.index = false;
                break;
            case "_routing":
                this.type = ESType.ROUTING.value;
                break;
            case "_index":
                this.type = ESType.INDEX.value;
                break;
            case "_type":
                this.type = ESType.TYPE.value;
                break;
            case "_all":
                this.type = ESType.ALL.value;
                break;
            case "_ignored":
                this.type = ESType.IGNORED.value;
                break;
            case "_seq_no":
                this.type = ESType.SEQ_NO.value;
                break;
            case "_parent":
                this.type = ESType.PARENT.value;
                break;
            case "_field_names":
                this.type = ESType.FIELD_NAMES.value;
                break;
            case "_source":
                this.type = ESType.SOURCE.value;
                break;
            case "_id":
                this.type = ESType.ID.value;
                break;
            case "_version":
                this.type = ESType.VERSION.value;
                break;
            case "_uid":
                this.type = ESType.UID.value;
                break;
            default:
                if (fieldName.equals("geo")) {
                    this.type = ESType.GEO.value;
                    this.ignore_malformed = true;
                } else if (fieldName.endsWith("_double") || fieldName.endsWith("_float")) {
                    this.type = ESType.DOUBLE.value;
                } else if (fieldName.endsWith("_long") || fieldName.endsWith("_int")) {
                    this.type = ESType.LONG.value;
                } else if (fieldName.endsWith("_date")) {
                    this.type = ESType.DATE.value;
                    this.format = "date_optional_time";
                } else if (fieldName.endsWith("_geolocation")) {
                    this.type = ESType.KEYWORD.value;
                    this.fields = ImmutableMap.of("geo", new KeflaRestType("geo"));
                } else if (fieldName.endsWith("_bool")) {
                    this.type = ESType.BOOL.value;
                } else if (fieldName.endsWith("_ip")) {
                    this.type = ESType.IP.value;
                } else if (fieldName.endsWith(".geo")) {
                    this.type = ESType.GEO.value;
                    this.ignore_malformed = true;
                } else {
                    this.type = ESType.KEYWORD.value;
                }
                break;
        }
    }

}
