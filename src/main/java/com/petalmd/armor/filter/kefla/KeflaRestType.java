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
        BOOL("boolean"),
        DOUBLE("double"),
        DATE("date"),
        GEO("geo_point"),
        INTEGER("integer"),
        IP("ip"),
        KEYWORD("keyword"),
        LONG("long"),
        TEXT("text");

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
            case "version":
                this.type = ESType.KEYWORD.value;
                this.index = false;
                break;
            case "line":
                this.type = ESType.LONG.value;
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
                } else {
                    this.type = ESType.KEYWORD.value;
                }
                break;
        }
    }

}
