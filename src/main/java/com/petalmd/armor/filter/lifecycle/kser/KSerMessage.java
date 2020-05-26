package com.petalmd.armor.filter.lifecycle.kser;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;
import java.util.UUID;

/**
 * Created by jehuty0shift on 04/03/2020.
 */

@JsonAutoDetect
public class KSerMessage {

    @JsonProperty
    private final String entrypoint;

    @JsonProperty
    private final Map<String, Object> params;

    @JsonProperty
    private final String uuid;

    public KSerMessage(@JsonProperty("params") final Map<String, Object> params, @JsonProperty("entrypoint") final String entrypoint) {
        this.params = params;
        this.entrypoint = entrypoint;
        this.uuid = UUID.randomUUID().toString();
    }

    public String getEntrypoint() {
        return entrypoint;
    }

    public Map<String, Object> getParams() {
        return params;
    }

    public String getUuid() {
        return uuid;
    }

}
