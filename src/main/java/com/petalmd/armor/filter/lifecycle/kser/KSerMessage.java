package com.petalmd.armor.filter.lifecycle.kser;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;
import java.util.UUID;

/**
 * Created by jehuty0shift on 04/03/2020.
 */

public class KSerMessage {

    private final String entrypoint;

    private final Map<String, Object> params;

    private final String uuid;

    @JsonCreator
    public KSerMessage(@JsonProperty("params") final Map<String, Object> params, @JsonProperty("entrypoint") final String entrypoint) {
        this.params = params;
        this.entrypoint = entrypoint;
        this.uuid = UUID.randomUUID().toString();
    }

    @JsonProperty
    public String getEntrypoint() {
        return entrypoint;
    }

    @JsonProperty
    public Map<String, Object> getParams() {
        return params;
    }

    @JsonProperty
    public String getUuid() {
        return uuid;
    }

}
