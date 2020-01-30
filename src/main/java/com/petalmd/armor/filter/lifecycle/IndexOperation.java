package com.petalmd.armor.filter.lifecycle;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Created by jehuty0shift on 30/01/2020.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class IndexOperation {

    public enum Type {
        CREATE,
        DELETE
    }

    @JsonProperty
    private Type type;

    @JsonProperty
    private String username;

    @JsonProperty
    private String index;

    @JsonProperty
    private Integer numberOfShards;


    public IndexOperation(Type type, String username, String index, Integer numberOfShards) {
        this.type = type;
        this.username = username;
        this.index = index;
        this.numberOfShards = numberOfShards;
    }


    public Type getType() {
        return type;
    }

    public void setType(Type type) {
        this.type = type;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getIndex() {
        return index;
    }

    public void setIndex(String index) {
        this.index = index;
    }

    public Integer getNumberOfShards() {
        return numberOfShards;
    }

    public void setNumberOfShards(Integer numberOfShards) {
        this.numberOfShards = numberOfShards;
    }
}
