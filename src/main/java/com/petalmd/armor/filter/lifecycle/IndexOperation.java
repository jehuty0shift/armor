package com.petalmd.armor.filter.lifecycle;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

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
    private List<String> indices;

    @JsonProperty
    private Integer numberOfShards;

    @JsonCreator
    public IndexOperation(){}

    public IndexOperation(Type type, String username, List<String> indices, Integer numberOfShards) {
        this.type = type;
        this.username = username;
        this.indices = indices;
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

    public List<String> getIndices() {
        return indices;
    }

    public void setIndices(List<String> indices) {
        this.indices = indices;
    }

    public Integer getNumberOfShards() {
        return numberOfShards;
    }

    public void setNumberOfShards(Integer numberOfShards) {
        this.numberOfShards = numberOfShards;
    }
}
