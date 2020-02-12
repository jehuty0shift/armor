package com.petalmd.armor.filter.lifecycle;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Created by jehuty0shift on 10/02/2020.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AliasOperation {

    public enum Type {
        ADD,
        REMOVE
    }

    @JsonCreator
    public AliasOperation() {
    }

    public AliasOperation(final String username, final String alias, final Type type, final List<String> indices) {
        this.username = username;
        this.alias = alias;
        this.type = type;
        this.indices = indices;
    }

    @JsonProperty
    private String username;

    @JsonProperty
    private String alias;

    @JsonProperty
    private Type type;

    @JsonProperty
    private List<String> indices;


    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public Type getType() {
        return type;
    }

    public void setType(Type type) {
        this.type = type;
    }

    public List<String> getIndices() {
        return indices;
    }

    public void setIndices(List<String> indices) {
        this.indices = indices;
    }
    
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }
}
