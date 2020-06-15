package com.petalmd.armor.filter.lifecycle;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.petalmd.armor.filter.lifecycle.kser.KSerMessage;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

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

    @JsonCreator
    public IndexOperation() {
    }

    public IndexOperation(final Type type, final String username, final String index, final Integer numberOfShards) {
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

    public KSerMessage buildKserMessage() {

        Map<String, Object> params = new HashMap<>();
        params.put("username", username);
        params.put("name", index);
        params.put("nbShard", numberOfShards);
        final String entrypoint = type.equals(Type.CREATE) ? "ldp_ms.kafka.tasks.from_es.IndexFromESAdd" : "ldp_ms.kafka.tasks.from_es.IndexFromESDelete";
        return new KSerMessage(params, entrypoint);
    }

    public static IndexOperation fromKserMessage(KSerMessage kSerMessage) {
        final IndexOperation indexOp = new IndexOperation();
        Map<String, Object> params = kSerMessage.getParams();
        final String entrypoint = kSerMessage.getEntrypoint();

        indexOp.setIndex(params.get("name").toString());
        indexOp.setNumberOfShards((Integer)params.get("nbShard"));
        indexOp.setUsername(params.get("username").toString());
        indexOp.setType(entrypoint.equals("ldp_ms.kafka.tasks.from_es.IndexFromESAdd")?Type.CREATE:Type.DELETE);

        return indexOp;
    }

}
