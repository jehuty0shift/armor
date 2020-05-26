package com.petalmd.armor.filter.lifecycle;

import com.petalmd.armor.filter.lifecycle.kser.KSerMessage;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by jehuty0shift on 10/02/2020.
 */
public class AliasOperation {

    public enum Type {
        ADD,
        REMOVE
    }

    public AliasOperation(){}

    public AliasOperation(final String username, final String alias, final Type type, final List<String> indices) {
        this.username = username;
        this.alias = alias;
        this.type = type;
        this.indices = indices;
    }

    private String username;

    private String alias;

    private Type type;

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

    public KSerMessage buildKserMessage() {

        Map<String, Object> params = new HashMap<>();
        params.put("username", username);
        params.put("name", alias);
        if (type.equals(Type.ADD)) {
            params.put("indices", indices);
        }
        final String entrypoint = type.equals(Type.ADD) ? "ldp_ms.kafka.tasks.from_es.AliasFromESAdd" : "ldp_ms.kafka.tasks.from_es.AliasFromESDelete";
        return new KSerMessage(params, entrypoint);
    }

    public static AliasOperation fromKSerMessage(final KSerMessage kSerMessage) {
        AliasOperation aliasOp = new AliasOperation();
        final Map<String, Object> params = kSerMessage.getParams();
        aliasOp.setType(kSerMessage.getEntrypoint().equals("ldp_ms.kafka.tasks.from_es.AliasFromESAdd")?Type.ADD:Type.REMOVE);
        aliasOp.setUsername(params.get("username").toString());
        aliasOp.setAlias(params.get("name").toString());
        if(aliasOp.getType().equals(Type.ADD)) {
            aliasOp.setIndices((List<String>)params.get("indices"));
        }
        return aliasOp;
    }
}
