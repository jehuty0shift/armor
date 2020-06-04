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
        UPDATE,
        REMOVE
    }

    public AliasOperation() {
    }

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
        if (!type.equals(Type.REMOVE)) {
            params.put("indexes", indices);
        }
        final String entrypoint;
        switch (type) {
            case ADD:
                entrypoint = "ldp_ms.kafka.tasks.from_es.AliasFromESAdd";
                break;
            case REMOVE:
                entrypoint = "ldp_ms.kafka.tasks.from_es.AliasFromESDelete";
                break;
            case UPDATE:
                entrypoint = "ldp_ms.kafka.tasks.from_es.AliasFromESUpdate";
                break;
            default:
                entrypoint = "";
                break;
        }

        return new KSerMessage(params, entrypoint);
    }

    public static AliasOperation fromKSerMessage(final KSerMessage kSerMessage) {
        AliasOperation aliasOp = new AliasOperation();
        final Map<String, Object> params = kSerMessage.getParams();
        if (kSerMessage.getEntrypoint().equals("ldp_ms.kafka.tasks.from_es.AliasFromESAdd")) {
            aliasOp.setType(Type.ADD);
        } else if (kSerMessage.getEntrypoint().equals("ldp_ms.kafka.tasks.from_es.AliasFromESDelete")) {
            aliasOp.setType(Type.REMOVE);
        } else {
            aliasOp.setType(Type.UPDATE);
        }
        aliasOp.setUsername(params.get("username").toString());
        aliasOp.setAlias(params.get("name").toString());
        if (!aliasOp.getType().equals(Type.REMOVE)) {
            aliasOp.setIndices((List<String>) params.get("indexes"));
        }
        return aliasOp;
    }
}
