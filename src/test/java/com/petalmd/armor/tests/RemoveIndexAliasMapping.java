package com.petalmd.armor.tests;

import com.google.common.base.Joiner;
import io.searchbox.indices.aliases.AbstractAliasMappingBuilder;
import io.searchbox.indices.aliases.AliasMapping;

import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * Created by jehuty0shift on 12/02/2020.
 */
public class RemoveIndexAliasMapping extends AliasMapping {

    protected RemoveIndexAliasMapping() {}

    protected RemoveIndexAliasMapping(Builder builder) {
        this.indices.addAll(builder.getIndices());
    }


    @Override
    public List<Map<String, Object>> getData() {

        List<Map<String, Object>> retList = new LinkedList<>();

        for (String index : indices) {
            Map<String, Object> paramsMap = new LinkedHashMap<>();
            paramsMap.put("index", index);

            Map<String, Object> actionMap = new LinkedHashMap<String, Object>();
            actionMap.put(getType(), paramsMap);
            retList.add(actionMap);
        }

        return retList;
    }

    @Override
    public String getType() {
        return "remove_index";
    }


    public static class Builder extends AbstractAliasMappingBuilder<RemoveIndexAliasMapping, Builder> {

        public Builder(String index) {
            super(index, null);
        }

        public List<String> getIndices() {
            return indices;
        }

        @Override
        public RemoveIndexAliasMapping build() {
            return new RemoveIndexAliasMapping(this);
        }
    }
}
