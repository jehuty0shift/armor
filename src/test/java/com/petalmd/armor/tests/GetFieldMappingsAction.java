package com.petalmd.armor.tests;

import com.google.common.base.Joiner;
import io.searchbox.action.AbstractMultiTypeActionBuilder;
import io.searchbox.action.GenericResultAbstractAction;
import io.searchbox.client.config.ElasticsearchVersion;

import java.util.List;

/**
 * Created by jehuty0shift on 26/10/18.
 */
public class GetFieldMappingsAction extends GenericResultAbstractAction {

    private String fields;
    protected GetFieldMappingsAction(Builder builder) {
        super(builder);
        fields= Joiner.on(',').join(builder.fields);
    }

    @Override
    protected String getURLCommandExtension(ElasticsearchVersion elasticsearchVersion) {
        return "_mapping";
    }

    @Override
    public String buildURI(ElasticsearchVersion elasticsearchVersion) {
        String finalUri = super.buildURI(elasticsearchVersion);
        finalUri += "/field";
        finalUri += "/"+ fields;
        return finalUri;
    }

    @Override
    public String getRestMethodName() {
        return "GET";
    }

    public static class Builder extends AbstractMultiTypeActionBuilder<GetFieldMappingsAction, Builder> {

        private List<String> fields;

        public GetFieldMappingsAction.Builder setFields(List<String> fieldList) throws IllegalArgumentException{
            if (fieldList == null || fieldList.isEmpty()) {
                throw new IllegalArgumentException("field List should not be empty or null");
            }
            this.fields = fieldList;

            return this;
        }

        @Override
        public GetFieldMappingsAction build() {
            return new GetFieldMappingsAction(this);
        }
    }


}

