package com.petalmd.armor.tests;

import io.searchbox.action.AbstractMultiIndexActionBuilder;
import io.searchbox.action.GenericResultAbstractAction;
import io.searchbox.client.config.ElasticsearchVersion;

public class PutSettings extends GenericResultAbstractAction {

    protected PutSettings(PutSettings.Builder builder) {
        super(builder);
        this.payload = builder.source;
    }

    protected String buildURI(ElasticsearchVersion elasticsearchVersion) {
        return super.buildURI(elasticsearchVersion) + "/_settings";
    }

    public String getRestMethodName() {
        return "PUT";
    }

    public static class Builder extends AbstractMultiIndexActionBuilder<PutSettings, Builder> {
        private Object source;

        public Builder(Object source) {
            this.source = source;
        }

        public PutSettings build() {
            return new PutSettings(this);
        }
    }
}