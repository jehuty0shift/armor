package com.petalmd.armor.tests;

import io.searchbox.action.AbstractMultiIndexActionBuilder;
import io.searchbox.action.GenericResultAbstractAction;
import io.searchbox.client.config.ElasticsearchVersion;

/**
 * Created by jehuty0shift on 11/02/2020.
 */
public class IndexAliasAction extends GenericResultAbstractAction {

    private String alias;
    private String restMethodName;

    protected IndexAliasAction(Builder builder) {
        super(builder);
        this.restMethodName = builder.restMethodName;
        this.alias = builder.alias;
    }

    @Override
    public String getRestMethodName() {
        return restMethodName;
    }

    @Override
    protected String getURLCommandExtension(ElasticsearchVersion elasticsearchVersion) {
        return "_alias";
    }

    @Override
    protected String buildURI(ElasticsearchVersion elasticsearchVersion) {
        return super.buildURI(elasticsearchVersion)  + "/" + alias;
    }

    public static class Builder extends AbstractMultiIndexActionBuilder<IndexAliasAction, IndexAliasAction.Builder> {

        private String alias;
        private String restMethodName;

        public Builder(final String alias) {
            this.alias = alias;
        }

        protected Builder(){};

        public Builder setRestMethod(String restMethodName) {
            this.restMethodName = restMethodName;
            return this;
        }


        public IndexAliasAction build() {
            return new IndexAliasAction(this);
        }

    }

}
