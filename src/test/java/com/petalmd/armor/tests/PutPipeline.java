package com.petalmd.armor.tests;

import io.searchbox.action.AbstractAction;
import io.searchbox.action.GenericResultAbstractAction;
import io.searchbox.client.config.ElasticsearchVersion;

/**
 * Created by jehuty0shift on 11/03/2020.
 */
public class PutPipeline extends GenericResultAbstractAction {

    private final String pipelineId;


    PutPipeline(final String pipelineId, final String payload) {
        this.pipelineId = pipelineId;
        this.payload = payload;
    }

    @Override
    public String getRestMethodName() {
        return "PUT";
    }

    @Override
    protected String getURLCommandExtension(ElasticsearchVersion elasticsearchVersion) {
        return "_ingest/pipeline";
    }


    @Override
    protected String buildURI(ElasticsearchVersion elasticsearchVersion) {
        return super.buildURI(elasticsearchVersion)  + "/_ingest/pipeline/" + pipelineId;
    }


    public static class Builder extends AbstractAction.Builder<PutPipeline, PutPipeline.Builder> {

        private final String pipelineId;
        private String payload;

        public Builder(final String pipelineId) {
            this.pipelineId = pipelineId;
        }


        public Builder payload(final String payload) {
            this.payload = payload;
            return this;
        }

        @Override
        public PutPipeline build() {
            return new PutPipeline(pipelineId, payload);
        }
    }

}
