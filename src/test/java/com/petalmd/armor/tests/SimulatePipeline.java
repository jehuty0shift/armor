package com.petalmd.armor.tests;

import io.searchbox.action.AbstractAction;
import io.searchbox.action.GenericResultAbstractAction;
import io.searchbox.client.config.ElasticsearchVersion;

/**
 * Created by jehuty0shift on 11/03/2020.
 */
public class SimulatePipeline extends GenericResultAbstractAction {

    private final String pipelineId;


    SimulatePipeline(final String pipelineId, final String payload) {
        this.pipelineId = pipelineId;
        this.payload = payload;
    }

    @Override
    public String getRestMethodName() {
        return "POST";
    }

    @Override
    protected String getURLCommandExtension(ElasticsearchVersion elasticsearchVersion) {
        return "_ingest/pipeline";
    }


    @Override
    protected String buildURI(ElasticsearchVersion elasticsearchVersion) {
        return super.buildURI(elasticsearchVersion)  + "/_ingest/pipeline/" + (pipelineId==null?"_simulate":(pipelineId+"/_simulate"));
    }


    public static class Builder extends AbstractAction.Builder<SimulatePipeline, SimulatePipeline.Builder> {

        private final String pipelineId;
        private String payload;


        public Builder(){
            pipelineId  = null;
        }

        public Builder(final String pipelineId) {
            this.pipelineId = pipelineId;
        }


        public Builder payload(final String payload) {
            this.payload = payload;
            return this;
        }

        @Override
        public SimulatePipeline build() {
            return new SimulatePipeline(pipelineId, payload);
        }
    }

}
