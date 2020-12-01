package com.petalmd.armor.tests;

import io.searchbox.action.AbstractAction;
import io.searchbox.action.GenericResultAbstractAction;
import io.searchbox.client.config.ElasticsearchVersion;

/**
 * Created by jehuty0shift on 11/03/2020.
 */
public class DeletePipeline extends GenericResultAbstractAction {

    private final String pipelineId;


    DeletePipeline(final String pipelineId) {
        this.pipelineId = pipelineId;
    }

    @Override
    public String getRestMethodName() {
        return "DELETE";
    }

    @Override
    protected String getURLCommandExtension(ElasticsearchVersion elasticsearchVersion) {
        return "_ingest/pipeline";
    }


    @Override
    protected String buildURI(ElasticsearchVersion elasticsearchVersion) {
        return super.buildURI(elasticsearchVersion) + "/_ingest/pipeline/" + pipelineId;
    }


    public static class Builder extends AbstractAction.Builder<DeletePipeline, DeletePipeline.Builder> {

        private final String pipelineId;


        public Builder(final String pipelineId) {
            this.pipelineId = pipelineId;
        }

        @Override
        public DeletePipeline build() {
            return new DeletePipeline(pipelineId);
        }
    }

}
