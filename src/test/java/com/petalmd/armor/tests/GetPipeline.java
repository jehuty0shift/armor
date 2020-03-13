package com.petalmd.armor.tests;

import io.searchbox.action.AbstractAction;
import io.searchbox.action.GenericResultAbstractAction;
import io.searchbox.client.config.ElasticsearchVersion;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Created by jehuty0shift on 11/03/2020.
 */
public class GetPipeline extends GenericResultAbstractAction {

    private final List<String> pipelineIds;


    GetPipeline(final List<String> pipelineIds) {
        this.pipelineIds = pipelineIds;
    }

    @Override
    public String getRestMethodName() {
        return "GET";
    }

    @Override
    protected String getURLCommandExtension(ElasticsearchVersion elasticsearchVersion) {
        return "_ingest/pipeline";
    }


    @Override
    protected String buildURI(ElasticsearchVersion elasticsearchVersion) {
        return super.buildURI(elasticsearchVersion) + "/_ingest/pipeline/" + pipelineIds.stream().collect(Collectors.joining(","));
    }


    public static class Builder extends AbstractAction.Builder<GetPipeline, GetPipeline.Builder> {

        private final List<String> pipelineIds;


        public Builder(final String... pipelineIds) {
            this.pipelineIds = Arrays.asList(pipelineIds);
        }

        @Override
        public GetPipeline build() {
            return new GetPipeline(pipelineIds);
        }
    }

}
