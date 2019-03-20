package com.petalmd.armor.tests;

import io.searchbox.action.AbstractAction;
import io.searchbox.action.GenericResultAbstractAction;
import io.searchbox.client.config.ElasticsearchVersion;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by jehuty0shift on 19/03/19.
 */
public class ClearScroll extends GenericResultAbstractAction {

    private final List<String> scrollIds;
    private final boolean deleteAll;

    protected ClearScroll(Builder builder) {
        super(builder);
        this.scrollIds = builder.scrollIds;
        deleteAll = scrollIds.contains("_all");
        if (!deleteAll) {
            StringBuilder payloadBuilder = new StringBuilder();
            payloadBuilder.append('{');
            payloadBuilder.append("\"scroll_id\" : [");
            for (int i = 0; i < scrollIds.size(); i++) {
                final String scrollId = scrollIds.get(i);
                payloadBuilder.append('\"').append(scrollId).append('\"');
                if (i + 1 < scrollIds.size()) {
                    payloadBuilder.append(',');
                }
            }
            payloadBuilder.append(']');
            payloadBuilder.append('}');

            this.payload = payloadBuilder.toString();
        }
    }


    @Override
    public String getRestMethodName() {
        return "DELETE";
    }

    @Override
    protected String buildURI(ElasticsearchVersion elasticsearchVersion) {
        return deleteAll?"_search/scroll/_all":"_search/scroll";
    }



    public static class Builder extends AbstractAction.Builder<ClearScroll, Builder> {

        private final List<String> scrollIds;

        public Builder(String scrollId) {
            this.scrollIds = new ArrayList<>();
            scrollIds.add(scrollId);
        }

        public Builder(List<String> scrollIds) {
            this.scrollIds = scrollIds;
        }


        @Override
        public ClearScroll build() {
            return new ClearScroll(this);
        }
    }
}
