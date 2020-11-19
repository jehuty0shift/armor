package com.petalmd.armor.tests;

import io.searchbox.action.AbstractMultiTypeActionBuilder;
import io.searchbox.action.GenericResultAbstractAction;

/**
 * Created by jehuty0shift on 21/11/18.
 */
public class UpdateByQueryNew extends GenericResultAbstractAction {


    protected UpdateByQueryNew(Builder builder) {
        super(builder);

        this.payload = builder.query;
    //    setURI(buildURI());
    }

//    @Override
//    protected String buildURI() {
//        return super.buildURI() + "/_update_by_query";
//    }

    @Override
    public String getPathToResult() {
        return "updated";
    }

    @Override
    public String getRestMethodName() {
        return "POST";
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        return super.equals(obj);
    }

    public static class Builder extends AbstractMultiTypeActionBuilder<UpdateByQueryNew, Builder> {

        private String query;

        public Builder(String query) {
            this.query = query;
        }

        @Override
        public UpdateByQueryNew build() {
            return new UpdateByQueryNew(this);
        }
    }
}
