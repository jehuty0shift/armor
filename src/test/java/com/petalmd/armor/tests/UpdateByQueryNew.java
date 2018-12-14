package com.petalmd.armor.tests;

import io.searchbox.action.AbstractMultiTypeActionBuilder;
import io.searchbox.action.GenericResultAbstractAction;
import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;

/**
 * Created by jehuty0shift on 21/11/18.
 */
public class UpdateByQueryNew extends GenericResultAbstractAction {


    protected UpdateByQueryNew(Builder builder) {
        super(builder);

        this.payload = builder.query;
        setURI(buildURI());
    }

    @Override
    protected String buildURI() {
        return super.buildURI() + "/_update_by_query";
    }

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
        return new HashCodeBuilder()
                .appendSuper(super.hashCode())
                .toHashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (obj == this) {
            return true;
        }
        if (obj.getClass() != getClass()) {
            return false;
        }

        return new EqualsBuilder()
                .appendSuper(super.equals(obj))
                .isEquals();
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
