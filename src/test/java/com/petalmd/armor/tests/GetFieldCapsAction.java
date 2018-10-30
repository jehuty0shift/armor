package com.petalmd.armor.tests;

import io.searchbox.action.AbstractMultiIndexActionBuilder;
import io.searchbox.action.GenericResultAbstractAction;

import java.util.List;

/**
 * Created by jehuty0shift on 26/10/18.
 */
public class GetFieldCapsAction extends GenericResultAbstractAction {

    protected GetFieldCapsAction(Builder builder) {
        super(builder);
        setURI(buildURI());
    }

    @Override
    protected String buildURI() {
        return super.buildURI() + "/_field_caps";
    }

    @Override
    public String getURI() {
        return super.getURI();
    }

    @Override
    public String getRestMethodName() {
        return "GET";
    }

    public static class Builder extends AbstractMultiIndexActionBuilder<GetFieldCapsAction, Builder> {

        public GetFieldCapsAction.Builder setFields(List<String> fieldList) throws IllegalArgumentException{
            if (fieldList == null || fieldList.isEmpty()) {
                throw new IllegalArgumentException("field List should not be empty or null");
            }
            return setParameter("fields", String.join(",",fieldList));
        }


        @Override
        public GetFieldCapsAction build() {
            return new GetFieldCapsAction(this);
        }
    }


}

