package com.petalmd.armor.filter.kefla;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.admin.indices.mapping.get.GetFieldMappingsAction;
import org.elasticsearch.action.admin.indices.mapping.get.GetMappingsAction;
import org.elasticsearch.action.fieldcaps.FieldCapabilitiesAction;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.Map;

/**
 * Created by jehuty0shift on 25/10/19.
 */
public class KeflaResponseFactory {

    private final Map<String, Class> hubMap;
    private static final Logger log = LogManager.getLogger(KeflaResponseFactory.class);

    public KeflaResponseFactory() {
        hubMap = Map.of(
                GetMappingsAction.NAME, KeflaGetMappingsResponse.class,
                GetFieldMappingsAction.NAME, KeflaGetFieldMappingsResponse.class,
                FieldCapabilitiesAction.NAME, KeflaFieldCapabilitiesResponse.class
        );
    }

    public ActionResponse getResponse(final String action, final ActionResponse orig, Map<String, Map<String, Map<String, KeflaRestType>>> strIndFieldMap) {

        Class resp = hubMap.get(action);
        try {

            Constructor ct = resp.getDeclaredConstructor(orig.getClass(), Map.class);
            KeflaResponse keflaResponse = (KeflaResponse) ct.newInstance(orig, strIndFieldMap);
            return keflaResponse.getActionResponse();

        } catch (NoSuchMethodException | SecurityException | InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            log.error("Could not create Kefla response", e);
            return null;
        }


    }

}
