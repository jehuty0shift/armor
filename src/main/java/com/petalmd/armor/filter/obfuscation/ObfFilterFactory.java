package com.petalmd.armor.filter.obfuscation;

import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoAction;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;

import java.lang.reflect.Constructor;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by bdiasse on 13/03/17.
 */
public class ObfFilterFactory {

    protected static final ESLogger log = Loggers.getLogger(ObfFilterFactory.class);
    private final Map<String,Class> hubMap;

    private static ObfFilterFactory factory;

    static public ObfFilterFactory getObfFilterFactory(){
        if (factory != null) {
            return factory;
        }
        factory = new ObfFilterFactory();
        return factory;
    }


    private ObfFilterFactory(){
        hubMap = new HashMap<>();
        hubMap.put(NodesInfoAction.NAME,ObfNodesInfoResponse.class);
        if (log.isDebugEnabled()) {
            for(Map.Entry<String,Class> entry : hubMap.entrySet()){
                log.debug("ObfuscationFilter will obfuscate " + entry.getKey() + " with" + entry.getValue().getName());
            }
        }
    }

    public void addObfFilterResponse(String filterBaseClass, Class response) {
        hubMap.put(filterBaseClass,response);
    }

    public ActionResponse getObfResponse(String actionResponseName, ActionResponse orig){
        Class resp = hubMap.get(actionResponseName);
        try {
            Constructor ct = resp.getDeclaredConstructor(orig.getClass());
            return (ActionResponse)ct.newInstance(orig);
        } catch (Exception e){
            return null;
        }
    }


    public boolean canObfuscate(String actionResponseName) {
        return hubMap.containsKey(actionResponseName);
    }
}
