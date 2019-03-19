/*
 * Copyright 2017 PetalMD.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.petalmd.armor.filter.obfuscation;

import com.petalmd.armor.service.ArmorConfigService;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoAction;
import org.elasticsearch.action.admin.cluster.state.ClusterStateAction;
import org.elasticsearch.action.admin.indices.get.GetIndexAction;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.Map;

/**
 * @author jehuty0shift
 *         Created by jehuty0shift on 13/03/17.
 */
public class ObfFilterFactory {

    protected static final Logger log = LogManager.getLogger(ObfFilterFactory.class);
    private final Map<String, Class> hubMap;
    private final Settings settings;
    private final ThreadContext threadContext;

    //private static ObfFilterFactory factory;


    public ObfFilterFactory(final Settings settings, final ThreadContext threadContext) {
        this.settings = settings;
        this.threadContext = threadContext;
        hubMap = new HashMap<>();
        hubMap.put(NodesInfoAction.NAME, ObfNodesInfoResponse.class);
        hubMap.put(GetIndexAction.NAME, ObfGetIndexResponse.class);
        hubMap.put(ClusterStateAction.NAME,ObfClusterStateResponse.class);
        if (log.isDebugEnabled()) {
            for (Map.Entry<String, Class> entry : hubMap.entrySet()) {
                log.debug("ObfuscationFilter will obfuscate " + entry.getKey() + " with" + entry.getValue().getName());
            }
        }
    }


    public ActionResponse getObfResponse(String actionResponseName, ActionResponse orig) {
        Class resp = hubMap.get(actionResponseName);
        try {

            Constructor ct = resp.getDeclaredConstructor(orig.getClass(), Settings.class, ThreadContext.class);
            ObfResponse obfResponse = (ObfResponse) ct.newInstance(orig, settings, threadContext);
            return obfResponse.getActionResponse();

        } catch (NoSuchMethodException | SecurityException | InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            log.error("Could not create obfuscated response", e);
            return null;
        }
    }


    public boolean canObfuscate(String actionResponseName) {
        return hubMap.containsKey(actionResponseName);
    }
}
