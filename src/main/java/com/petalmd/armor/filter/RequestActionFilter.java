/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
 * Copyright 2015 PetalMD
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.petalmd.armor.filter;

import com.petalmd.armor.service.ArmorConfigService;
import com.petalmd.armor.service.ArmorService;
import com.petalmd.armor.util.ArmorConstants;
import com.petalmd.armor.util.ConfigConstants;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;

import java.util.*;
import java.util.Map.Entry;

public class RequestActionFilter extends AbstractActionFilter {

    private static final String filterType = "actionrequestfilter";
    private final Map<String, Tuple<List<String>, List<String>>> filterMap = new HashMap<String, Tuple<List<String>, List<String>>>();

    @Inject
    public RequestActionFilter(final Settings settings, final ClusterService clusterService, final ThreadPool threadPool, final ArmorService armorService, final ArmorConfigService armorConfigService) {
        super(settings, armorService.getAuthenticationBackend(), armorService.getAuthorizator(), clusterService,armorService, armorConfigService, armorService.getAuditListener(), threadPool);

        final List<String> arFilters = settings.getAsList(ConfigConstants.ARMOR_ACTIONREQUESTFILTER);
        for (final String filterName : arFilters) {

            final List<String> allowedActions = settings.getAsList("armor." + filterType + "." + filterName
                    + ".allowed_actions", Collections.emptyList());
            final List<String> forbiddenActions = settings.getAsList("armor." + filterType + "." + filterName
                    + ".forbidden_actions", Collections.emptyList());

            filterMap.put(filterName, new Tuple<List<String>, List<String>>(allowedActions, forbiddenActions));
        }
    }

    @Override
    public void applySecure(Task task, final String action, final ActionRequest request, final ActionListener listener, final ActionFilterChain chain) {

        if (filterMap.size() == 0) {
            chain.proceed(task, action, request, listener);
            return;
        }

        final ThreadContext threadContext = threadpool.getThreadContext();

        for (final Iterator<Entry<String, Tuple<List<String>, List<String>>>> it = filterMap.entrySet().iterator(); it.hasNext();) {

            final Entry<String, Tuple<List<String>, List<String>>> entry = it.next();

            final String filterName = entry.getKey();
            final List<String> allowedActions = entry.getValue().v1();
            final List<String> forbiddenActions = entry.getValue().v2();

            String allowedActionsKey = "armor." + filterType + "." + filterName + ".allowed_actions";
            String forbiddenActionsKey = "armor." + filterType + "." + filterName + ".allowed_actions";

            if (threadContext.getTransient(allowedActionsKey) == null) {
                threadContext.putTransient("armor." + filterType + "." + filterName + ".allowed_actions", allowedActions);
            }
            if (threadContext.getTransient(forbiddenActionsKey) == null) {
                threadContext.putTransient("armor." + filterType + "." + filterName + ".forbidden_actions", forbiddenActions);
            }

            if (threadContext.getTransient(ArmorConstants.ARMOR_FILTER) != null && filterType != null) {
                if (!((List<String>) threadContext.getTransient(ArmorConstants.ARMOR_FILTER)).contains(filterType + ":" + filterName)) {
                    ((List<String>) threadContext.getTransient(ArmorConstants.ARMOR_FILTER)).add(filterType + ":" + filterName);
                }
            } else if (filterType != null) {
                final List<String> _filters = new ArrayList<String>();
                _filters.add(filterType + ":" + filterName);
                threadContext.putTransient(ArmorConstants.ARMOR_FILTER, _filters);
            }
        }

        chain.proceed(task, action, request, listener);
    }

}
