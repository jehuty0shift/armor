package com.petalmd.armor.filter;

import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authorization.ForbiddenException;
import com.petalmd.armor.service.ArmorConfigService;
import com.petalmd.armor.service.ArmorService;
import com.petalmd.armor.util.ArmorConstants;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.search.ClearScrollAction;
import org.elasticsearch.action.search.ClearScrollRequest;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;

/**
 * Created by jehuty0shift on 19/03/19.
 */
public class ClearScrollFilter extends AbstractActionFilter {

    protected final Logger log = LogManager.getLogger(ClearScrollFilter.class);

    public ClearScrollFilter(final Settings settings, final ClusterService clusterService, final ThreadPool threadPool, final ArmorService armorService, final ArmorConfigService armorConfigService) {
        super(settings, armorService.getAuthenticationBackend(), armorService.getAuthorizator(), clusterService, armorService, armorConfigService, armorService.getAuditListener(), threadPool);
    }


    @Override
    public void applySecure(Task task, String action, ActionRequest request, ActionListener listener, ActionFilterChain chain) {

        if (action.equals(ClearScrollAction.NAME)) {

            ClearScrollRequest csRequest = (ClearScrollRequest) request;

            final ThreadContext threadContext = threadpool.getThreadContext();

            User user = threadContext.getTransient(ArmorConstants.ARMOR_AUTHENTICATED_USER);
            if (csRequest.scrollIds().isEmpty() || csRequest.scrollIds().contains("_all")) {
                log.warn("attempt to clear all scroll from user " + user.getName());
                throw new ForbiddenException("_all is not allowed for scroll Ids parameters");
            }

        }

        chain.proceed(task, action, request, listener);

    }
}
