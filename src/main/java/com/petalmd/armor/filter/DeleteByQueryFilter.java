package com.petalmd.armor.filter;

import com.petalmd.armor.service.ArmorConfigService;
import com.petalmd.armor.service.ArmorService;
import com.petalmd.armor.util.ArmorConstants;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.search.SearchAction;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.index.reindex.DeleteByQueryAction;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;

/**
 * Created by jehuty0shift on 26/11/18.
 */
public class DeleteByQueryFilter extends AbstractActionFilter {

    protected final Logger log = LogManager.getLogger(DeleteByQueryFilter.class);

    @Inject
    public DeleteByQueryFilter(final Settings settings, final ClusterService clusterService, final ThreadPool threadPool, final ArmorService armorService, final ArmorConfigService armorConfigService) {
        super(settings, armorService.getAuthenticationBackend(), armorService.getAuthorizator(), clusterService, armorService, armorConfigService, armorService.getAuditListener(), threadPool);
    }

    @Override
    public void applySecure(Task task, String action, ActionRequest request, ActionListener listener, ActionFilterChain chain) {

        ThreadContext tContext = threadpool.getThreadContext();

        if(action.equals(DeleteByQueryAction.NAME)) {
            log.debug("Delete by query starts");
            tContext.putTransient(ArmorConstants.ARMOR_DELETE_BY_QUERY_START,true);
        }

        if (action.equals(SearchAction.NAME)) {
            if(Boolean.TRUE.equals(tContext.getTransient(ArmorConstants.ARMOR_DELETE_BY_QUERY_START))) {
                log.debug("DeleteByQuery subrequest asked for bypass action filter. ");
                if(tContext.getTransient(ArmorConstants.ARMOR_ACTION_FILTER_BYPASS) == null) {
                    tContext.putTransient(ArmorConstants.ARMOR_ACTION_FILTER_BYPASS, true);
                }
            }
        }

        chain.proceed(task,action,request,listener);

    }
}
