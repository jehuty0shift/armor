package com.petalmd.armor.filter;

import com.petalmd.armor.service.ArmorConfigService;
import com.petalmd.armor.service.ArmorService;
import com.petalmd.armor.util.ArmorConstants;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.fieldcaps.FieldCapabilitiesAction;
import org.elasticsearch.action.search.SearchAction;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.index.reindex.DeleteByQueryAction;
import org.elasticsearch.index.reindex.UpdateByQueryAction;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;

/**
 * Created by jehuty0shift on 19/02/19.
 */
public class BypassFilter extends AbstractActionFilter {

    protected final Logger log = LogManager.getLogger(BypassFilter.class);

    public static final String FIELD_CAPS_INDEX_ACTION_NAME = FieldCapabilitiesAction.NAME + "[index]";

    public BypassFilter(final Settings settings, final ClusterService clusterService, final ThreadPool threadPool, final ArmorService armorService, final ArmorConfigService armorConfigService) {
        super(settings, armorService.getAuthenticationBackend(), armorService.getAuthorizator(), clusterService, armorService, armorConfigService, armorService.getAuditListener(), threadPool);
    }

    @Override
    public int order() {
        return Integer.MIN_VALUE+1;
    }

    public void applySecure(Task task, String action, ActionRequest request, ActionListener listener, ActionFilterChain chain) {

        ThreadContext tContext = threadpool.getThreadContext();

        //Check UpdateByQuery.
        if (action.equals(UpdateByQueryAction.NAME)) {
            log.debug("Update By query starts");
            tContext.putTransient(ArmorConstants.ARMOR_UPDATE_BY_QUERY_START, true);
        }

        if (action.equals(SearchAction.NAME) && Boolean.TRUE.equals(tContext.getTransient(ArmorConstants.ARMOR_UPDATE_BY_QUERY_START))) {
            log.debug("UpdateByQuery subrequest asked for bypass action filter. ");
            if (tContext.getTransient(ArmorConstants.ARMOR_ACTION_FILTER_BYPASS) == null) {
                tContext.putTransient(ArmorConstants.ARMOR_ACTION_FILTER_BYPASS, true);
            }
        }

        //Check DeleteByQuery
        if(action.equals(DeleteByQueryAction.NAME)) {
            log.debug("Delete by query starts");
            tContext.putTransient(ArmorConstants.ARMOR_DELETE_BY_QUERY_START,true);
        }

        if (action.equals(SearchAction.NAME) && Boolean.TRUE.equals(tContext.getTransient(ArmorConstants.ARMOR_DELETE_BY_QUERY_START))) {
            if(Boolean.TRUE.equals(tContext.getTransient(ArmorConstants.ARMOR_DELETE_BY_QUERY_START))) {
                log.debug("DeleteByQuery subrequest asked for bypass action filter. ");
                if(tContext.getTransient(ArmorConstants.ARMOR_ACTION_FILTER_BYPASS) == null) {
                    tContext.putTransient(ArmorConstants.ARMOR_ACTION_FILTER_BYPASS, true);
                }
            }
        }

        if(action.equals(FieldCapabilitiesAction.NAME)) {

            //TransportFieldCapabilitiesIndexAction
            log.debug("Field Capabilities action starts");
            tContext.putTransient(ArmorConstants.ARMOR_FIELD_CAPS_ACTION_START,true);
        }

        if (action.equals(FIELD_CAPS_INDEX_ACTION_NAME)) {
            if(Boolean.TRUE.equals(tContext.getTransient(ArmorConstants.ARMOR_FIELD_CAPS_ACTION_START))) {
                log.debug("Field Capabilities subrequest on concrete indices asked for bypass action filter. ");
                if(tContext.getTransient(ArmorConstants.ARMOR_ACTION_FILTER_BYPASS) == null) {
                    tContext.putTransient(ArmorConstants.ARMOR_ACTION_FILTER_BYPASS, true);
                }
            }
        }

        chain.proceed(task, action, request, listener);

    }


}
