package com.petalmd.armor.filter;

import com.petalmd.armor.authentication.User;
import com.petalmd.armor.service.ArmorConfigService;
import com.petalmd.armor.service.ArmorService;
import com.petalmd.armor.util.ArmorConstants;
import com.petalmd.armor.util.ConfigConstants;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.bulk.BulkAction;
import org.elasticsearch.action.index.IndexAction;
import org.elasticsearch.action.ingest.*;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.ingest.IngestService;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;

import java.util.Map;

/**
 * Created by jehuty0shift on 26/02/2020.
 */
public class IngestPipelineFilter extends AbstractActionFilter {

    private static final Logger log = LogManager.getLogger(IngestPipelineFilter.class);
    private final boolean enabled;
    private final IngestService ingestService;

    public IngestPipelineFilter(final Settings settings, final ClusterService clusterService, final ArmorService armorService, final ArmorConfigService armorConfigService, final ThreadPool threadPool, final IngestService ingestService) {
        super(settings, armorService.getAuthenticationBackend(), armorService.getAuthorizator(), clusterService, armorService, armorConfigService, armorService.getAuditListener(), threadPool);
        enabled = settings.getAsBoolean(ConfigConstants.ARMOR_INGEST_PIPELINE_FILTER_ENABLED, true);
        this.ingestService = ingestService;
        log.info("IngestPipelineFilter is {}", enabled ? "enabled" : "disabled");
    }

    @Override
    public int order() {
        return Integer.MIN_VALUE + 10;
    }

    @Override
    public void applySecure(Task task, String action, ActionRequest request, ActionListener listener, ActionFilterChain chain) {

        if (!enabled || (!action.equals(DeletePipelineAction.NAME)
                && !action.equals(PutPipelineAction.NAME)
                && !action.equals(GetPipelineAction.NAME)
                && !action.equals(SimulatePipelineAction.NAME)
                && !action.equals(BulkAction.NAME)
                && !action.equals(IndexAction.NAME))
        ) {
            chain.proceed(task, action, request, listener);
            return;
        }

        final ThreadContext threadContext = threadpool.getThreadContext();
        final User user = threadContext.getTransient(ArmorConstants.ARMOR_AUTHENTICATED_USER);

        if (action.equals(PutPipelineAction.NAME)) {
            PutPipelineRequest putPipelineRequestReq = (PutPipelineRequest) request;
            applyPutPipeline(user,action,putPipelineRequestReq,listener, chain);
            return;
        }


    }


    private void applyPutPipeline(final User user, final String action, final PutPipelineRequest request, final ActionListener listener, final ActionFilterChain chain) {

        final String newId = user.getName() + "-" + request.getId();

        Map<String, Object> pipelineConfig = XContentHelper.convertToMap(request.getSource(), false, request.getXContentType()).v2();
        // find processor config using Pipeline create Code,
        // Change PipelineProcessor config to call a user-prefixed processor
        // Assert Script code does not contain any ctx._index assignement ( creates a Regexp for that) Nazi mode
        //


    }



}
