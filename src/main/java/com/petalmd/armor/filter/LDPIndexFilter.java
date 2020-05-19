package com.petalmd.armor.filter;

import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authorization.ForbiddenException;
import com.petalmd.armor.service.ArmorConfigService;
import com.petalmd.armor.service.ArmorService;
import com.petalmd.armor.util.ArmorConstants;
import com.petalmd.armor.util.ConfigConstants;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.DocWriteRequest;
import org.elasticsearch.action.IndicesRequest;
import org.elasticsearch.action.bulk.BulkAction;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.delete.DeleteRequest;
import org.elasticsearch.action.index.IndexAction;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.ingest.GetPipelineResponse;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.action.support.master.AcknowledgedRequest;
import org.elasticsearch.action.support.master.AcknowledgedResponse;
import org.elasticsearch.action.update.UpdateRequest;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.common.xcontent.json.JsonXContent;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.Scheduler;
import org.elasticsearch.threadpool.ThreadPool;

import java.io.IOException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Stream;

public class LDPIndexFilter extends AbstractActionFilter {

    public static final String LDP_DEFAULT_PIPELINE = "ldpDefault";

    private static final Logger log = LogManager.getLogger(LDPIndexFilter.class);
    private final boolean enabled;
    private final String ldpIndex;
    private final String ldpPipelineName;
    private final Scheduler.Cancellable putPipelineTask;
    private AtomicBoolean ldpPipelineBuilt;

    private final Client client;


    public LDPIndexFilter(final Settings settings, final Client client, final ClusterService clusterService, final ArmorService armorService, final ArmorConfigService armorConfigService, final ThreadPool threadPool) {
        super(settings, armorService.getAuthenticationBackend(), armorService.getAuthorizator(), clusterService, armorService, armorConfigService, armorService.getAuditListener(), threadPool);
        this.enabled = settings.getAsBoolean(ConfigConstants.ARMOR_LDP_FILTER_ENABLED, false);
        this.ldpIndex = settings.get(ConfigConstants.ARMOR_LDP_INDEX);
        this.ldpPipelineName = settings.get(ConfigConstants.ARMOR_LDP_FILTER_LDP_PIPELINE_NAME, LDP_DEFAULT_PIPELINE);
        this.client = client;
        this.ldpPipelineBuilt = new AtomicBoolean(false);
        if (enabled) {
            this.putPipelineTask = threadPool.scheduleWithFixedDelay(() -> {
                putLDPPipelineIfNeeded();
            }, TimeValue.timeValueSeconds(30), ThreadPool.Names.GENERIC);
        } else {
            this.putPipelineTask = null;
        }
    }


    @Override
    public int order() {
        return Integer.MIN_VALUE + 14;
    }

    @Override
    public void applySecure(Task task, String action, ActionRequest request, ActionListener listener, ActionFilterChain chain) {
        if (!enabled || ldpIndex == null) {
            chain.proceed(task, action, request, listener);
            return;
        }

        final ThreadContext threadContext = threadpool.getThreadContext();
        final User user = threadContext.getTransient(ArmorConstants.ARMOR_AUTHENTICATED_USER);


        if (action.equals(IndexAction.NAME)) {
            IndexRequest iReq = (IndexRequest) request;
            if (iReq.index().equals(ldpIndex) && iReq.getPipeline() == null) {
                if (!ldpPipelineBuilt.get()) {
                    listener.onFailure(new ForbiddenException("this index is not ready"));
                    return;
                } else if (!putPipelineTask.isCancelled()) {
                    putPipelineTask.cancel();
                }
                log.debug("IndexAction targets ldp index {}", ldpIndex);
                iReq.setPipeline(ldpPipelineName);
            }
        } else if (action.equals(BulkAction.NAME)) {
            BulkRequest bReq = (BulkRequest) request;
            for (DocWriteRequest dwr : bReq.requests()) {
                if (ldpIndex.equals(dwr.index())) {
                    log.debug("inner bulkRequest target ldp index {}", ldpIndex);
                    if (!ldpPipelineBuilt.get()) {
                        listener.onFailure(new ForbiddenException("this index is not yet ready"));
                        return;
                    } else if (!putPipelineTask.isCancelled()) {
                        putPipelineTask.cancel();
                    }
                    if (dwr instanceof IndexRequest) {
                        IndexRequest iReq = (IndexRequest) dwr;
                        if (iReq.getPipeline() == null || iReq.getPipeline().isEmpty()) {
                            iReq.setPipeline(ldpPipelineName);
                        }
                    } else if (dwr instanceof UpdateRequest) {
                        log.debug("UpdateRequest not authorized");
                        auditListener.onMissingPrivileges(user.getName(), request, threadContext);
                        listener.onFailure(new ForbiddenException("Update Request in bulk on this index {} is not authorized", dwr.index()));
                        return;
                    } else if (dwr instanceof DeleteRequest) {
                        log.debug("DeleteRequest not authorized");
                        auditListener.onMissingPrivileges(user.getName(), request, threadContext);
                        listener.onFailure(new ForbiddenException("Delete Request in bulk on this index {} is not authorized", dwr.index()));
                        return;
                    }
                }
            }
        } else if (request instanceof IndicesRequest) {
            IndicesRequest iRequest = (IndicesRequest) request;
            if (Stream.of(iRequest.indices()).anyMatch(i -> i.startsWith(ldpIndex))) {
                if (iRequest.indices().length > 1) {
                    auditListener.onMissingPrivileges(user.getName(), request, threadContext);
                    listener.onFailure(new ForbiddenException("Forbidden to target multiple index and {}", ldpIndex));
                } else {
                    if (iRequest instanceof AcknowledgedRequest) {
                        listener.onResponse(new AcknowledgedResponse(true));
                    } else {
                        auditListener.onMissingPrivileges(user.getName(), request, threadContext);
                        listener.onFailure(new ForbiddenException("This action is not authorized for this index"));
                    }
                }
                return;
            }
        }

        chain.proceed(task, action, request, listener);
    }

    private void putLDPPipelineIfNeeded() {
        final CountDownLatch countDown = new CountDownLatch(1);
        client.admin().cluster().prepareGetPipeline(ldpPipelineName).execute(new ActionListener<GetPipelineResponse>() {
            @Override
            public void onResponse(GetPipelineResponse getPipelineResponse) {
                if (getPipelineResponse.isFound()) {
                    log.info("Default LDPPipeline has been found");
                    ldpPipelineBuilt.set(true);
                }
                countDown.countDown();
            }

            @Override
            public void onFailure(Exception e) {
                log.warn("couldn't check if pipeline was installed");
                countDown.countDown();
            }
        });

        try {
            countDown.await(30, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            log.warn("Waiting for GetResponse has been interrupted");
            return;
        }
        //
//               "{\n" +
//                "    \"description\": \"_description\",\n" +
//                "    \"processors\": [\n" +
//                "      {\n" +
//                "        \"ldp\" : {\n" +
//                "          \"generated\" : true,\n" +
//                "          \"drop_message\" : true\n" +
//                "        }\n" +
//                "      }\n" +
//                "   ]\n" +
//                "}";
        if (!ldpPipelineBuilt.get()) {
            log.info("Setting up the Basic pipeline");
            try {
                XContentBuilder jsonBuilder = JsonXContent.contentBuilder();
                jsonBuilder.startObject();
                jsonBuilder.field("description", "Basic Pipeline built by LDPIndexFilter");
                jsonBuilder.startArray("processors");
                jsonBuilder.startObject();
                jsonBuilder.startObject("ldp");
                jsonBuilder.field("generated", true);
                jsonBuilder.field("drop_message", true);
                jsonBuilder.endObject();
                jsonBuilder.endObject();
                jsonBuilder.endArray();
                jsonBuilder.endObject();
                final CountDownLatch finalCountDown = new CountDownLatch(1);
                client.admin().cluster().preparePutPipeline(ldpPipelineName, BytesReference.bytes(jsonBuilder), XContentType.JSON).execute(new ActionListener<AcknowledgedResponse>() {
                    @Override
                    public void onResponse(AcknowledgedResponse acknowledgedResponse) {
                        log.info("Default pipeline of LDPIndexFilter has been setup");
                        if (acknowledgedResponse.isAcknowledged()) {
                            ldpPipelineBuilt.set(true);
                        }
                        finalCountDown.countDown();
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.warn("error during put pipeline request", e);
                        finalCountDown.countDown();
                    }
                });

                try {
                    finalCountDown.await(30, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    log.warn("Waiting for PutResponse has been interrupted");
                    return;
                }

            } catch (IOException e) {
                log.warn("Put Pipeline failed due to an unexpected IO Error", e);
            }
        } else {
            putPipelineTask.cancel();
        }
    }


}
