package com.petalmd.armor.filter;

import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authorization.ForbiddenException;
import com.petalmd.armor.service.ArmorConfigService;
import com.petalmd.armor.service.ArmorService;
import com.petalmd.armor.util.ArmorConstants;
import com.petalmd.armor.util.ConfigConstants;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.DocWriteRequest;
import org.elasticsearch.action.bulk.BulkAction;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.index.IndexAction;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.ingest.*;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.cluster.metadata.AliasOrIndex;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.*;
import org.elasticsearch.common.xcontent.json.JsonXContent;
import org.elasticsearch.ingest.*;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;

import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Created by jehuty0shift on 26/02/2020.
 */
public class IngestPipelineFilter extends AbstractActionFilter {

    private static final Logger log = LogManager.getLogger(IngestPipelineFilter.class);
    private final boolean enabled;
    private IngestService ingestService;
    private final List<Pattern> forbiddenScriptPatterns;

    public IngestPipelineFilter(final Settings settings, final ClusterService clusterService, final ArmorService armorService, final ArmorConfigService armorConfigService, final ThreadPool threadPool) {
        super(settings, armorService.getAuthenticationBackend(), armorService.getAuthorizator(), clusterService, armorService, armorConfigService, armorService.getAuditListener(), threadPool);
        enabled = settings.getAsBoolean(ConfigConstants.ARMOR_INGEST_PIPELINE_FILTER_ENABLED, true);
        log.info("IngestPipelineFilter is {}", enabled ? "enabled" : "disabled");
        forbiddenScriptPatterns = new ArrayList<>();
        forbiddenScriptPatterns.add(Pattern.compile(".*ctx\\._index\\s+=\\s+.*"));
    }

    @Override
    public int order() {
        return Integer.MIN_VALUE + 13;
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

        if (ingestService == null) {
            ingestService = armorService.getIngestService();
            if (ingestService == null && enabled) {
                listener.onFailure(new ForbiddenException("Ingest Service cannot be found"));
                return;
            }
        }

        final ThreadContext threadContext = threadpool.getThreadContext();
        final User user = threadContext.getTransient(ArmorConstants.ARMOR_AUTHENTICATED_USER);

        if (action.equals(BulkAction.NAME)) {
            BulkRequest bReq = (BulkRequest) request;
            final String globalPipeline = bReq.pipeline();
            if(globalPipeline != null && !globalPipeline.isEmpty() && !globalPipeline.startsWith(user.getName() + "-")) {
                bReq.pipeline(user.getName() + "-" + globalPipeline);
            }
            for(DocWriteRequest dwr : bReq.requests()) {
                if (dwr instanceof IndexRequest) {
                    IndexRequest iReq = (IndexRequest) dwr;
                    final String pipeline = iReq.getPipeline();
                    if (pipeline != null && !pipeline.isEmpty() && !iReq.getPipeline().startsWith(user.getName())) {
                        iReq.setPipeline(user.getName() + "-" + pipeline);
                    }
                }
            }
            chain.proceed(task, action, bReq, listener);
            return;
        } else if (action.equals(PutPipelineAction.NAME)) {
            PutPipelineRequest putPipelineRequestReq = (PutPipelineRequest) request;
            try {
                PutPipelineRequest newPPReq = transformPutPipeline(user, putPipelineRequestReq);
                chain.proceed(task, action, newPPReq, listener);
                return;
            } catch (ForbiddenException ex) {
                log.error("Forbidden Error during PutPipelineRequest", ex);
                listener.onFailure(ex);
                return;
            } catch (Exception ex) {
                log.error("unexepected Error during PutPipelineRequest", ex);
                listener.onFailure(new ElasticsearchException("Unexpected Error during Pipeline Creation"));
                return;
            }
        } else if (action.equals(GetPipelineAction.NAME)) {
            GetPipelineRequest getPipelineReq = (GetPipelineRequest) request;
            GetPipelineRequest newGetPReq = transformGetPipeline(user, getPipelineReq);
            chain.proceed(task, action, newGetPReq, listener);
            return;
        } else if (action.equals(DeletePipelineAction.NAME)) {
            DeletePipelineRequest delPipelineRequest = (DeletePipelineRequest) request;
            DeletePipelineRequest newDelRequest = transformDelPipeline(user, delPipelineRequest);
            chain.proceed(task, action, newDelRequest, listener);
            return;
        } else if (action.equals(SimulatePipelineAction.NAME)) {
            try {
                SimulatePipelineRequest newSimPReq = transformSimulPipeline(user, (SimulatePipelineRequest) request);
                chain.proceed(task, action, newSimPReq, listener);
                return;
            } catch (ForbiddenException ex) {
                log.error("Forbidden Error during PutPipelineRequest", ex);
                listener.onFailure(ex);
                return;
            } catch (Exception ex) {
                log.error("unexepected Error during PutPipelineRequest", ex);
                listener.onFailure(new ElasticsearchException("Unexpected Error during Pipeline Creation"));
                return;

            }
        } else if (action.equals(IndexAction.NAME)) {
            IndexRequest iReq = (IndexRequest) request;
            final String pipeline = iReq.getPipeline();
            if (pipeline != null && !pipeline.isEmpty() && !iReq.getPipeline().startsWith(user.getName())) {
                iReq.setPipeline(user.getName() + "-" + pipeline);
            }
            chain.proceed(task, action, iReq, listener);
            return;
        }

        //if we don't handle the request at all
        chain.proceed(task, action, request, listener);
    }


    private DeletePipelineRequest transformDelPipeline(final User user, final DeletePipelineRequest request) {
        final String pipelineToDel = request.getId();
        log.debug("Pipeline to Delete is {}", pipelineToDel);
        if (!pipelineToDel.startsWith(user.getName())) {
            request.setId(user.getName() + "-" + pipelineToDel);
        }

        return request;
    }


    private GetPipelineRequest transformGetPipeline(final User user, final GetPipelineRequest request) {

        final String userName = user.getName();
        List<String> pipelineIds = Stream.of(request.getIds()).map(s -> s.startsWith(userName) ? s : userName + "-" + s).collect(Collectors.toList());
        GetPipelineRequest gPipelineReq = new GetPipelineRequest(pipelineIds.toArray(new String[pipelineIds.size()]));

        log.debug("final pipelineIds are {}", pipelineIds);

        return gPipelineReq;
    }


    private PutPipelineRequest transformPutPipeline(final User user, final PutPipelineRequest request) throws Exception {

        final String newId = user.getName() + "-" + request.getId();

        Map<String, Object> pipelineConfig = XContentHelper.convertToMap(request.getSource(), false, request.getXContentType()).v2();
        // find processor config using Pipeline create Code,
        // Change PipelineProcessor config to call a user-prefixed processor
        // Assert Script code does not contain any ctx._index assignement ( creates a Regexp for that)
        List<Map<String, Object>> processorConfigs = ConfigurationUtils.readList(null, null, pipelineConfig, Pipeline.PROCESSORS_KEY);


        pipelineConfig.put(Pipeline.PROCESSORS_KEY, transformProcessorConfigs(processorConfigs, user.getName()));


        List<Map<String, Object>> onFailureProcessorConfigs = ConfigurationUtils.readOptionalList(null, null, pipelineConfig, Pipeline.ON_FAILURE_KEY);
        if (onFailureProcessorConfigs != null) {
            pipelineConfig.put(Pipeline.ON_FAILURE_KEY, transformProcessorConfigs(onFailureProcessorConfigs, user.getName()));
        }
        XContentBuilder builder = JsonXContent.contentBuilder().map(pipelineConfig);

        PutPipelineRequest newPPreq = new PutPipelineRequest(newId, BytesReference.bytes(builder), XContentType.JSON);

        return newPPreq;
    }


    private SimulatePipelineRequest transformSimulPipeline(final User user, final SimulatePipelineRequest request) throws Exception {

        Map<String, Object> simulatePipelineConfig = XContentHelper.convertToMap(request.getSource(), false, request.getXContentType()).v2();

        Map<String, Object> pipelineConfig = (Map<String, Object>) simulatePipelineConfig.get("pipeline");

        // Simulate can simulate existing pipeline without providing a configuration
        if (pipelineConfig != null) {
            List<Map<String, Object>> processorConfigs = ConfigurationUtils.readList(null, null, pipelineConfig, Pipeline.PROCESSORS_KEY);

            pipelineConfig.put(Pipeline.PROCESSORS_KEY, transformProcessorConfigs(processorConfigs, user.getName()));


            List<Map<String, Object>> onFailureProcessorConfigs = ConfigurationUtils.readOptionalList(null, null, pipelineConfig, Pipeline.ON_FAILURE_KEY);
            if (onFailureProcessorConfigs != null) {
                pipelineConfig.put(Pipeline.ON_FAILURE_KEY, transformProcessorConfigs(onFailureProcessorConfigs, user.getName()));
            }
        }
        XContentBuilder builder = JsonXContent.contentBuilder().map(simulatePipelineConfig);

        SimulatePipelineRequest newSimPReq = new SimulatePipelineRequest(BytesReference.bytes(builder), XContentType.JSON);

        // Simulate action can
        if (request.getId() != null) {
            final String newId = user.getName() + "-" + request.getId();
            log.debug("we change old pipeline id {} to  {}", request.getId(), newId);
            newSimPReq.setId(newId);
        }
        return newSimPReq;

    }

    private List<Map<String, Object>> transformProcessorConfigs(List<Map<String, Object>> processorConfigs, String userName) throws ForbiddenException {
        boolean pipelineChanged = false;
        for (Map<String, Object> processorConfig : processorConfigs) {
            for (Map.Entry<String, Object> entry : processorConfig.entrySet()) {
                String type = entry.getKey();
                if ("script".equals(type)) {
                    log.debug("we have a script Processor to analyze");
                    String source = "";
                    if (entry.getValue() instanceof Map) {
                        log.debug("script config is a map ");
                        Map<String, String> configMap = (Map<String, String>) entry.getValue();
                        if (configMap.containsKey("source")) {
                            source = configMap.get("source");
                        } else if (configMap.containsKey("inline")) {
                            source = configMap.get("inline");
                        }
                    } else if (entry.getValue() instanceof String) {
                        log.debug("script config is a plain string");
                        source = (String) entry.getValue();
                    }
                    log.trace("source of script is {}", source);
                    if (source.contains("ctx._index")) {
                        log.warn("the script contains a ctx._index statement");
                        //verify it doesn't match any forbidden Script Pattern
                        for (Pattern pattern : forbiddenScriptPatterns) {
                            if (pattern.matcher(source).find()) {
                                log.warn("this script contains a forbidden Pattern {} : {}", pattern.pattern(), source);
                                //Cancel the request
                                throw new ForbiddenException("The script Processor provided contains a forbidden command");
                            }
                        }
                    }
                } else if ("pipeline".equals(type)) {
                    Map<String, Object> pipelineProcessorConfig = (Map<String, Object>) entry.getValue();
                    String pipelineName = ConfigurationUtils.readStringProperty("pipeline", null, pipelineProcessorConfig, "name");
                    if (!pipelineName.startsWith(userName)) {
                        log.warn("The pipeline used does not start with user, changing it to {}", userName + "-" + pipelineName);
                    }
                    pipelineProcessorConfig.put("name", userName + "-" + pipelineName);
                    pipelineChanged = true;
                }
            }
        }
        return processorConfigs;
    }


}
