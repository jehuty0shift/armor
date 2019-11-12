package com.petalmd.armor.filter.kefla;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.petalmd.armor.util.ConfigConstants;
import kong.unirest.*;
import kong.unirest.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.cluster.metadata.IndexMetaData;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.component.AbstractLifecycleComponent;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.EsExecutors;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * Created by jehuty0shift on 22/10/19.
 */
public class KeflaEngine extends AbstractLifecycleComponent {

    private static final Logger log = LogManager.getLogger(KeflaEngine.class);
    private final ScheduledThreadPoolExecutor scheduler;
    private final Settings settings;
    private final String graylogEndpoint;
    private final String graylogUser;
    private final String graylogPassword;
    private final Map<String, Map<String, Map<String, KeflaRestType>>> streamIndicesFieldMap;
    private final ClusterService clusterService;
    private String currentDefaultIndex;



    public KeflaEngine(final Settings settings, final ClusterService clusterService) {
        super();
        this.settings = settings;
        scheduler = (ScheduledThreadPoolExecutor) Executors.newScheduledThreadPool(1, EsExecutors.daemonThreadFactory(settings, "kefla_engine"));
        graylogEndpoint = settings.get(ConfigConstants.ARMOR_KEFLA_PLUGIN_ENDPOINT, "");
        graylogUser = settings.get(ConfigConstants.ARMOR_KEFLA_PLUGIN_USER, "");
        graylogPassword = settings.get(ConfigConstants.ARMOR_KEFLA_PLUGIN_PASSWORD, "");
        streamIndicesFieldMap = new ConcurrentHashMap<>();
        this.clusterService = clusterService;
        currentDefaultIndex = "graylog2_1";
    }

    @Override
    protected void doStart() {
        //start scheduler
        if (settings.getAsBoolean(ConfigConstants.ARMOR_KEFLA_FILTER_ENABLED, false)) {
            //first Update
            scheduler.scheduleAtFixedRate(this::updateEngine,1,10, TimeUnit.SECONDS);
            Unirest.config().setObjectMapper(new JacksonObjectMapper());
            log.info("Kefla Engine started");
        }
    }

    public Map<String, Map<String, Map<String, KeflaRestType>>> getFieldsForStream(Collection<String> streamIds) {
        Map<String, Map<String, Map<String, KeflaRestType>>> strIndicesFieldResp = new HashMap<>();
        List<String> streamIdsToRetrieve = new ArrayList<>();
        for (String streamId : streamIds) {
            if (streamIndicesFieldMap.containsKey(streamId)) {
                strIndicesFieldResp.put(streamId, streamIndicesFieldMap.get(streamId));
            } else {
                streamIdsToRetrieve.add(streamId);
            }
        }
        if (!streamIdsToRetrieve.isEmpty()) {
            retrieveFieldsFromStream(streamIdsToRetrieve);
        }
        //fill unknown streams with default fields.
        for(String streamId : streamIdsToRetrieve) {
            if(streamIndicesFieldMap.containsKey(streamId)) {
                strIndicesFieldResp.put(streamId, streamIndicesFieldMap.get(streamId));
            } else {
                strIndicesFieldResp.put(streamId, KeflaUtils.buildDefaultMapping(currentDefaultIndex));
            }
        }
        return strIndicesFieldResp;
    }


    private void retrieveFieldsFromStream(List<String> strIdsToRet) {
        HttpRequestWithBody httpReq = Unirest.post(graylogEndpoint + "/api/plugins/com.ovh.graylog/mapping/fields");
        FieldsRequest fReq = new FieldsRequest();
        fReq.streams = strIdsToRet;
        try {
            log.debug("retrieving fields for {}", strIdsToRet);
            HttpResponse<JsonNode> response = httpReq.basicAuth(graylogUser, graylogPassword).body(fReq).asJson();
            JSONObject jsonObj = response.getBody().getObject();
            Map<String, Map<String, Map<String, KeflaRestType>>> newStrIndFieldMap = KeflaUtils.strFieldMapFromJsonObject(jsonObj);
            log.debug("we extracted {} new streams",newStrIndFieldMap.size());
            log.trace("here are the new fields {}",newStrIndFieldMap);
            streamIndicesFieldMap.putAll(newStrIndFieldMap);
        } catch (UnirestException ex) {
            log.error("couldn't retrieve stream fields for streams {}", strIdsToRet,ex);
        }
    }

    private void updateEngine() {
        //first update the default index
        String[] defaultSplit = currentDefaultIndex.split("_");
        int max = Integer.parseInt(defaultSplit[defaultSplit.length -1]);
        String indexMax = currentDefaultIndex;
        for (IndexMetaData iMetadata : clusterService.state().metaData()) {
            if(iMetadata.getIndex().getName().startsWith("graylog2_")){
                String indexName = iMetadata.getIndex().getName();
                if(Integer.parseInt(currentDefaultIndex.substring(9)) > max) {
                    indexMax = indexName;
                }
            }
        }
        log.debug("found the new currentDefaultIndex {}", indexMax);
        currentDefaultIndex = indexMax;

        //update the streamIndicesFieldMap
        List<String> streamToUpdates = new ArrayList<>(streamIndicesFieldMap.keySet());
        retrieveFieldsFromStream(streamToUpdates);

    }


    @Override
    protected void doStop() {
        //stop scheduler
        scheduler.shutdown();
    }

    @Override
    protected void doClose() throws IOException {
        //force scheduler to stop
        scheduler.shutdownNow();
    }

    private class FieldsRequest {

        @JsonProperty
        public List<String> streams;

    }


}
