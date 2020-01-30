package com.petalmd.armor.filter;

import com.carrotsearch.hppc.cursors.ObjectObjectCursor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mongodb.MongoClient;
import com.mongodb.ReadPreference;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Filters;
import com.petalmd.armor.audit.AuditListener;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authentication.backend.AuthenticationBackend;
import com.petalmd.armor.authorization.Authorizator;
import com.petalmd.armor.authorization.ForbiddenException;
import com.petalmd.armor.authorization.PaymentRequiredException;
import com.petalmd.armor.filter.lifecycle.EngineUser;
import com.petalmd.armor.filter.lifecycle.IndexOperation;
import com.petalmd.armor.filter.lifecycle.LifeCycleMongoCodecProvider;
import com.petalmd.armor.service.ArmorConfigService;
import com.petalmd.armor.service.ArmorService;
import com.petalmd.armor.service.KafkaService;
import com.petalmd.armor.service.MongoDBService;
import com.petalmd.armor.util.ArmorConstants;
import com.petalmd.armor.util.ConfigConstants;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.clients.producer.RecordMetadata;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bson.codecs.configuration.CodecRegistries;
import org.bson.codecs.configuration.CodecRegistry;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.admin.indices.create.CreateIndexAction;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.admin.indices.delete.DeleteIndexAction;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.client.Response;
import org.elasticsearch.cluster.metadata.IndexMetaData;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;

import java.util.List;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * Created by jehuty0shift on 22/01/2020.
 */
public class IndexLifecycleFilter extends AbstractActionFilter {

    private static final Logger log = LogManager.getLogger(IndexLifecycleFilter.class);

    private boolean enabled;
    private final List<String> allowedSettings;
    private final MongoCollection<EngineUser> engineUsers;
    private KafkaService kService;
    private ObjectMapper mapper;

    public IndexLifecycleFilter(final Settings settings, final AuthenticationBackend authBackend, final Authorizator authorizator, final ClusterService clusterService, final ArmorService armorService, final ArmorConfigService armorConfigService, final AuditListener auditListener, final ThreadPool threadPool, final MongoDBService mongoService, final KafkaService kafkaService) {
        super(settings, authBackend, authorizator, clusterService, armorService, armorConfigService, auditListener, threadPool);
        enabled = settings.getAsBoolean(ConfigConstants.ARMOR_INDEX_LIFECYCLE_ENABLED, false);
        allowedSettings = settings.getAsList(ConfigConstants.ARMOR_INDEX_LIFECYCLE_ALLOWED_SETTINGS);
        if (enabled) {
            if (!mongoService.getEngineDatabase().isPresent()) {
                log.error("IndexLifeCycled need a working engine Mongo DB Database ! Disabling the filter !");
                engineUsers = null;
            } else {
                CodecRegistry cRegistry = CodecRegistries.fromRegistries(CodecRegistries.fromProviders(new LifeCycleMongoCodecProvider()), MongoClient.getDefaultCodecRegistry());
                engineUsers = mongoService.getEngineDatabase().get().getCollection("users")
                        .withCodecRegistry(cRegistry)
                        .withReadPreference(ReadPreference.primary())
                        .withDocumentClass(EngineUser.class);
                log.info("connected to Users Database");
            }
            kService = kafkaService;
            mapper = new ObjectMapper();
        } else {
            engineUsers = null;
        }

    }


    @Override
    public void applySecure(Task task, String action, ActionRequest request, ActionListener listener, ActionFilterChain chain) {

        log.debug("IndexLifeCycleFilter is {}", enabled);

        if (!enabled || (!action.equals(CreateIndexAction.NAME) && !action.equals(DeleteIndexAction.NAME))) {
            chain.proceed(task, action, request, listener);
            return;
        }
        if (engineUsers == null) {
            log.error("impossible to validate users, we will not continue");
            throw new ElasticsearchException("This action cannot be fulffiled, contact the administrator");
        }

        if (kService == null) {
            log.error("impossible to report indices operation, we will not continue");
            throw new ElasticsearchException("This action cannot be fulffiled, contact the administrator");
        }

        log.debug("action is {}", action);
        ThreadContext threadContext = threadpool.getThreadContext();

        if (action.equals(CreateIndexAction.NAME)) {

            //Check rights In Mongo
            User restUser = threadContext.getTransient(ArmorConstants.ARMOR_AUTHENTICATED_USER);
            EngineUser engineUser = engineUsers.find(Filters.eq("username", restUser.getName())).first();
            if (engineUser == null) {
                log.error("This user has not been found in this cluster {}", restUser.getName());
                throw new ForbiddenException("This action is not authorized for this user");
            }

            if (!engineUser.isTrusted()) {
                log.error("This user {} cannot be trusted for Index creation", engineUser.getUsername());
                throw new PaymentRequiredException("Your current billing status rating is too low");
            }

            //Check User has rights on IndiceName
            CreateIndexRequest cir = (CreateIndexRequest) request;
            String indexName = cir.index();
            Settings cirSettings = cir.settings();
            log.debug("this trusted user {} will attempt to create index  {}", restUser.getName(), indexName);

            if (!indexName.startsWith(restUser.getName())) {
                log.error("the user {} is not allowed to create a user with this name {}", restUser.getName(), indexName);
                throw new ForbiddenException("The index you want to create must be in the following format {}-i-*", restUser.getName());
            }

            int numberOfShards = cirSettings.getAsInt("index.number_of_shards", 1);
            if (numberOfShards > settings.getAsInt(ConfigConstants.ARMOR_INDEX_LIFECYCLE_MAX_NUM_OF_SHARDS_BY_INDEX, 16)) {
                log.error("number of shards asked ({}) for index {} is too high", numberOfShards, indexName);
                throw new ForbiddenException("number of shards asked ({}) for index {} is too high", numberOfShards, indexName);
            }
            //check the max num of shards for this user
            long totalShardsForUser = 0;
            for (ObjectObjectCursor<String, IndexMetaData> cursor : clusterService.state().getMetaData().getIndices()) {
                if (cursor.key.startsWith(restUser.getName())) {
                    totalShardsForUser += cursor.value.getNumberOfShards();
                }
            }

            if (totalShardsForUser + numberOfShards > settings.getAsInt(ConfigConstants.ARMOR_INDEX_LIFECYCLE_MAX_NUM_OF_SHARDS_BY_USER, 1000)) {
                log.error("the number of total shards of the user {} : {} will exceed the maximum number of shards by user with the new index {} of {} shards", restUser.getName(), totalShardsForUser, indexName, numberOfShards);
                throw new ForbiddenException("this index {} with {} shards will exceed the number of shards allowed by user", indexName, numberOfShards);
            }

            //Remove not allowed settings
            log.debug("creating index {}", cir.index());
            Settings.Builder newSettingsBuilder = Settings.builder();
            for (String prefix : allowedSettings) {
                log.debug("checking prefix {} in UpdateSettingsRequest", prefix);
                Settings allowedSetting = cirSettings.filter((k) -> (k.startsWith(prefix)));
                if (!allowedSetting.isEmpty()) {
                    log.debug("{} is not empty, keeping setting");
                    newSettingsBuilder.put(allowedSetting);
                }
            }

            newSettingsBuilder.put("index.number_of_replicas", 1);
            cir.settings(newSettingsBuilder.build());

            //Install the Listener,
            //Listener (should validate by putting a message in Kafka, if failed, rollback (delete the index) and respond 5XX


            //Proceed

        }

    }


    private static class IndexActionListener<Response extends ActionResponse> implements ActionListener<Response> {

        private String action;
        private String indexName;
        private Settings indexSettings;
        private EngineUser engineUser;
        private ObjectMapper mapper;
        private ActionListener origListener;
        private KafkaService kService;

        public IndexActionListener(String action, String indexName, final Settings indexSettings, final EngineUser engineUser, final KafkaService kafkaService, final ActionListener origListener, final ObjectMapper mapper) {
            this.indexName = indexName;
            this.engineUser = engineUser;
            this.origListener = origListener;
            this.kService = kafkaService;
            this.mapper = mapper;
            this.indexSettings = indexSettings;
        }

        @Override
        public void onResponse(Response response) {
            String topic = kService.getTopicPrefix() + "." +
                    engineUser.getRegion().value + "." +
                    "armor";

            try {
                if (action.equals(CreateIndexAction.NAME)) {
                    //report creation.
                    int numberOfShards = indexSettings.getAsInt("index.number_of_shards", 1);
                    IndexOperation indexOp = new IndexOperation(IndexOperation.Type.CREATE, engineUser.getUsername(), indexName, numberOfShards);
                    String indexOpString = mapper.writeValueAsString(indexOp);

                    log.info("reporting index creation {}, from user {}, with number Of Shards {}", indexName, engineUser.getUsername(), numberOfShards);
                    if (!kService.getKafkaProducer().isPresent()) {
                        throw new IllegalStateException("Kafka Producer is not available");
                    }
                    Producer<String, String> kProducer = (Producer<String, String>) kService.getKafkaProducer().get();
                    Future<RecordMetadata> report = kProducer.send(new ProducerRecord<>(topic, engineUser.getUsername(), indexOpString));
                    RecordMetadata rMetadata = report.get(10, TimeUnit.SECONDS);

                    log.info("index creation has been successfully reported with index offset {}", rMetadata.offset());

                } else if (action.equals(DeleteIndexAction.NAME)) {

                }
            } catch (Exception ex) {
                log.error("We couldn't report the action {} on index {} from user {}, Check if everything is Okay", action, indexName, engineUser.getUsername(), ex);
            }

        }

        @Override
        public void onFailure(Exception e) {
            origListener.onFailure(e);
        }
    }
}
