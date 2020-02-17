package com.petalmd.armor.filter;

import com.carrotsearch.hppc.cursors.ObjectObjectCursor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mongodb.MongoClient;
import com.mongodb.ReadPreference;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Filters;
import com.petalmd.armor.authentication.User;
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
import org.elasticsearch.action.IndicesRequest;
import org.elasticsearch.action.admin.indices.create.CreateIndexAction;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.admin.indices.delete.DeleteIndexAction;
import org.elasticsearch.action.admin.indices.delete.DeleteIndexRequest;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.cluster.metadata.IndexMetaData;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

/**
 * Created by jehuty0shift on 22/01/2020.
 */
public class IndexLifecycleFilter extends AbstractActionFilter {

    private static final Logger log = LogManager.getLogger(IndexLifecycleFilter.class);

    private boolean enabled;
    private final List<String> allowedIndexSettings;
    private final MongoCollection<EngineUser> engineUsers;
    private KafkaService kService;
    private ObjectMapper mapper;

    public IndexLifecycleFilter(final Settings settings, final ClusterService clusterService, final ArmorService armorService, final ArmorConfigService armorConfigService, final ThreadPool threadPool, final MongoDBService mongoService, final KafkaService kafkaService) {
        super(settings, armorService.getAuthenticationBackend(), armorService.getAuthorizator(), clusterService, armorService, armorConfigService, armorService.getAuditListener(), threadPool);
        enabled = settings.getAsBoolean(ConfigConstants.ARMOR_INDEX_LIFECYCLE_ENABLED, false);
        allowedIndexSettings = settings.getAsList(ConfigConstants.ARMOR_INDEX_LIFECYCLE_ALLOWED_SETTINGS);
        if (enabled) {
            if (!mongoService.getEngineDatabase().isPresent()) {
                log.error("IndexLifeCycled need a working engine Mongo DB Database ! Disabling the filter !");
                engineUsers = null;
            } else {
                CodecRegistry cRegistry = CodecRegistries.fromRegistries(CodecRegistries.fromProviders(new LifeCycleMongoCodecProvider()), MongoClient.getDefaultCodecRegistry());
                engineUsers = mongoService.getEngineDatabase().get().getCollection("users")
                        .withCodecRegistry(cRegistry)
                        .withDocumentClass(EngineUser.class);
                log.info("connected to Users Database");
            }
            kService = kafkaService;
            mapper = new ObjectMapper();
        } else {
            engineUsers = null;
            kService = null;
        }
        log.info("IndexLifeCycleFilter is {}", enabled ? "enabled" : "disabled");
    }

    @Override
    public int order() {
        return Integer.MIN_VALUE + 10;
    }

    @Override
    public void applySecure(Task task, String action, ActionRequest request, ActionListener listener, ActionFilterChain chain) {

        log.debug("IndexLifeCycleFilter is {}", enabled);

        if (!enabled || (!action.equals(CreateIndexAction.NAME) && !action.equals(DeleteIndexAction.NAME))) {
            log.trace("not enabled or not an index creation/deletion action, skipping filter");
            chain.proceed(task, action, request, listener);
            return;
        }
        if (engineUsers == null) {
            log.error("impossible to validate users, we will not continue");
            throw new ElasticsearchException("This action cannot be fulfilled, contact the administrator");
        }

        if (kService == null) {
            log.error("impossible to report indices operation, we will not continue");
            throw new ElasticsearchException("This action cannot be fulfilled, contact the administrator");
        }

        log.debug("action is {}", action);
        ThreadContext threadContext = threadpool.getThreadContext();

        //Check rights In Mongo
        User restUser = threadContext.getTransient(ArmorConstants.ARMOR_AUTHENTICATED_USER);
        EngineUser engineUser = engineUsers.find(Filters.eq("username", restUser.getName())).first();
        if (engineUser == null) {
            log.error("This user has not been found in this cluster {}", restUser.getName());
            throw new ForbiddenException("This action is not authorized for this user");
        }

        List<String> indices = Arrays.asList(((IndicesRequest) request).indices());
        Settings indexSettings = Settings.EMPTY;

        if (action.equals(CreateIndexAction.NAME)) {

            if (!engineUser.isTrusted()) {
                log.error("This user {} cannot be trusted for Index creation", engineUser.getUsername());
                listener.onFailure(new PaymentRequiredException("Your current billing status rating is too low"));
                return;
            }

            //Check User has rights on IndiceName
            CreateIndexRequest cir = (CreateIndexRequest) request;
            String indexName = indices.get(0);
            Settings cirSettings = cir.settings();
            log.debug("this trusted user {} will attempt to create index  {}", restUser.getName(), indexName);

            if (!indexName.startsWith(restUser.getName())) {
                log.error("the user {} is not allowed to create a user with this name {}", restUser.getName(), indexName);
                listener.onFailure(new ForbiddenException("The index you want to create must be in the following format {}-i-*", restUser.getName()));
                return;
            }

            int numberOfShards = cirSettings.getAsInt("index.number_of_shards", 1);
            if (numberOfShards > settings.getAsInt(ConfigConstants.ARMOR_INDEX_LIFECYCLE_MAX_NUM_OF_SHARDS_BY_INDEX, 16)) {
                log.error("number of shards asked ({}) for index {} is too high", numberOfShards, indexName);
                listener.onFailure(new ForbiddenException("number of shards asked ({}) for index {} is too high", numberOfShards, indexName));
                return;
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
                listener.onFailure(new ForbiddenException("this index {} with {} shards will exceed the number of shards allowed by user", indexName, numberOfShards));
                return;
            }

            //Remove not allowed settings
            log.debug("creating index {}", cir.index());
            Settings.Builder newSettingsBuilder = Settings.builder();
            for (String prefix : allowedIndexSettings) {
                log.debug("checking prefix {} in UpdateSettingsRequest", prefix);
                Settings allowedSetting = cirSettings.filter((k) -> (k.startsWith(prefix)));
                if (!allowedSetting.isEmpty()) {
                    log.debug("{} is not empty, keeping setting");
                    newSettingsBuilder.put(allowedSetting);
                }
            }

            newSettingsBuilder.put("index.number_of_replicas", 1);
            newSettingsBuilder.put("index.number_of_shards", numberOfShards);
            cir.settings(newSettingsBuilder.build());

            indexSettings = newSettingsBuilder.build();


        } else if (action.equals(DeleteIndexAction.NAME)) {

            DeleteIndexRequest dir = (DeleteIndexRequest) request;

            //validate names
            Optional<String> isForbidden = Stream.of(dir.indices()).filter(k -> !k.startsWith(engineUser.getUsername())).findAny();
            if (isForbidden.isPresent()) {
                listener.onFailure(new ForbiddenException("You have no right to delete index {}", isForbidden.get()));
                return;
            }
            //we need concrete names
            Optional<String> isNotConcrete = Stream.of(dir.indices()).filter(k -> k.contains("*") || k.equals("_all")).findAny();
            if (isNotConcrete.isPresent()) {
                listener.onFailure(new ForbiddenException("All indices names must be fully indicated: {} is not allowed", isNotConcrete.get()));
                return;
            }

        }

        //Install the Listener,
        //Listener (should validate by putting a message in Kafka, if failed, rollback (delete the index) and respond 5XX
        final IndexLifeCycleListener indexLifeCycleListener = new IndexLifeCycleListener(action, indices, indexSettings, engineUser, kService, listener, mapper);

        //Proceed
        chain.proceed(task, action, request, indexLifeCycleListener);
        return;

    }


    private static class IndexLifeCycleListener<Response extends ActionResponse> implements ActionListener<Response> {

        private String action;
        private List<String> indices;
        private Settings indexSettings;
        private EngineUser engineUser;
        private ObjectMapper mapper;
        private ActionListener origListener;
        private KafkaService kService;

        public IndexLifeCycleListener(String action, List<String> indices, final Settings indexSettings, final EngineUser engineUser, final KafkaService kafkaService, final ActionListener origListener, final ObjectMapper mapper) {
            this.action = action;
            this.indices = indices;
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
                IndexOperation.Type type = action.equals(CreateIndexAction.NAME) ? IndexOperation.Type.CREATE : IndexOperation.Type.DELETE;
                //report creation.
                int numberOfShards = indexSettings.getAsInt("index.number_of_shards", -1);
                if (type.equals(IndexOperation.Type.CREATE) && numberOfShards < 1) {
                    throw new ElasticsearchException("Illegal number of shards during index creation");
                }
                IndexOperation indexOp = new IndexOperation(type, engineUser.getUsername(), indices, numberOfShards);
                String indexOpString = mapper.writeValueAsString(indexOp);

                log.info("reporting index action {} on index {}, from user {}, with number Of Shards {}", type, indices, engineUser.getUsername(), numberOfShards);
                if (!kService.getKafkaProducer().isPresent()) {
                    throw new IllegalStateException("Kafka Producer is not available");
                }

                Producer<String, String> kProducer = (Producer<String, String>) kService.getKafkaProducer().get();
                Future<RecordMetadata> report = kProducer.send(new ProducerRecord<>(topic, engineUser.getUsername(), indexOpString));
                RecordMetadata rMetadata = report.get(10, TimeUnit.SECONDS);

                log.info("index action {} has been successfully reported with index offset {}", type, rMetadata.offset());
                origListener.onResponse(response);

            } catch (Exception ex) {
                log.error("We couldn't report the action {} on indices {} from user {}, Check if everything is Okay", action, indices, engineUser.getUsername(), ex);
                origListener.onFailure(new ElasticsearchException("We couldn't create the index"));
            }
        }

        @Override
        public void onFailure(Exception e) {
            origListener.onFailure(e);
        }
    }
}
