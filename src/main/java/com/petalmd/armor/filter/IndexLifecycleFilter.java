package com.petalmd.armor.filter;

import com.carrotsearch.hppc.cursors.ObjectObjectCursor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mongodb.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Filters;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authorization.ForbiddenException;
import com.petalmd.armor.authorization.PaymentRequiredException;
import com.petalmd.armor.filter.lifecycle.AliasOperation;
import com.petalmd.armor.filter.lifecycle.EngineUser;
import com.petalmd.armor.filter.lifecycle.IndexOperation;
import com.petalmd.armor.filter.lifecycle.LifeCycleMongoCodecProvider;
import com.petalmd.armor.filter.lifecycle.kser.KSerSecuredMessage;
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
import org.elasticsearch.cluster.metadata.AliasMetadata;
import org.elasticsearch.cluster.metadata.IndexAbstraction;
import org.elasticsearch.cluster.metadata.IndexMetadata;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.collect.ImmutableOpenMap;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.*;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
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
                engineUsers = AccessController.doPrivileged((PrivilegedAction<MongoCollection<EngineUser>>) () ->
                        mongoService.getEngineDatabase().get().getCollection("user")
                                .withCodecRegistry(cRegistry)
                                .withDocumentClass(EngineUser.class));
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
        EngineUser engineUser = AccessController.doPrivileged((PrivilegedAction<EngineUser>) () ->
                engineUsers.find(Filters.eq("username", restUser.getName())).first());
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

            int numberOfShards = cirSettings.hasValue("number_of_shards") ?
                    cirSettings.getAsInt("number_of_shards", 1) : cirSettings.getAsInt("index.number_of_shards", 1);
            int maxShardAllowed = settings.getAsInt(ConfigConstants.ARMOR_INDEX_LIFECYCLE_MAX_NUM_OF_SHARDS_BY_INDEX, 16);
            if (numberOfShards > maxShardAllowed) {
                log.error("number of shards asked ({}) for index {} is too high, max allowed is {}", numberOfShards, indexName, maxShardAllowed);
                listener.onFailure(new ForbiddenException("number of shards asked ({}) for index {} is too high", numberOfShards, indexName));
                return;
            }

            int numberOfReplicas = cirSettings.hasValue("number_of_replicas") ?
                    cirSettings.getAsInt("number_of_replicas", 1) : cirSettings.getAsInt("index.number_of_replicas", 1);
            int maxReplicasAllowed = settings.getAsInt(ConfigConstants.ARMOR_INDEX_LIFECYCLE_MAX_NUM_OF_REPLICAS_BY_INDEX, 1);
            if (numberOfReplicas > maxReplicasAllowed) {
                log.error("number of replicas asked ({}) for index {} is too high, max allowed is {}", numberOfReplicas, indexName, maxReplicasAllowed);
                listener.onFailure(new ForbiddenException("number of replicas asked ({}) for index {} is too high", numberOfReplicas, indexName));
                return;
            }

            //check the max num of shards for this user
            long totalShardsForUser = 0;
            for (ObjectObjectCursor<String, IndexMetadata> cursor : clusterService.state().getMetadata().getIndices()) {
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
                    log.debug("{} is not empty, keeping setting", allowedSetting.toString());
                    newSettingsBuilder.put(allowedSetting);
                }
            }

            newSettingsBuilder.put("index.number_of_replicas", numberOfReplicas);
            newSettingsBuilder.put("index.number_of_shards", numberOfShards);
            cir.settings(newSettingsBuilder.build());

            indexSettings = newSettingsBuilder.build();

            //Handle aliases

            if (cir.aliases().stream().anyMatch(a -> !a.name().startsWith(restUser.getName() + "-a-"))) {
                listener.onFailure(new ForbiddenException("Alias name in create Index MUST start with " + restUser.getName() + "-a-"));
                return;
            }


        } else {

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
        final IndexLifeCycleListener indexLifeCycleListener = new IndexLifeCycleListener(action, indices, clusterService, indexSettings, engineUser, kService, listener, mapper);

        //Proceed
        chain.proceed(task, action, request, indexLifeCycleListener);
    }


    private static class IndexLifeCycleListener<Response extends ActionResponse> implements ActionListener<Response> {

        private final String action;
        private final List<String> indices;
        private final Set<String> oldAliases;
        private final ClusterService clusterService;
        private final Settings indexSettings;
        private final EngineUser engineUser;
        private final ObjectMapper mapper;
        private final ActionListener<Response> origListener;
        private final KafkaService kService;

        public IndexLifeCycleListener(String action, List<String> indices, final ClusterService clusterService, final Settings indexSettings, final EngineUser engineUser, final KafkaService kafkaService, final ActionListener<Response> origListener, final ObjectMapper mapper) {
            this.action = action;
            this.indices = indices;
            this.engineUser = engineUser;
            this.origListener = origListener;
            this.kService = kafkaService;
            this.mapper = mapper;
            this.indexSettings = indexSettings;
            this.clusterService = clusterService;
            final SortedMap<String, IndexAbstraction> aliasIndexLookup = clusterService.state().getMetadata().getIndicesLookup();
            oldAliases = new HashSet<>();
            if (action.equals(DeleteIndexAction.NAME)) {
                // Restrict oldAliases to the indices concerned by the request
                ImmutableOpenMap<String, List<AliasMetadata>> aliasesForIndices = clusterService.state().getMetadata().findAllAliases(indices.toArray(String[]::new));
                aliasesForIndices.forEach(e -> e.value.stream().forEach(aM -> oldAliases.add(aM.alias())));
            } else {
                oldAliases.addAll(clusterService.state().getMetadata().getIndicesLookup().entrySet().stream().filter(e -> e.getKey().startsWith(engineUser.getUsername() + "-a-") && e.getValue().getType().equals(IndexAbstraction.Type.ALIAS)).map(e -> e.getKey()).collect(Collectors.toSet()));
            }
        }

        @Override
        public void onResponse(Response response) {

            try {
                final IndexOperation.Type type = action.equals(CreateIndexAction.NAME) ? IndexOperation.Type.CREATE : IndexOperation.Type.DELETE;
                //report creation.
                int numberOfShards = indexSettings.getAsInt("index.number_of_shards", -1);
                if (type.equals(IndexOperation.Type.CREATE) && numberOfShards < 1) {
                    throw new ElasticsearchException("Illegal number of shards during index creation");
                }
                List<IndexOperation> indexOps = indices.stream().map(i -> new IndexOperation(type, engineUser.getUsername(), i, numberOfShards)).collect(Collectors.toList());
                final List<String> indexOpStrings = indexOps.stream().map(iOp -> {
                            try {
                                return AccessController.doPrivileged((PrivilegedExceptionAction<String>) () ->
                                        mapper.writeValueAsString(iOp.buildKserMessage())
                                );
                            } catch (PrivilegedActionException e) {
                                log.error("Couldn't serialize {} due to {}", iOp.toString(), e);
                                return null;
                            }
                        }
                ).filter(Objects::nonNull).collect(Collectors.toList());

                log.info("reporting index action {} on index {}, from user {}, with number Of Shards {}", type, indices, engineUser.getUsername(), numberOfShards);
                if (kService.getKafkaProducer().isEmpty()) {
                    throw new IllegalStateException("Kafka Producer is not available");
                }
                final Producer<String, String> kProducer = (Producer<String, String>) kService.getKafkaProducer().get();

                //If the operation is CREATE, we report it before reporting the creation of aliases.
                if (type.equals(IndexOperation.Type.CREATE)) {
                    AccessController.doPrivileged((PrivilegedExceptionAction<Void>) () -> {
                        List<Future<RecordMetadata>> reportList = new ArrayList<>(kService.getTopicList().size() * indexOpStrings.size());
                        for (String indexOpString : indexOpStrings) {
                            final KSerSecuredMessage indexOpSecured = kService.buildKserSecuredMessage(indexOpString);
                            final String indexOpSecuredString = mapper.writeValueAsString(indexOpSecured);
                            for (final String topic : kService.getTopicList()) {
                                reportList.add(kProducer.send(new ProducerRecord<>(topic, engineUser.getUsername(), indexOpSecuredString)));
                            }
                        }

                        for (Future<RecordMetadata> report : reportList) {
                            final RecordMetadata indexRecordMetadata = report.get(10, TimeUnit.SECONDS);
                            log.info("index action {} has been successfully reported with index offset {}", type, indexRecordMetadata.offset());
                        }

                        return null;
                    });
                }

                //Check aliases on this index
                final SortedMap<String, IndexAbstraction> aliasAndIndexLookup = clusterService.state().getMetadata().getIndicesLookup();

                final Set<String> aliasesToCheck;
                if (type.equals(IndexOperation.Type.CREATE)) {
                    aliasesToCheck = new HashSet<>();
                    IndexAbstraction aio = aliasAndIndexLookup.get(indices.get(0));
                    ImmutableOpenMap<String, AliasMetadata> iom = aio.getIndices().get(0).getAliases();
                    iom.forEach(aName -> aliasesToCheck.add(aName.key));
                } else {
                    aliasesToCheck = oldAliases;
                }

                if (!aliasesToCheck.isEmpty()) {
                    for (String aliasToCheck : aliasesToCheck) {
                        try {
                            final IndexAbstraction aliasFromMeta = aliasAndIndexLookup.get(aliasToCheck);
                            final List<String> indicesName;
                            final AliasOperation.Type aliasOpType;
                            if (aliasFromMeta != null) {
                                //the alias exist, we must update it
                                indicesName = aliasFromMeta.getIndices().stream().map(im -> im.getIndex().getName()).collect(Collectors.toList());
                                if (oldAliases.contains(aliasToCheck)) {
                                    aliasOpType = AliasOperation.Type.UPDATE;
                                } else {
                                    aliasOpType = AliasOperation.Type.ADD;
                                }
                            } else {
                                //the alias does not exist anymore, we must remove it
                                indicesName = Collections.emptyList();
                                aliasOpType = AliasOperation.Type.REMOVE;
                            }
                            final AliasOperation aliasOp = new AliasOperation(engineUser.getUsername(), aliasToCheck, aliasOpType, indicesName);
                            RecordMetadata rMetadataAlias = AccessController.doPrivileged((PrivilegedExceptionAction<RecordMetadata>) () -> {
                                final String aliasOpString = mapper.writeValueAsString(aliasOp.buildKserMessage());
                                List<Future<RecordMetadata>> reportList = new ArrayList<>();
                                final KSerSecuredMessage aliasOpSecured = kService.buildKserSecuredMessage(aliasOpString);
                                final String aliasOpSecuredString = mapper.writeValueAsString(aliasOpSecured);

                                for (final String topic : kService.getTopicList()) {
                                    reportList.add(kProducer.send(new ProducerRecord<>(topic, engineUser.getUsername(), aliasOpSecuredString)));
                                }
                                for (Future<RecordMetadata> report : reportList) {
                                    report.get(10, TimeUnit.SECONDS);
                                }
                                return reportList.get(0).get();
                            });
                            log.info("alias action {} on alias {} with indices {} has been successfully reported with offset {}", aliasOp.getType(), aliasToCheck, indicesName, rMetadataAlias.offset());
                        } catch (Exception e) {
                            log.error("The alias {} has not been reported successfully !", aliasToCheck);
                        }
                    }
                }

                //If the operation is DELETE we report the delete after having removed the alias
                if (type.equals(IndexOperation.Type.DELETE)) {
                    AccessController.doPrivileged((PrivilegedExceptionAction<Void>) () -> {
                        List<Future<RecordMetadata>> reportList = new ArrayList<>(kService.getTopicList().size() * indexOpStrings.size());
                        for (String indexOpString : indexOpStrings) {
                            final KSerSecuredMessage indexOpSecured = kService.buildKserSecuredMessage(indexOpString);
                            final String indexOpSecuredString = mapper.writeValueAsString(indexOpSecured);
                            for (final String topic : kService.getTopicList()) {
                                reportList.add(kProducer.send(new ProducerRecord<>(topic, engineUser.getUsername(), indexOpSecuredString)));
                            }
                        }

                        for (Future<RecordMetadata> report : reportList) {
                            RecordMetadata indexRecordMetadata = report.get(10, TimeUnit.SECONDS);
                            log.info("index action {} has been successfully reported with index offset {}", type, indexRecordMetadata.offset());
                        }

                        return null;
                    });

                }

                origListener.onResponse(response);

            } catch (PrivilegedActionException ex) {
                log.error("We couldn't report the action {} on indices {} from user {}, Check if everything is Okay", action, indices, engineUser.getUsername(), ex.getException());
                origListener.onFailure(new ElasticsearchException("We couldn't create the index"));
            } catch (RuntimeException ex) {
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
