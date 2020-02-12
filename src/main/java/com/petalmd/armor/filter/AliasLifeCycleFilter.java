package com.petalmd.armor.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mongodb.MongoClient;
import com.mongodb.ReadPreference;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Filters;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authorization.ForbiddenException;
import com.petalmd.armor.filter.lifecycle.AliasOperation;
import com.petalmd.armor.filter.lifecycle.EngineUser;
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
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesAction;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.metadata.AliasOrIndex;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;

import java.util.*;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Created by jehuty0shift on 04/02/2020.
 */
public class AliasLifeCycleFilter extends AbstractActionFilter {

    private static final Logger log = LogManager.getLogger(AliasLifeCycleFilter.class);

    private boolean enabled;
    private final MongoCollection<EngineUser> engineUsers;
    private KafkaService kService;
    private ObjectMapper mapper;


    public AliasLifeCycleFilter(final Settings settings, final ClusterService clusterService, final ArmorService armorService, final ArmorConfigService armorConfigService, final ThreadPool threadPool, final MongoDBService mongoService, final KafkaService kafkaService) {
        super(settings, armorService.getAuthenticationBackend(), armorService.getAuthorizator(), clusterService, armorService, armorConfigService, armorService.getAuditListener(), threadPool);
        this.enabled = settings.getAsBoolean(ConfigConstants.ARMOR_ALIAS_LIFECYCLE_ENABLED, false);
        if (enabled) {
            if (!mongoService.getEngineDatabase().isPresent()) {
                log.error("IndexLifeCycled need a working engine Mongo DB Database ! Disabling the filter !");
                engineUsers = null;
                enabled = false;
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
            kService = null;
            engineUsers = null;
            mapper = null;
        }
        log.info("AliasLifeCycleFilter is {}", enabled ? "enabled" : "disabled");
    }


    @Override
    public int order() {
        return Integer.MIN_VALUE + 11;
    }

    @Override
    public void applySecure(Task task, String action, ActionRequest request, ActionListener listener, ActionFilterChain chain) {

        if (!enabled || (!action.equals(IndicesAliasesAction.NAME))) {
            chain.proceed(task, action, request, listener);
            return;
        }

        IndicesAliasesRequest aliasRequest = (IndicesAliasesRequest) request;

        List<IndicesAliasesRequest.AliasActions> aliasActions = aliasRequest.getAliasActions();

        ThreadContext threadContext = threadpool.getThreadContext();
        User restUser = threadContext.getTransient(ArmorConstants.ARMOR_AUTHENTICATED_USER);

        log.info("user {} is requesting {} alias actions", restUser.getName(), aliasActions.size());

        Set<String> newAliases = new HashSet<>();

        final String aliasPrefix = restUser.getName() + "-a-";

        for (IndicesAliasesRequest.AliasActions aliasAction : aliasActions) {

            List<String> actionsAliasesList = Arrays.asList(aliasAction.aliases());

            if (aliasAction.actionType().equals(IndicesAliasesRequest.AliasActions.Type.ADD)) {
                //check that number of indices linked to an alias is not too high
                int numberOfIndicesForAction = settings.getAsInt(ConfigConstants.ARMOR_ALIAS_LIFECYCLE_MAX_NUM_OF_INDICES_BY_ALIAS, 1000);
                if (aliasAction.indices().length > numberOfIndicesForAction) {
                    log.error("trying to create an alias over {} indices. this is not allowed", numberOfIndicesForAction);
                    listener.onFailure(new ForbiddenException("Alias {} span over {} indices, this is not allowed", actionsAliasesList.get(0), numberOfIndicesForAction));
                    return;
                }

                newAliases.add(actionsAliasesList.get(0));
            } else if (aliasAction.actionType().equals(IndicesAliasesRequest.AliasActions.Type.REMOVE)) {
                newAliases.removeAll(actionsAliasesList);
                List<String> removedAliasesList = actionsAliasesList;
                if (removedAliasesList.contains("*") || removedAliasesList.contains("_all")) {
                    aliasAction.alias(restUser.getName() + "-a-*");
                    actionsAliasesList = Arrays.asList(aliasAction.aliases());
                }
            }

            Optional<String> forbiddenAliasName = actionsAliasesList.stream().filter(s -> !s.startsWith(aliasPrefix)).findAny();
            if (forbiddenAliasName.isPresent()) {
                log.warn("user {} tries to create an alias {}, this is not allowed.", restUser.getName(), forbiddenAliasName);
                listener.onFailure(new ForbiddenException("Alias names MUST start with " + aliasPrefix));
                return;
            }
            log.debug("aliases are {}", actionsAliasesList);
            Optional<String> forbiddenIndexName = Stream.of(aliasAction.indices()).filter(s -> !s.startsWith(restUser.getName() + "-i-")).findAny();
            if (forbiddenIndexName.isPresent()) {
                log.warn("user {} tries to create an alias on index {}, this is not allowed.");
                listener.onFailure(new ForbiddenException("Index Names in a alias action MUST start with " + restUser.getName() + "-i-"));
                return;
            }

            log.debug("indices are {}", Arrays.asList(aliasAction.indices()));
        }

        log.debug("we will create {} new aliases", newAliases.size());
        //check if number of aliases are not too high
        int maxNumberOfAliasAllowed = settings.getAsInt(ConfigConstants.ARMOR_ALIAS_LIFECYCLE_MAX_NUM_OF_ALIAS_BY_USER, 1000);
        long numberOfAliases = clusterService.state().getMetaData().getAliasAndIndexLookup().tailMap(aliasPrefix).entrySet()
                .stream().filter(entry -> entry.getValue().isAlias() && entry.getKey().startsWith(aliasPrefix)).count();

        if (numberOfAliases + newAliases.size() > maxNumberOfAliasAllowed) {
            log.error("the user {} is trying to create {} new aliases, this will exceed the maximum of {} aliases per user", restUser.getName(), newAliases.size(), maxNumberOfAliasAllowed);
            listener.onFailure(new ForbiddenException("the number of alias will exceed the maximum allowed for one user : {}", maxNumberOfAliasAllowed));
            return;
        }

        log.info("will allows {} actions for user {}", aliasActions.size(), restUser.getName());
        EngineUser engineUser = engineUsers.find(Filters.eq("username", restUser.getName())).first();

        if (engineUser == null) {
            log.error("EngineUser for user {} is null, aborting the aliasAction request.", restUser.getName());
            listener.onFailure(new ElasticsearchException("Impossible to complete this action right now"));
            return;
        }

        log.info("will proceed with {} alias actions for user {}", aliasActions.size(), engineUser.getUsername());

        chain.proceed(task, action, request, new AliasLifeCycleListener(aliasActions, engineUser, kService, listener, mapper, clusterService));

    }


    private static class AliasLifeCycleListener<Response extends ActionResponse> implements ActionListener<Response> {

        private static final Logger log = LogManager.getLogger(AliasLifeCycleListener.class);
        private final Set<String> resolvedAliases;
        private final EngineUser engineUser;
        private final KafkaService kService;
        private final ActionListener origListener;
        private final ObjectMapper mapper;
        private final ClusterService clusterService;

        public AliasLifeCycleListener(final List<IndicesAliasesRequest.AliasActions> aliasActions, final EngineUser engineUser, final KafkaService kafkaService, final ActionListener origListener, final ObjectMapper mapper, final ClusterService clusterService) {
            this.engineUser = engineUser;
            this.kService = kafkaService;
            this.origListener = origListener;
            this.mapper = mapper;
            this.clusterService = clusterService;
            IndexNameExpressionResolver resolver = new IndexNameExpressionResolver(Settings.EMPTY);
            final ClusterState clusterState = clusterService.state();
            Set<String> aliasInActions = aliasActions.stream().flatMap(a -> Arrays.stream(a.aliases())).collect(Collectors.toSet());
            // If reqAlias contains a '*' (star) the name have to be resolved before we can continue.
            // If it is not resolved, the expression will be kept but the ES API will naturally reject it when executing the action.
            this.resolvedAliases = resolver.resolveExpressions(clusterState, aliasInActions.toArray(String[]::new));
        }


        @Override
        public void onResponse(Response response) {
            SortedMap<String, AliasOrIndex> aliasMetadata = clusterService.state().getMetaData().getAliasAndIndexLookup();
            List<AliasOperation> aliasOperations = new ArrayList<>();
            for (String reqAlias : resolvedAliases) {
                if (aliasMetadata.containsKey(reqAlias)) {
                    final AliasOrIndex aliasOrIndex = aliasMetadata.get(reqAlias);
                    List<String> indices = aliasOrIndex.getIndices().stream().map(im -> im.getIndex().getName()).collect(Collectors.toList());
                    AliasOperation addOperation = new AliasOperation(engineUser.getUsername(), reqAlias, AliasOperation.Type.ADD, indices);
                    aliasOperations.add(addOperation);
                } else {
                    //the alias was resolved but it is not here anymore, so we delete it.
                    AliasOperation removeOperation = new AliasOperation(engineUser.getUsername(), reqAlias, AliasOperation.Type.REMOVE, List.of());
                    aliasOperations.add(removeOperation);
                }
            }
            log.debug("we will report {} aliasActions to Engine for user {}", resolvedAliases.size(), engineUser.getUsername());

            if (!kService.getKafkaProducer().isPresent()) {
                origListener.onFailure(new ElasticsearchException("Unexpected error on this operation"));
                log.error("Unexpected error", new IllegalStateException("Kafka Producer is not available"));
                return;
            }

            Producer<String, String> kProducer = (Producer<String, String>) kService.getKafkaProducer().get();
            final String topic = kService.getTopicPrefix() + engineUser.getRegion() + "armor";

            try {
                for (AliasOperation aliasOp : aliasOperations) {
                    String aliasOpString = mapper.writeValueAsString(aliasOp);
                    Future<RecordMetadata> report = kProducer.send(new ProducerRecord<>(topic, engineUser.getUsername(), aliasOpString));
                    RecordMetadata rMetadata = report.get(10, TimeUnit.SECONDS);
                    log.info("index action {} has been successfully reported with index offset {}", aliasOp.getType(), rMetadata.offset());
                }
                origListener.onResponse(response);

            } catch (final Exception ex) {
                log.error("Unexpected Exception during report", ex);
                origListener.onFailure(new ElasticsearchException("Unknown error during alias operations"));
            }
        }

        @Override
        public void onFailure(Exception e) {
            origListener.onFailure(e);
        }
    }


}
