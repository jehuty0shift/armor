package com.petalmd.armor.filter;

import com.carrotsearch.hppc.cursors.ObjectObjectCursor;
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
import com.petalmd.armor.filter.lifecycle.LifeCycleMongoCodecProvider;
import com.petalmd.armor.service.ArmorConfigService;
import com.petalmd.armor.service.ArmorService;
import com.petalmd.armor.service.MongoDBService;
import com.petalmd.armor.util.ArmorConstants;
import com.petalmd.armor.util.ConfigConstants;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bson.codecs.configuration.CodecRegistries;
import org.bson.codecs.configuration.CodecRegistry;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.admin.indices.create.CreateIndexAction;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.admin.indices.delete.DeleteIndexAction;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.cluster.metadata.IndexMetaData;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;

import java.util.List;
import java.util.stream.Stream;

/**
 * Created by jehuty0shift on 22/01/2020.
 */
public class IndexLifecycleFilter extends AbstractActionFilter {

    private static final Logger log = LogManager.getLogger(IndexLifecycleFilter.class);

    private boolean enabled;
    private final List<String> settingsAllowed;
    private final MongoCollection<EngineUser> engineUsers;

    public IndexLifecycleFilter(final Settings settings, final AuthenticationBackend authBackend, final Authorizator authorizator, final ClusterService clusterService, final ArmorService armorService, final ArmorConfigService armorConfigService, final AuditListener auditListener, final ThreadPool threadPool, final MongoDBService mongoService) {
        super(settings, authBackend, authorizator, clusterService, armorService, armorConfigService, auditListener, threadPool);
        enabled = settings.getAsBoolean(ConfigConstants.ARMOR_INDEX_LIFECYCLE_ENABLED, false);
        settingsAllowed = settings.getAsList(ConfigConstants.ARMOR_INDEX_LIFECYCLE_ALLOWED_SETTINGS);
        if(enabled) {
            if(!mongoService.getEngineDatabase().isPresent()) {
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
        } else {
            engineUsers = null;
        }
    }


    @Override
    public void applySecure(Task task, String action, ActionRequest request, ActionListener listener, ActionFilterChain chain) {

        log.debug("IndexLifeCycleFilter is {}", enabled);

        if(!enabled || (!action.equals(CreateIndexAction.NAME) && !action.equals(DeleteIndexAction.NAME))) {
            chain.proceed(task,action,request,listener);
        }
        if (engineUsers == null) {
            log.error("impossible to validate users, we will not continue");
            throw new ElasticsearchException("This action cannot be fulffiled, contact the administrator");
        }

        log.debug("action is {}", action);
        ThreadContext threadContext = threadpool.getThreadContext();

        if (action.equals(CreateIndexAction.NAME)) {

            //Check rights In Mongo
            User restUser = threadContext.getTransient(ArmorConstants.ARMOR_AUTHENTICATED_USER);
            EngineUser engineUser = engineUsers.find(Filters.eq("username",restUser.getName())).first();
            if(engineUser == null) {
                log.error("This user has not been found in this cluster {}",restUser.getName());
                throw new ForbiddenException("This action is not authorized for this user");
            }

            if(!engineUser.trusted) {
                log.error("This user {} cannot be trusted for Index creation", engineUser.username);
                throw new PaymentRequiredException("Your current billing status rating is too low");
            }

            //Check User has rights on IndiceName
            CreateIndexRequest cir = (CreateIndexRequest) request;
            String indexName = cir.index();
            log.debug("this trusted user {} will attempt to create index  {}", restUser.getName(), indexName);

            if (!indexName.startsWith(restUser.getName())) {
                log.error("the user {} is not allowed to create a user with this name {}", restUser.getName(), indexName);
                throw new ForbiddenException("The index you want to create must be in the following format {}-i-*",restUser.getName());
            }

            int numberOfShards  = cir.settings().getAsInt("index.number_of_shards",1);
            if (numberOfShards > settings.getAsInt(ConfigConstants.ARMOR_INDEX_LIFECYCLE_MAX_NUM_OF_SHARDS_BY_INDEX,16)) {
                log.error("number of shards asked ({}) for index {} is too high", numberOfShards, indexName);
            }
            //check the max num of shards for this user
            long shards = 0;
            for (ObjectObjectCursor<String, IndexMetaData> cursor :clusterService.state().getMetaData().getIndices()) {
                if(cursor.key.startsWith(restUser.getName())) {
                    shards += cursor.value.getNumberOfShards();
                }
            }

            //Remove not allowed settings
            log.debug("creating index {}", cir.index());

            //Create the index,

            //Install the Listener,
            //Listener (should validate by putting a message in Kafka, if failed, rollback (delete the index) and respond 5XX


            //Proceed

        }

    }
}
