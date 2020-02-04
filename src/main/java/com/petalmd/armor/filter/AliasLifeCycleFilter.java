package com.petalmd.armor.filter;

import com.petalmd.armor.service.ArmorConfigService;
import com.petalmd.armor.service.ArmorService;
import com.petalmd.armor.service.KafkaService;
import com.petalmd.armor.service.MongoDBService;
import com.petalmd.armor.util.ConfigConstants;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;

/**
 * Created by jehuty0shift on 04/02/2020.
 */
public class AliasLifeCycleFilter extends AbstractActionFilter {

    private static final Logger log = LogManager.getLogger(AliasLifeCycleFilter.class);

    private boolean enabled;

    public AliasLifeCycleFilter(final Settings settings, final ClusterService clusterService, final ArmorService armorService, final ArmorConfigService armorConfigService, final ThreadPool threadPool, final MongoDBService mongoService, final KafkaService kafkaService) {
        super(settings, armorService.getAuthenticationBackend(), armorService.getAuthorizator(), clusterService, armorService, armorConfigService, armorService.getAuditListener(), threadPool);
        this.enabled = settings.getAsBoolean(ConfigConstants.ARMOR_ALIAS_LIFECYCLE_ENABLED, false);
        if (enabled) {

        }

    }



    @Override
    public int order() {
        return Integer.MIN_VALUE + 11;
    }

    @Override
    public void applySecure(Task task, String action, ActionRequest request, ActionListener listener, ActionFilterChain chain) {

    }
}
