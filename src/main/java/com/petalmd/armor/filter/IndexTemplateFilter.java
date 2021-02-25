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
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.admin.indices.template.delete.DeleteIndexTemplateAction;
import org.elasticsearch.action.admin.indices.template.delete.DeleteIndexTemplateRequest;
import org.elasticsearch.action.admin.indices.template.get.GetIndexTemplatesAction;
import org.elasticsearch.action.admin.indices.template.get.GetIndexTemplatesRequest;
import org.elasticsearch.action.admin.indices.template.get.GetIndexTemplatesResponse;
import org.elasticsearch.action.admin.indices.template.put.PutIndexTemplateAction;
import org.elasticsearch.action.admin.indices.template.put.PutIndexTemplateRequest;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.action.support.master.AcknowledgedResponse;
import org.elasticsearch.client.Response;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Created by jehuty0shift on 21/02/2020.
 */
public class IndexTemplateFilter extends AbstractActionFilter {

    private static final Logger log = LogManager.getLogger(IndexTemplateFilter.class);
    private final boolean enabled;
    private final List<String> allowedSettings;
    private final Optional<String> ldpIndex;
    private static final int MAX_NUM_FIELDS = 5000;
    private static final int MAX_NUM_SHARDS = 16;

    public IndexTemplateFilter(final Settings settings, final ClusterService clusterService, final ArmorService armorService, final ArmorConfigService armorConfigService, final ThreadPool threadPool) {
        super(settings, armorService.getAuthenticationBackend(), armorService.getAuthorizator(), clusterService, armorService, armorConfigService, armorService.getAuditListener(), threadPool);
        this.enabled = settings.getAsBoolean(ConfigConstants.ARMOR_INDEX_TEMPLATE_FILTER_ENABLED, true);
        this.allowedSettings = settings.getAsList(ConfigConstants.ARMOR_INDEX_TEMPLATE_FILTER_ALLOWED_SETTINGS,
                Arrays.asList("index.number_of_shards",
                        "index.query",
                        "index.mapping.total_fields.limit",
                        "index.refresh_interval"));
        this.ldpIndex = Optional.ofNullable(settings.get(ConfigConstants.ARMOR_LDP_INDEX));
        log.info("IndexTemplateFilter is {}", enabled ? "enabled" : "disabled");
    }

    @Override
    public int order() {
        return Integer.MIN_VALUE + 13;
    }

    @Override
    public void applySecure(Task task, String action, ActionRequest request, ActionListener listener, ActionFilterChain chain) {
        if (!enabled ||
                (!action.equals(PutIndexTemplateAction.NAME) &&
                        !action.equals(DeleteIndexTemplateAction.NAME) &&
                        !action.equals(GetIndexTemplatesAction.NAME))) {
            chain.proceed(task, action, request, listener);
            return;
        }

        final ThreadContext threadContext = threadpool.getThreadContext();

        final User user = threadContext.getTransient(ArmorConstants.ARMOR_AUTHENTICATED_USER);

        if (action.equals(PutIndexTemplateAction.NAME)) {
            final PutIndexTemplateRequest putITReq = (PutIndexTemplateRequest) request;

            //check if template is on ldp index
            if (ldpIndex.isPresent()) {
                if (putITReq.indices().length == 1) {
                    final String indexName = putITReq.indices()[0];
                    if (indexName.equals(ldpIndex.get())) {
                        log.debug("template is on ldp index, not doing anything");
                        listener.onResponse(new AcknowledgedResponse(true));
                        return;
                    }
                }
            }

            //check template name
            if (!putITReq.name().contains(user.getName())) {
                // Auto prefix it with User Name
                final String prefixedName = user.getName() + "-" + putITReq.name();
                putITReq.name(prefixedName);
                log.info("PutIndexTemplateRequest of user {} has non prefixed name {}, internal name will be {}", user.getName(), putITReq.name(), prefixedName);
            }

            //check index names
            if (Stream.of(putITReq.indices()).anyMatch(iName -> !iName.startsWith(user.getName() + "-i-"))) {
                log.error("PutIndexTemplateRequest of user {} has invalid index names {}", user.getName(), putITReq.indices());
                listener.onFailure(new ForbiddenException("The template MUST only contain index names starting with " + user.getName() + "-i-"));
                return;
            }

            //check aliasesName
            if (putITReq.aliases().stream().anyMatch(aName -> !aName.name().startsWith(user.getName() + "-a-"))) {
                log.error("PutIndexTemplateRequest of user {} has invalid aliases names {}", user.getName(), putITReq.aliases());
                listener.onFailure(new ForbiddenException("The aliases in template MUST start with " + user.getName() + "-a-"));
                return;
            }

            //settings aliases
            Settings.Builder newSettingsBuilder = Settings.builder();
            Settings templateSettings = putITReq.settings();

            for (String prefix : allowedSettings) {
                log.debug("checking prefix {} in PutIndexTemplateRequest", prefix);
                final Settings filteredSetting = templateSettings.filter(k -> k.startsWith(prefix));
                if (!filteredSetting.isEmpty()) {
                    log.debug("keeping setting {}", filteredSetting.toString());
                    newSettingsBuilder.put(filteredSetting);
                    //Check index.mapping.total_fields.limit
                    int numFields = filteredSetting.getAsInt("index.mapping.total_fields.limit", MAX_NUM_FIELDS);
                    if (numFields > MAX_NUM_FIELDS) {
                        newSettingsBuilder.put("index.mapping.total_fields.limit", MAX_NUM_FIELDS);
                    }
                    int numShards = filteredSetting.getAsInt("index.number_of_shards", MAX_NUM_SHARDS);
                    if(numShards > MAX_NUM_SHARDS) {
                        newSettingsBuilder.put("index.number_of_shards", MAX_NUM_SHARDS);
                    }
                }
            }

            putITReq.settings(newSettingsBuilder);

        } else if (action.equals(GetIndexTemplatesAction.NAME)) {
            final GetIndexTemplatesRequest gITReq = (GetIndexTemplatesRequest) request;

            List<String> newNamesLst = Stream.of(gITReq.names()).map(tName -> {
                if (!tName.contains(user.getName())) {
                    return user.getName() + "-" + tName;
                } else {
                    return tName;
                }
            }).collect(Collectors.toList());

            if(newNamesLst.size() == 0) {
                newNamesLst.add("*"+user.getName()+"*");
            }

            gITReq.names(newNamesLst.toArray(new String[newNamesLst.size()]));

        } else if (action.equals(DeleteIndexTemplateAction.NAME)) {
            final DeleteIndexTemplateRequest dITReq = (DeleteIndexTemplateRequest) request;
            if (!dITReq.name().contains(user.getName())) {
                //Auto prefix it
                dITReq.name(user.getName() +"-"+ dITReq.name());
            }
        }

        chain.proceed(task, action, request, listener);
    }
}
