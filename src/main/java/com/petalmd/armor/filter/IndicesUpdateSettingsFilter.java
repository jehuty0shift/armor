package com.petalmd.armor.filter;

import com.google.common.collect.Lists;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.service.ArmorConfigService;
import com.petalmd.armor.service.ArmorService;
import com.petalmd.armor.util.ArmorConstants;
import com.petalmd.armor.util.ConfigConstants;
import com.petalmd.armor.util.SecurityUtil;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionRequestValidationException;
import org.elasticsearch.action.IndicesRequest;
import org.elasticsearch.action.admin.indices.settings.put.UpdateSettingsRequest;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.action.support.IndicesOptions;
import org.elasticsearch.action.support.master.AcknowledgedRequest;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.io.stream.BytesStreamOutput;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;

import java.io.IOException;
import java.util.List;

import static org.elasticsearch.action.ValidateActions.addValidationError;
import static org.elasticsearch.common.settings.Settings.readSettingsFromStream;

/**
 * Created by jehuty0shift on 14/03/18.
 */
public class IndicesUpdateSettingsFilter extends AbstractActionFilter {

    protected final Logger log = LogManager.getLogger(IndicesUpdateSettingsFilter.class);
    private final String UPDATE_ACTION_NAME = "indices:admin/settings/update";
    private final List<String> allowedSettings;

    private final boolean enabled;

    @Inject
    public IndicesUpdateSettingsFilter(final Settings settings, final ClusterService clusterService, final ThreadPool threadPool, final ArmorService armorService, final ArmorConfigService armorConfigService) {
        super(settings, armorService.getAuthenticationBackend(), armorService.getAuthorizator(), clusterService, armorService, armorConfigService, armorService.getAuditListener(), threadPool);
        enabled = settings.getAsBoolean(ConfigConstants.ARMOR_INDICES_UPDATESETTINGSFILTER_ENABLED, false);
        allowedSettings = Lists.newArrayList(settings.getAsArray(ConfigConstants.ARMOR_INDICES_UPDATESETTINGSFILTER_ALLOWED));
        log.info("IndicesUpdateSettingsFilter is " + (enabled ? "enabled" : "disabled"));
        log.debug("allowed Settings are {}",allowedSettings.toString());
    }


    public void applySecure(Task task, final String action, final ActionRequest request, final ActionListener listener, final ActionFilterChain chain) {
        //proceed if not enabled
        if (!enabled) {
            chain.proceed(task, action, request, listener);
            return;
        }


        if (!UPDATE_ACTION_NAME.equals(action)) {
            chain.proceed(task, action, request, listener);
            return;
        }

        final ThreadContext threadContext = threadpool.getThreadContext();

        final User user = threadContext.getTransient(ArmorConstants.ARMOR_AUTHENTICATED_USER);
        final String authHeader = threadContext.getHeader(ArmorConstants.ARMOR_AUTHENTICATED_TRANSPORT_REQUEST);

        log.trace("user {}", user);

        if (user == null) {

            if (authHeader == null) {
                log.error("not authenticated");
                throw new ElasticsearchException("not authenticated");
            }

            final Object decrypted = SecurityUtil.decryptAnDeserializeObject((String) authHeader, armorService.getSecretKey());

            if (decrypted == null || !(decrypted instanceof String) || !decrypted.equals("authorized")) {
                log.error("bad authenticated");
                throw new ElasticsearchException("bad authentication");
            }

        }

        UpdateSettingsRequest uSRequest = (UpdateSettingsRequest) request;
        try {

            CustomUpdateSettingsRequest cUSR = new CustomUpdateSettingsRequest(uSRequest);
            Settings oldSettings = cUSR.settings();
            Settings.Builder newSettingsBuilder = Settings.builder();

            for (String prefix : allowedSettings) {
                log.debug("checking prefix {} in UpdateSettingsRequest", prefix);
                Settings allowedSetting = oldSettings.filter((k) -> (k.startsWith(prefix)));
                if (!allowedSetting.isEmpty()) {
                    log.debug("{} is not empty, keeping setting");
                    newSettingsBuilder.put(allowedSetting);
                }
            }
            if (log.isDebugEnabled()) {
                log.debug("Settings has been changed from {} to {}", oldSettings.toDelimitedString(';'), newSettingsBuilder.build().toDelimitedString(';'));
            }
            uSRequest.settings(newSettingsBuilder);

            chain.proceed(task, action, request, listener);

        } catch (IOException e) {
            log.error("IO Exception during creation of settings !");
            throw new ElasticsearchException(e);
        }

    }


    class CustomUpdateSettingsRequest extends AcknowledgedRequest<UpdateSettingsRequest> implements IndicesRequest.Replaceable {

        private IndicesOptions indicesOptions = IndicesOptions.fromOptions(false, false, true, true);
        private Settings settings = Settings.Builder.EMPTY_SETTINGS;
        private String[] indices;

        CustomUpdateSettingsRequest(UpdateSettingsRequest usr) throws IOException {
            BytesStreamOutput bSO = new BytesStreamOutput();
            try {
                usr.writeTo(bSO);

                readFrom(StreamInput.wrap(bSO.bytes().toBytesRef().bytes));

            } catch (IOException ex) {
                log.error("I/O Exception during CustomUpdateSettings Creation");
                throw ex;
            }
        }

        @Override
        public IndicesOptions indicesOptions() {
            return indicesOptions;
        }

        @Override
        public ActionRequestValidationException validate() {
            ActionRequestValidationException validationException = null;
            if (settings.isEmpty()) {
                validationException = addValidationError("no settings to update", validationException);
            }
            return validationException;
        }

        @Override
        public String[] indices() {
            return indices;
        }

        public Settings settings() {
            return settings;
        }

        @Override
        public CustomUpdateSettingsRequest indices(String... indices) {
            this.indices = indices;
            return this;
        }

        @Override
        public void readFrom(StreamInput in) throws IOException {
            super.readFrom(in);
            indices = in.readStringArray();
            indicesOptions = IndicesOptions.readIndicesOptions(in);
            settings = readSettingsFromStream(in);
            readTimeout(in);
            boolean preserveExisting = in.readBoolean();
        }

    }
}
