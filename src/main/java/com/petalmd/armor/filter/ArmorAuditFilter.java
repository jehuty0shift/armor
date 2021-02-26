package com.petalmd.armor.filter;

import com.petalmd.armor.audit.KafkaAuditFactory;
import com.petalmd.armor.audit.KafkaAuditMessage;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.common.KafkaOutput;
import com.petalmd.armor.common.LDPGelf;
import com.petalmd.armor.util.ArmorConstants;
import com.petalmd.armor.util.ConfigConstants;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.AliasesRequest;
import org.elasticsearch.action.IndicesRequest;
import org.elasticsearch.action.admin.indices.mapping.put.PutMappingRequest;
import org.elasticsearch.action.support.ActionFilter;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;

import java.net.InetAddress;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

public class ArmorAuditFilter implements ActionFilter {

    private static final Logger log = LogManager.getLogger(ArmorAuditFilter.class);

    private boolean enabled;
    private ThreadPool threadpool;
    private KafkaAuditFactory kafkaAuditFactory;
    private String clusterName;
    private String clientId;
    private String xOVHToken;

    public ArmorAuditFilter(final Settings settings, final ClusterService clusterService,
                            final ThreadPool threadpool) {

        this.enabled = settings.getAsBoolean(ConfigConstants.ARMOR_AUDIT_KAFKA_ENABLED, false);
        this.clientId = settings.get(ConfigConstants.ARMOR_AUDIT_KAFKA_CLIENT_ID, "es-armor");
        this.threadpool = threadpool;
        this.kafkaAuditFactory = KafkaAuditFactory.makeInstance(settings);
        this.clusterName = clusterService.getClusterName().value();
        this.xOVHToken = settings.get(ConfigConstants.ARMOR_AUDIT_KAFKA_X_OVH_TOKEN, "unknown");

        log.info("ArmorAuditFilter is {}", enabled ? "enabled" : "not enabled");
    }

    @Override
    public int order() {
        return Integer.MIN_VALUE;
    }


    @Override
    public void apply(Task task, final String action, final ActionRequest request, final ActionListener listener, final ActionFilterChain chain) {

        if (!enabled) {
            log.debug("Armor audit filter is not enabled proceeding");
            chain.proceed(task, action, request, listener);
            return;
        }

        if (action.startsWith("indices:data")) {
            log.debug("we don't indices data related requests");
            chain.proceed(task, action, request, listener);
            return;
        }

        ThreadContext threadContext = threadpool.getThreadContext();

        AtomicBoolean isExternal = threadContext.getTransient(ArmorConstants.ARMOR_REQUEST_IS_EXTERNAL);
        if (action.startsWith("internal") || isExternal == null || !isExternal.get()) {
            log.debug("we don't audit internal requests");
            chain.proceed(task, action, request, listener);
            return;
        }

        User user = threadContext.getTransient(ArmorConstants.ARMOR_AUTHENTICATED_USER);
        if (user == null) {
            user = new User("unknown");
        }


        final RestRequest.Method method = threadContext.getTransient(ArmorConstants.ARMOR_AUDIT_REQUEST_METHOD);
        final String url = threadContext.getTransient(ArmorConstants.ARMOR_AUDIT_REQUEST_URL);
        final InetAddress resolvedAddress = threadContext.getTransient(ArmorConstants.ARMOR_RESOLVED_REST_ADDRESS);


        if (RestRequest.Method.OPTIONS.equals(method) ||
                RestRequest.Method.GET.equals(method) ||
                RestRequest.Method.HEAD.equals(method)) {
            log.debug("we don't audit OPTIONS, GET, HEAD methods");
            chain.proceed(task, action, request, listener);
            return;
        }

        log.debug("Auditing request from {} by user : {}, url : {}, method : {}", resolvedAddress != null ? resolvedAddress.toString() : "unknown address", user.toString(), url, method.toString());
        AuditListener auditListener = new AuditListener(listener, kafkaAuditFactory, action, request, user, method, url, resolvedAddress, clusterName, clientId, xOVHToken);
        chain.proceed(task, action, request, auditListener);

    }

    private class AuditListener implements ActionListener {

        private final ActionListener delegate;
        private final KafkaAuditMessage kafkaAuditMessage;
        private final KafkaAuditFactory kafkaAuditFactory;


        public AuditListener(final ActionListener delegate,
                             final KafkaAuditFactory kafkaAuditFactory,
                             final String action,
                             final ActionRequest request,
                             final User user,
                             final RestRequest.Method method,
                             final String url,
                             final InetAddress remoteAddress,
                             final String clusterName,
                             final String clientId,
                             final String xOVHToken) {
            this.delegate = delegate;

            this.kafkaAuditMessage = new KafkaAuditMessage(Instant.now(), action, user.getName(), method.toString(), url, remoteAddress, clusterName, clientId, xOVHToken);
            this.kafkaAuditFactory = kafkaAuditFactory;
            if (request instanceof IndicesRequest) {
                IndicesRequest iReq = (IndicesRequest) request;
                String[] indices = iReq.indices();
                if (indices == null) {
                    if (iReq instanceof PutMappingRequest) {
                        PutMappingRequest pmr = (PutMappingRequest) iReq;
                        String index = pmr.getConcreteIndex().toString();
                        log.trace("Put Mapping Request with index: {}", index);
                        kafkaAuditMessage.setItems(Collections.singletonList(index));
                    }
                } else {
                    log.trace("indices request on {}", iReq.indices());
                    kafkaAuditMessage.setItems(Arrays.asList(iReq.indices()));
                }
            } else if (request instanceof AliasesRequest) {
                AliasesRequest aReq = (AliasesRequest) request;
                List<String> items = new ArrayList<>();
                items.addAll(Arrays.asList(aReq.aliases()));
                items.addAll(Arrays.asList(aReq.indices()));
                log.trace("aliases request on aliases {}, indices {}", aReq.aliases(), aReq.indices());
                kafkaAuditMessage.setItems(items);
            }
        }

        @Override
        public void onResponse(Object o) {
            kafkaAuditMessage.setEnd(Instant.now());
            kafkaAuditMessage.setStatus(KafkaAuditMessage.Status.SUCCESS);

            delegate.onResponse(o);

            KafkaOutput kafkaOutput = kafkaAuditFactory.getKafkaOutput();
            kafkaOutput.initialize();

            log.debug("Audited successful request {}", kafkaAuditMessage.toString());

            final LDPGelf ldpGelf = kafkaAuditMessage.toLDPGelf();
            ldpGelf.validate();
            kafkaOutput.sendLDPGelf(ldpGelf);
            log.debug("audit message sent");
        }

        @Override
        public void onFailure(Exception e) {
            kafkaAuditMessage.setEnd(Instant.now());
            kafkaAuditMessage.setStatus(KafkaAuditMessage.Status.FAILURE);

            kafkaAuditMessage.setExceptionMessage(e.getMessage());
            kafkaAuditMessage.setExceptionType(e.getClass().getName());

            delegate.onFailure(e);

            KafkaOutput kafkaOutput = kafkaAuditFactory.getKafkaOutput();
            kafkaOutput.initialize();

            log.debug("Audited failed request  {}", kafkaAuditMessage.toString());

            final LDPGelf ldpGelf = kafkaAuditMessage.toLDPGelf();
            ldpGelf.validate();
            kafkaOutput.sendLDPGelf(ldpGelf);
            log.debug("audit message sent");

        }
    }

}