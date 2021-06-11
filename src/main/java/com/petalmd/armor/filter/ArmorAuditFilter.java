package com.petalmd.armor.filter;

import com.petalmd.armor.audit.*;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.common.KafkaOutput;
import com.petalmd.armor.common.LDPGelf;
import com.petalmd.armor.service.ArmorService;
import com.petalmd.armor.util.ArmorConstants;
import com.petalmd.armor.util.ConfigConstants;
import com.petalmd.armor.util.SecurityUtil;
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
import java.net.UnknownHostException;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

public class ArmorAuditFilter implements ActionFilter, AuditForwarder {

    private static final Logger log = LogManager.getLogger(ArmorAuditFilter.class);

    private final boolean enabled;
    private final ThreadPool threadpool;
    private final KafkaAuditFactory kafkaAuditFactory;
    private final String clusterName;
    private final String clientId;
    private final String xOVHToken;
    private final Settings settings;

    public ArmorAuditFilter(final Settings settings, final ClusterService clusterService, final ArmorService armorService,
                            final ThreadPool threadpool) {

        this.enabled = settings.getAsBoolean(ConfigConstants.ARMOR_AUDIT_KAFKA_ENABLED, false);
        this.clientId = settings.get(ConfigConstants.ARMOR_AUDIT_KAFKA_CLIENT_ID, "es-armor");
        this.settings = settings;
        this.threadpool = threadpool;
        this.kafkaAuditFactory = KafkaAuditFactory.makeInstance(settings);
        this.clusterName = clusterService.getClusterName().value();
        this.xOVHToken = settings.get(ConfigConstants.ARMOR_AUDIT_KAFKA_X_OVH_TOKEN, "unknown");
        if(enabled) {
            armorService.getAuditListener().setAuditForwarder(this);
        }

        log.info("ArmorAuditFilter is {}", enabled ? "enabled" : "not enabled");
    }

    @Override
    public int order() {
        return Integer.MIN_VALUE;
    }


    @Override
    public void apply(Task task, final String action, final ActionRequest request, final ActionListener listener, final ActionFilterChain chain) {

        if (!enabled) {
            log.trace("Armor audit filter is not enabled proceeding");
            chain.proceed(task, action, request, listener);
            return;
        }

        if (action.startsWith("indices:data")) {
            log.trace("we don't indices data related requests");
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
            log.trace("we don't audit OPTIONS, GET, HEAD methods");
            chain.proceed(task, action, request, listener);
            return;
        }

        log.debug("Auditing request from {} by user : {}, url : {}, method : {}", resolvedAddress != null ? resolvedAddress.toString() : "unknown address", user.toString(), url, method.toString());

        AuditListener auditListener = new AuditListener(listener, kafkaAuditFactory, action, request, user, method, url, resolvedAddress, clusterName, clientId, xOVHToken);
        chain.proceed(task, action, request, auditListener);

    }

    @Override
    public void forwardFailedLogin(final String username, final RestRequest request, final ThreadContext threadContext) {
        if (!enabled || kafkaAuditFactory.getKafkaOutput() == null) {
            return;
        }

        KafkaOutput kafkaAuditOutput = kafkaAuditFactory.getKafkaOutput();

        final Instant date = Instant.now();
        InetAddress address = null;

        try {
            address = SecurityUtil.getProxyResolvedHostAddressFromRequest(request, settings);
        } catch (UnknownHostException uhEx) {
            log.warn("couldn't retrieve failed login origin");
        }

        KafkaAuditMessage failedAudit = new KafkaAuditMessage(date,"login:failure" , username, request.method().toString(), request.path(), address, clusterName, clientId, xOVHToken);
        failedAudit.setStatus(KafkaAuditMessage.Status.FAILURE);

        kafkaAuditOutput.sendLDPGelf(failedAudit.toLDPGelf());
        log.debug("failed login : {}",failedAudit.toString());
    }

    private static class AuditListener implements ActionListener {

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
                log.trace("indices request on {}", (String[]) indices);
                if (indices == null) {
                    if (iReq instanceof PutMappingRequest) {
                        PutMappingRequest pmr = (PutMappingRequest) iReq;
                        String index = pmr.getConcreteIndex().toString();
                        log.trace("Put Mapping Request with index: {}", index);
                        kafkaAuditMessage.setItems(Collections.singletonList(index));
                    }
                } else {
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