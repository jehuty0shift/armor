package com.petalmd.armor.audit;

import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.RestRequest;

public interface AuditForwarder {
    void forwardFailedLogin(final String username, final RestRequest request, final ThreadContext threadContext);
}
