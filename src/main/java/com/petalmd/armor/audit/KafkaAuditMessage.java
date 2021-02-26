package com.petalmd.armor.audit;

import com.petalmd.armor.common.LDPGelf;
import jnr.ffi.annotations.In;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

import java.net.InetAddress;
import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

public class KafkaAuditMessage {

    public enum Status {
        SUCCESS("success"),
        FAILURE("failure");

        public String label;

        Status(String label) {
            this.label = label;
        }
    }

    private Status status;
    private String exceptionType;
    private String exceptionMessage;
    private String user;
    private String action;
    private String clientId;
    private String method;
    private String url;
    private InetAddress remoteAddress;
    private String clusterName;
    private List<String> items;
    private Instant start;
    private Instant end;
    private String xOVHToken;

    public KafkaAuditMessage(final Instant start, final String action, final String user, final String method, final String url, final InetAddress remoteAddress, final String clusterName, final String clientId, final String xOVHToken) {
        this.start = start;
        this.action = action;
        this.clientId = clientId;
        this.user = user;
        this.method = method;
        this.url = url;
        this.remoteAddress = remoteAddress;
        this.clusterName = clusterName;
        this.xOVHToken = xOVHToken;
    }

    public Status getStatus() {
        return status;
    }

    public void setStatus(Status status) {
        this.status = status;
    }

    public String getExceptionType() {
        return exceptionType;
    }

    public void setExceptionType(String exceptionType) {
        this.exceptionType = exceptionType;
    }

    public String getExceptionMessage() {
        return exceptionMessage;
    }

    public void setExceptionMessage(String exceptionMessage) {
        this.exceptionMessage = exceptionMessage;
    }

    public String getUser() {
        return user;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }


    public void setItems(List<String> items) {
        this.items = items;
    }

    public Instant getStart() {
        return start;
    }

    public Instant getEnd() {
        return end;
    }

    public void setEnd(Instant end) {
        this.end = end;
    }

    public LDPGelf toLDPGelf() {
        LDPGelf ldpGelf = new LDPGelf();
        ldpGelf.setTimestamp(org.joda.time.Instant.ofEpochMilli(start.toEpochMilli()).toDateTime(DateTimeZone.UTC));
        ldpGelf.setHost(clientId);
        ldpGelf.addDate("end", org.joda.time.Instant.ofEpochMilli(end.toEpochMilli()).toDateTime(DateTimeZone.UTC));
        ldpGelf.addDate("start", org.joda.time.Instant.ofEpochMilli(start.toEpochMilli()).toDateTime(DateTimeZone.UTC));
        ldpGelf.addInt("duration", (int) (end.toEpochMilli() - start.toEpochMilli()));
        ldpGelf.setMessage(user + ": " + method + " " + url);
        if (remoteAddress != null) {
            ldpGelf.addIP("remote_address", remoteAddress);
        }
        ldpGelf.addString("status", status.label);
        ldpGelf.addString("action", action);
        ldpGelf.addString("cluster_name", clusterName);
        ldpGelf.addString("url", url);
        ldpGelf.addString("method", method);
        ldpGelf.addString("user", user);
        ldpGelf.addString("X-OVH-TOKEN",xOVHToken);

        if (exceptionType != null) {
            ldpGelf.addString("exception_type", exceptionType);
        }

        if (exceptionMessage != null) {
            ldpGelf.addString("exception_message", exceptionMessage);
        }

        if (items != null && !items.isEmpty()) {
            items.sort(String::compareTo);
            ldpGelf.addString("_items", items.stream().collect(Collectors.joining(", ")));
        }

        return ldpGelf;
    }


    @Override
    public String toString() {
        return "KafkaAuditMessage{" +
                "status=" + status +
                ", exceptionType='" + exceptionType + '\'' +
                ", exceptionMessage='" + exceptionMessage + '\'' +
                ", user='" + user + '\'' +
                ", action='" + action + '\'' +
                ", method='" + method + '\'' +
                ", url='" + url + '\'' +
                ", remoteAddress=" + remoteAddress +
                ", clusterName='" + clusterName + '\'' +
                ", start=" + start +
                ", end=" + end +
                '}';
    }
}
