package com.petalmd.armor.common;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.Instant;

import java.net.InetAddress;
import java.util.HashMap;
import java.util.Map;

public class LDPGelf {
    private final Map<String, Object> document;

    public LDPGelf() {
        document = new HashMap<>();
        document.put("version", "1.1");
    }

    public LDPGelf addString(final String field, final String value) {
        return addValue(field, value);
    }

    public LDPGelf addLong(final String field, final long value) {
        String finalField = field;
        if (!finalField.endsWith("_long")) {
            finalField += "_long";
        }
        return addValue(finalField, value);
    }

    // In order to not confuse users on values overloading int,
    // we force any integer values to be in the same format of long.
    public LDPGelf addInt(final String field, final int value) {
        String finalField = field;
        if (!finalField.endsWith("_long")) {
            finalField += "_long";
        }
        return addValue(finalField, value);
    }

    public LDPGelf addFloat(final String field, final float value) {
        String finalField = field;
        if (!finalField.endsWith("_num")) {
            finalField += "_num";
        }
        return addValue(finalField, value);
    }

    public LDPGelf addDouble(final String field, final double value) {
        String finalField = field;
        if (!finalField.endsWith("_num") || !finalField.endsWith("_double")) {
            finalField += "_num";
        }
        return addValue(finalField, value);
    }


    public LDPGelf setMessage(final String message) {
        document.put("short_message", message);
        return this;
    }


    public LDPGelf addBoolean(final String field, final boolean value) {
        String finalField = field;
        if (!finalField.endsWith("_bool")) {
            finalField += "_bool";
        }
        String strValue = value?"true":"false";
        return addValue(finalField, strValue);
    }

    public LDPGelf addFullMessage(final String fullMessage) {
        document.put("full_message", fullMessage);
        return this;
    }

    public LDPGelf addDate(final String field, final DateTime value) {
        String finalField = field;
        if (!finalField.endsWith("_date")) {
            finalField += "_date";
        }
        return addValue(finalField, value);
    }

    public LDPGelf addIP(final String field, final InetAddress ip) {
        String finalField = field;
        if (!finalField.endsWith("_ip")) {
            finalField += "_ip";
        }
        //add Ip in string
        addValue(finalField.substring(0,finalField.length()-3),ip.toString());
        return addValue(finalField, ip.getHostAddress());
    }

    private LDPGelf addValue(final String field, final Object value) {
        String gelfField = field;
        if (!gelfField.startsWith("_")) {
            gelfField = "_" + gelfField;
        }
        document.put(gelfField, value);
        return this;
    }

    public LDPGelf setTimestamp(final DateTime timestamp) {
        document.put("timestamp", timestamp.toInstant().getMillis() / 1000.0);
        return this;
    }

    public DateTime getTimestamp(){
        return Instant.ofEpochMilli((long)document.get("timestamp")*1000l).toDateTime(DateTimeZone.UTC);
    }

    public LDPGelf setHost(final String host) {
        document.put("host", host);
        return this;
    }

    public LDPGelf validate() {
        if (!document.containsKey("short_message")) {
            if (document.containsKey("_message")) {
                document.put("short_message", document.get("_message"));
            } else {
                document.put("short_message", "-");
            }
        }

        if (!document.containsKey("host")) {
            if (document.containsKey("_host_hostname")) {
                this.setHost(document.get("_host_hostname").toString());
            } else if (document.containsKey("_host_name")) {
                this.setHost(document.get("_host_name").toString());
            } else {
                document.put("host", "unknown");
            }
        }

        if (!document.containsKey("timestamp")) {
            if (document.containsKey("_@timestamp")) {
                try {
                    this.setTimestamp(DateTime.parse(document.get("_@timestamp").toString()));
                } catch (Exception ex) {
                    this.setTimestamp(DateTime.now());
                }
            } else {
                this.setTimestamp(DateTime.now());
            }
        }

        return this;
    }

    public Map<String, Object> getDocumentMap() {
        return document;
    }
}


