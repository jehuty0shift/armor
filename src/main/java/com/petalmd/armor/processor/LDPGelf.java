package com.petalmd.armor.processor;

import com.petalmd.armor.processor.kafka.KafkaOutput;
import com.petalmd.armor.processor.kafka.KafkaOutputFactory;
import org.joda.time.DateTime;

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

    public LDPGelf addInt(final String field, final int value) {
        String finalField = field;
        if (!finalField.endsWith("_int")) {
            finalField += "_int";
        }
        return addValue(finalField, value);
    }

    public LDPGelf addFloat(final String field, final float value) {
        String finalField = field;
        if (!finalField.endsWith("_float")) {
            finalField += "_float";
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
        return addValue(finalField, value);
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

    public LDPGelf setHost(final String host) {
        document.put("host", host);
        return this;
    }

    public LDPGelf validate() {
        if (!document.containsKey("short_message")) {
            document.put("short_message", "-");
        }

        if (!document.containsKey("host")) {
            document.put("host", "unknown");
        }

        if(!document.containsKey("timestamp")) {
            this.setTimestamp(DateTime.now());
        }

        return this;
    }

    public Map<String, Object> getDocumentMap() {
        return document;
    }
}


