package com.petalmd.armor.processor;

import com.petalmd.armor.processor.kafka.KafkaOutput;
import com.petalmd.armor.processor.kafka.KafkaOutputFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ingest.AbstractProcessor;
import org.elasticsearch.ingest.ConfigurationUtils;
import org.elasticsearch.ingest.IngestDocument;
import org.elasticsearch.ingest.Processor;
import org.joda.time.DateTime;

import java.time.ZonedDateTime;
import java.util.*;

public class LDPProcessor extends AbstractProcessor {

    public static final String TYPE = "ldp";
    private static final Logger log = LogManager.getLogger(LDPProcessor.class);
    private final boolean dropMessage;
    private final KafkaOutput kafkaOutput;

    public LDPProcessor(final String tag, final boolean dropMessage, final KafkaOutput kafkaOutput) {
        super(tag);
        this.kafkaOutput = kafkaOutput;
        this.dropMessage = dropMessage;
    }

    @Override
    public IngestDocument execute(IngestDocument ingestDocument) throws Exception {
        if (ingestDocument == null) {
            return null;
        }
        LDPGelf ldpGelf = new LDPGelf();
        for (Map.Entry<String, Object> ingestField : ingestDocument.getSourceAndMetadata().entrySet()) {
            final String fieldKey = ingestField.getKey();
            if (fieldKey.equals(IngestDocument.MetaData.INDEX.getFieldName()) ||
                    fieldKey.equals(IngestDocument.MetaData.TYPE.getFieldName()) ||
                    fieldKey.equals(IngestDocument.MetaData.ID.getFieldName()) ||
                    fieldKey.equals("_version_type") ||
                    fieldKey.equals("_version")) {
                continue;
            }


            if (fieldKey.equals("short_message")) {
                ldpGelf.setMessage(ingestField.getValue().toString());
                continue;
            }

            if (fieldKey.equals("host")) {
                ldpGelf.setHost(ingestField.getValue().toString());
                continue;
            }

            if (fieldKey.equals("timestamp")) {
                Object value = ingestField.getValue();
                if (value instanceof Number) {
                    ldpGelf.setTimestamp(new DateTime(((Number) value).longValue()));
                    continue;
                }
            }

            if (fieldKey.equals("full_message")) {
                ldpGelf.addFullMessage(ingestField.getValue().toString());
                continue;
            }

            addEntryToLDPGelf(fieldKey, ingestField.getValue(), ldpGelf);
        }

        kafkaOutput.sendLDPGelf(ldpGelf.validate());

        if (dropMessage) {
            return null;
        } else {
            return ingestDocument;
        }
    }


    private void addEntryToLDPGelf(final String key, final Object value, final LDPGelf ldpGelf) {
        if (value instanceof ZonedDateTime) {
            final ZonedDateTime zdtValue = (ZonedDateTime) value;
            long millis = zdtValue.toInstant().getNano() / 1000000L;
            ldpGelf.addDate(key, new DateTime(millis));
        }

        if (value instanceof Date) {
            final Date dValue = (Date) value;
            ldpGelf.addDate(key, new DateTime(dValue.toInstant().getNano() / 1000000L));
        }

        if (value instanceof Map) {
            final Map<String, Object> mapValue = (Map<String, Object>) value;
            for (Map.Entry<String, Object> mapEntry : mapValue.entrySet()) {
                addEntryToLDPGelf(key + "_" + mapEntry.getKey(), mapEntry.getValue(), ldpGelf);
            }
            return;
        }


        if (value instanceof List) {
            List<Object> valueList = (List<Object>) value;
            for (int i = 0; i < valueList.size(); i++) {
                addEntryToLDPGelf(key + "_" + i, valueList.get(i), ldpGelf);
            }
            return;
        }

        if (value instanceof byte[]) {
            final String strValue = Base64.getEncoder().encodeToString((byte[]) value);
            log.debug("adding key {} with byte value {}", key, strValue);
            ldpGelf.addString(key, strValue);
            return;
        }

        if (value instanceof Integer) {
            final Integer intValue = (Integer) value;
            log.debug("adding integer key {} with integer value {}", key, intValue);
            ldpGelf.addInt(key, intValue);
            return;
        }

        if (value instanceof Long) {
            final Long longValue = (Long) value;
            log.debug("adding key {} with long value {}", key, longValue);
            ldpGelf.addLong(key, longValue);
            return;
        }

        if (value instanceof Float) {
            final Float floatValue = (Float) value;
            log.debug("adding key {} with Float value {}", key, floatValue);
            ldpGelf.addFloat(key, floatValue);
            return;
        }

        if (value instanceof Double) {
            final Double doubleValue = (Double) value;
            log.debug("adding key {} with Double value {}", key, doubleValue);
            ldpGelf.addDouble(key, doubleValue);
            return;
        }

        if (value instanceof Boolean) {
            final Boolean boolValue = (Boolean) value;
            log.debug("adding key {} with Double value {}", key, boolValue);
            ldpGelf.addBoolean(key, boolValue);
            return;
        }

        if (value instanceof String) {
            final String strValue = (String) value;
            log.debug("adding key {} with String value {}", key, strValue);
            ldpGelf.addString(key, strValue);
        }

        log.warn("couldn't find the type of the value added");
    }

    @Override
    public String getType() {
        return TYPE;
    }


    public static final class Factory implements Processor.Factory {

        private final KafkaOutputFactory kafkaOutputFactory;

        public Factory(final KafkaOutputFactory kafkaOutputFactory) {
            this.kafkaOutputFactory = kafkaOutputFactory;
        }


        @Override
        public LDPProcessor create(Map<String, Processor.Factory> registry, String processorTag,
                                          Map<String, Object> config) throws Exception {

            final boolean dropMessage = ConfigurationUtils.readBooleanProperty(TYPE, processorTag, config, "drop_message", true);
            final KafkaOutput kOutput = kafkaOutputFactory.getKafkaOutput();
            kOutput.initialize();

            return new LDPProcessor(processorTag, dropMessage, kOutput);
        }

    }

}
