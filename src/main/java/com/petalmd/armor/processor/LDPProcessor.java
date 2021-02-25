package com.petalmd.armor.processor;

import com.petalmd.armor.common.KafkaOutput;
import com.petalmd.armor.common.LDPGelf;
import com.petalmd.armor.processor.kafka.KafkaOutputFactory;
import com.petalmd.armor.util.ConfigConstants;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.ingest.AbstractProcessor;
import org.elasticsearch.ingest.ConfigurationUtils;
import org.elasticsearch.ingest.IngestDocument;
import org.elasticsearch.ingest.Processor;
import org.joda.time.DateTime;

import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

public class LDPProcessor extends AbstractProcessor {

    public static final String TYPE = "ldp";
    public static final String DROP_MESSAGE_OPTION = "drop_message";
    public static final String IS_GENERATED_OPTION = "generated";
    private static final Logger log = LogManager.getLogger(LDPProcessor.class);
    private final boolean dropMessage;
    private final boolean generated;
    private final KafkaOutput kafkaOutput;
    private final String ldpIndex;

    public LDPProcessor(final String tag, final String description, final boolean dropMessage, final boolean generated, final KafkaOutput kafkaOutput, final String ldpIndex) {
        super(tag,description);
        this.kafkaOutput = kafkaOutput;
        this.dropMessage = dropMessage;
        this.generated = generated;
        this.ldpIndex = ldpIndex;
    }

    @Override
    public IngestDocument execute(IngestDocument ingestDocument) throws Exception {
        if (ingestDocument == null) {
            return null;
        }
        //If ldp processor has been automatically generated and does not target ldpIndex, we quit.
        if (generated && !ingestDocument.getSourceAndMetadata().get(IngestDocument.Metadata.INDEX.getFieldName()).equals(ldpIndex)) {
            return ingestDocument;
        }

        LDPGelf ldpGelf = new LDPGelf();
        for (Map.Entry<String, Object> ingestField : ingestDocument.getSourceAndMetadata().entrySet()) {
            final String fieldKey = ingestField.getKey();
            if (fieldKey.equals(IngestDocument.Metadata.INDEX.getFieldName()) ||
                    fieldKey.equals(IngestDocument.Metadata.TYPE.getFieldName()) ||
                    fieldKey.equals(IngestDocument.Metadata.ID.getFieldName()) ||
                    fieldKey.equals("_version_type") ||
                    fieldKey.equals("_version")) {
                continue;
            }


            if (fieldKey.equals("short_message")) {
                ldpGelf.setMessage(ingestField.getValue().toString());
                continue;
            }

            if (fieldKey.equals("host") && ingestField.getValue() instanceof String) {
                ldpGelf.setHost(ingestField.getValue().toString());
                continue;
            }

            if (fieldKey.equals("timestamp")) {
                Object value = ingestField.getValue();
                if (value instanceof Number) {
                    //test if value is > 2100-01-01T00:00:00 in UNIX seconds (if yes assume, it's milliseconds, otherwise convert them)
                    long longValue = ((Number)value).longValue() > 4102444800L? ((Number)value).longValue():(long)(((Number)value).doubleValue()*1000.0f);
                    ldpGelf.setTimestamp(new DateTime(longValue));
                    continue;
                }
                if (value instanceof String) {
                    final String strValue = (String)value;
                    if(strValue.length() < 50) {
                        try {
                            DateTime dt = DateTime.parse(strValue);
                            ldpGelf.setTimestamp(dt);
                        } catch (IllegalArgumentException ex) {
                            //means the timestamp couldn't be parsed
                            ldpGelf.addString("timestamp_fixit",strValue);
                        }
                        continue;
                    }
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
            if (log.isDebugEnabled()) {
                log.debug("adding key {} with Zoned Date Time value {}", key, zdtValue.toString());
            }
            long millis = zdtValue.toInstant().getNano() / 1000000L;
            ldpGelf.addDate(key, new DateTime(millis));
        }

        if (value instanceof Date) {
            final Date dValue = (Date) value;
            if (log.isDebugEnabled()) {
                log.debug("adding key {} with Date Time value {}", key, dValue.toString());
            }
            ldpGelf.addDate(key, new DateTime(dValue.toInstant().getNano() / 1000000L));
        }

        if (value instanceof Map) {
            final Map<String, Object> mapValue = (Map<String, Object>) value;
            log.debug("adding map with {} elements", mapValue.size());
            for (Map.Entry<String, Object> mapEntry : mapValue.entrySet()) {
                addEntryToLDPGelf(key + "_" + mapEntry.getKey(), mapEntry.getValue(), ldpGelf);
            }
            return;
        }


        if (value instanceof List) {
            List<Object> valueList = (List<Object>) value;
            log.debug("adding list with {} elements", valueList.size());
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
            log.debug("adding key {} with Boolean value {}", key, boolValue);
            ldpGelf.addBoolean(key, boolValue);
            return;
        }

        if (value instanceof String) {
            final String strValue = (String) value;
            log.debug("adding key {} with String value {}", key, strValue);
            ldpGelf.addString(key, strValue);
            return;
        }
        log.warn("couldn't find the type of the value added {} and type {}", value.toString(), value.getClass().getName());
    }

    @Override
    public String getType() {
        return TYPE;
    }


    public static final class Factory implements Processor.Factory {

        private final KafkaOutputFactory kafkaOutputFactory;
        private final String ldpIndex;

        public Factory(final KafkaOutputFactory kafkaOutputFactory, final Settings settings) {
            this.kafkaOutputFactory = kafkaOutputFactory;
            this.ldpIndex = settings.get(ConfigConstants.ARMOR_LDP_INDEX);
        }


        @Override
        public LDPProcessor create(Map<String, Processor.Factory> registry, String processorTag, String description,
                                   Map<String, Object> config) {

            final boolean dropMessage = ConfigurationUtils.readBooleanProperty(TYPE, processorTag, config, DROP_MESSAGE_OPTION, true);
            final boolean generated = ConfigurationUtils.readBooleanProperty(TYPE, processorTag, config, IS_GENERATED_OPTION, false);
            final KafkaOutput kOutput = kafkaOutputFactory.getKafkaOutput();
            kOutput.initialize();

            return new LDPProcessor(processorTag, description, dropMessage, generated, kOutput, ldpIndex);
        }

    }

}
