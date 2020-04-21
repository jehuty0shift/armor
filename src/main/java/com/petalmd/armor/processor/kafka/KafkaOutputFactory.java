package com.petalmd.armor.processor.kafka;

import com.petalmd.armor.util.ConfigConstants;
import org.elasticsearch.common.settings.Settings;

public class KafkaOutputFactory {

    private static KafkaOutputFactory INSTANCE;
    private KafkaOutput kafkaOutput;

    public static KafkaOutputFactory getInstance() {
        if(INSTANCE == null) {
            throw new IllegalStateException("INSTANCE should have been created before");
        }
        return INSTANCE;
    }

    public static synchronized KafkaOutputFactory makeInstance(final Settings settings) {
        if (INSTANCE == null) {
            return new KafkaOutputFactory(settings);
        } else {
            return INSTANCE;
        }
    }

    public KafkaOutput getKafkaOutput() {
        return kafkaOutput;
    }

    public void setKafkaOutput(KafkaOutput kafkaOutput) {
        this.kafkaOutput = kafkaOutput;
    }

    public KafkaOutputFactory(final Settings settings) {
        final boolean useInnerImpl = settings.getAsBoolean(ConfigConstants.ARMOR_LDP_PROCESSOR_KAFKA_OUTPUT_USE_KAFKA_IMPL, true);
        if (useInnerImpl == true) {
            this.kafkaOutput = new KafkaOutputImpl(settings);
        }
        INSTANCE = this;
    }

}
