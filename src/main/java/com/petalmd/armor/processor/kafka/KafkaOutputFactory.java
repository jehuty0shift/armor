package com.petalmd.armor.processor.kafka;

import com.petalmd.armor.common.KafkaOutput;
import com.petalmd.armor.common.KafkaOutputConsumer;
import com.petalmd.armor.util.ConfigConstants;
import org.elasticsearch.common.settings.Settings;

public class KafkaOutputFactory {

    private static KafkaOutputFactory INSTANCE = null;
    private KafkaOutput kafkaOutput;

    public static KafkaOutputFactory getInstance() {
        if(INSTANCE == null) {
            throw new IllegalStateException("INSTANCE should have been created before");
        }
        return INSTANCE;
    }

    public static synchronized KafkaOutputFactory makeInstance(final Settings settings) {
        if (INSTANCE == null) {
            INSTANCE = new KafkaOutputFactory(settings);
        }
        return INSTANCE;
    }

    public KafkaOutput getKafkaOutput() {
        return kafkaOutput;
    }

    public void setKafkaOutput(KafkaOutput kafkaOutput) {
        this.kafkaOutput = kafkaOutput;
    }

    private KafkaOutputFactory(final Settings settings) {
        final boolean useInnerImpl = settings.getAsBoolean(ConfigConstants.ARMOR_LDP_PROCESSOR_KAFKA_OUTPUT_USE_KAFKA_IMPL, true);
        if (useInnerImpl == true) {
            this.kafkaOutput = new KafkaOutputImpl(settings);
        } else {
            KafkaOutputConsumer kOConsumer = new KafkaOutputConsumer((ldpGelf) -> {}); //noop consumer;
            this.kafkaOutput = kOConsumer;
        }
    }

}
