package com.petalmd.armor.audit;

import com.petalmd.armor.common.KafkaOutput;
import com.petalmd.armor.util.ConfigConstants;
import org.elasticsearch.common.settings.Settings;

public class KafkaAuditFactory {


    private static KafkaAuditFactory INSTANCE;
    private KafkaOutput kafkaOutput;
    private boolean enabled;


    public static KafkaAuditFactory getInstance() {
        if (INSTANCE == null) {
            throw new IllegalStateException("INSTANCE should have been created before");
        }
        return INSTANCE;
    }

    public static synchronized KafkaAuditFactory makeInstance(final Settings settings) {
        if (INSTANCE == null) {
            INSTANCE = new KafkaAuditFactory(settings);
        }
        return INSTANCE;
    }

    public void setKafkaOutput(KafkaOutput kOutput) {
        this.kafkaOutput = kOutput;
    }

    public KafkaOutput getKafkaOutput() {
        return kafkaOutput;
    }

    private KafkaAuditFactory(final Settings settings) {

        enabled = settings.getAsBoolean(ConfigConstants.ARMOR_AUDIT_KAFKA_ENABLED, false);
        boolean useImpl = settings.getAsBoolean(ConfigConstants.ARMOR_AUDIT_KAFKA_USE_IMPL, true);
        if (enabled) {
            if (useImpl) {
                kafkaOutput = new KafkaAuditOutputImpl(settings);
            }
        }

    }


}