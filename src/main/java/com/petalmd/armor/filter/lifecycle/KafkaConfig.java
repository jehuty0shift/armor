package com.petalmd.armor.filter.lifecycle;

import com.bettercloud.vault.json.JsonObject;
import com.petalmd.armor.util.SecurityUtil;

import java.util.Map;

/**
 * Created by jehuty0shift on 24/01/2020.
 */
public class KafkaConfig {
    public String bootstrapServers;
    public String SASLPlainUsername;
    public String SASLPlainPassword;
    public String securityProtocol;
    public String SASLMechanism;
    public String topicPrefix;
    public String kSerPrivateKey;

    public KafkaConfig(){}

    public KafkaConfig(final JsonObject kafkaConfigMap) {
        topicPrefix = kafkaConfigMap.getString("KSER_TOPIC_PREFIX");
        JsonObject kSerProducerConfig = kafkaConfigMap.get("KSER_PRODUCER_CONFIG").asObject();
        bootstrapServers = kSerProducerConfig.getString("BOOTSTRAP_SERVERS");
        SASLMechanism = kSerProducerConfig.getString("SASL_MECHANISM");
        SASLPlainUsername = kSerProducerConfig.getString("SASL_PLAIN_USERNAME");
        SASLPlainPassword = kSerProducerConfig.getString("SASL_PLAIN_PASSWORD");
        securityProtocol = kSerProducerConfig.getString("SECURITY_PROTOCOL");
        SASLMechanism = kSerProducerConfig.getString("SASL_MECHANISM");
        kSerPrivateKey = kafkaConfigMap.getString("KSER_SECRETBOX_KEY");
    }


    public boolean isValid() {
        boolean valid = SecurityUtil.isNotEmpty(bootstrapServers) &&
                SecurityUtil.isNotEmpty(topicPrefix) &&
                SecurityUtil.isNotEmpty(securityProtocol);
        if (!valid) {
            return valid;
        }
        if (!securityProtocol.equals("PLAINTEXT")) {
            valid = SecurityUtil.isNotEmpty(SASLMechanism) &&
                    SecurityUtil.isNotEmpty(SASLPlainPassword) &&
                    SecurityUtil.isNotEmpty(SASLPlainUsername);
        }
        return valid;
    }

}
