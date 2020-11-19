package com.petalmd.armor.filter.lifecycle;

import com.petalmd.armor.util.SecurityUtil;

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
