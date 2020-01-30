package com.petalmd.armor.filter.lifecycle;

import org.apache.commons.lang.StringUtils;

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

    public boolean isValid() {
        boolean valid = StringUtils.isNotEmpty(bootstrapServers) &&
                StringUtils.isNotEmpty(topicPrefix) &&
                StringUtils.isNotEmpty(securityProtocol);
        if (!valid) {
            return valid;
        }
        if (!securityProtocol.equals("PLAINTEXT")) {
            valid = StringUtils.isNotEmpty(SASLMechanism) &&
                    StringUtils.isNotEmpty(SASLPlainPassword) &&
                    StringUtils.isNotEmpty(SASLPlainUsername);
        }
        return valid;
    }

}
