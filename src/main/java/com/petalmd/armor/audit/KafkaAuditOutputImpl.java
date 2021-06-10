package com.petalmd.armor.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.petalmd.armor.common.KafkaOutput;
import com.petalmd.armor.common.LDPGelf;
import com.petalmd.armor.util.ConfigConstants;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.serialization.StringSerializer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.common.settings.Settings;

import java.io.IOException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Properties;

public class KafkaAuditOutputImpl implements KafkaOutput {


    private Properties kProps;
    private final boolean enabled;
    private final boolean printEnabled;
    private KafkaProducer<String, String> kProducer;
    private String topic;
    private ObjectMapper objMapper;

    protected final Logger log = LogManager.getLogger(KafkaAuditOutputImpl.class);


    public KafkaAuditOutputImpl(final Settings settings) {
        enabled = settings.getAsBoolean(ConfigConstants.ARMOR_AUDIT_KAFKA_ENABLED, false);
        printEnabled = settings.getAsBoolean(ConfigConstants.ARMOR_AUDIT_KAFKA_PRINT_MESSAGES_ENABLED, false);
        log.info("Kafka Audit Output Impl is {}.", enabled ? "enabled" : "not enabled");
        if (!enabled) {
            return;
        }
        kProps = new Properties();

        final String clientId = settings.get(ConfigConstants.ARMOR_AUDIT_KAFKA_CLIENT_ID);
        topic = settings.get(ConfigConstants.ARMOR_AUDIT_KAFKA_TOPIC);
        final String bootstrapServers = settings.get(ConfigConstants.ARMOR_AUDIT_KAFKA_BOOTSTRAP_SERVERS);
        final String securityProtocol = settings.get(ConfigConstants.ARMOR_AUDIT_KAFKA_SECURITY_PROTOCOL);
        final String SSLTruststoreLocation = settings.get(ConfigConstants.ARMOR_AUDIT_KAFKA_SSL_TRUSTSTORE_LOCATION, "");
        final String SSLTruststorePassword = settings.get(ConfigConstants.ARMOR_AUDIT_KAFKA_SSL_TRUSTSTORE_PASSWORD, "");
        final String SASLUsername = settings.get(ConfigConstants.ARMOR_AUDIT_KAFKA_SASL_USERNAME);
        final String SASLPassword = settings.get(ConfigConstants.ARMOR_AUDIT_KAFKA_SASL_PASSWORD);
        final String ackConfig = settings.get(ConfigConstants.ARMOR_AUDIT_KAFKA_ACKS_CONFIG, "1");
        final String compressionCodec = settings.get(ConfigConstants.ARMOR_AUDIT_KAFKA_COMPRESSION_CODEC, "gzip");

        log.info("audit topic: {};  bootstrap.servers :'{}', security.protocol : {}, sasl.username : {}", topic, bootstrapServers, securityProtocol, SASLUsername);

        kProps.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        kProps.put(ProducerConfig.CLIENT_ID_CONFIG, clientId);
        kProps.put(ProducerConfig.ACKS_CONFIG, ackConfig);
        kProps.put(ProducerConfig.COMPRESSION_TYPE_CONFIG, compressionCodec);

        if ("SASL_SSL".equals(securityProtocol) || "SASL_PLAINTEXT".equals(securityProtocol)) {
            kProps.put("security.protocol", securityProtocol);
            kProps.put("sasl.mechanism", "PLAIN");
            if (!"".equals(SSLTruststoreLocation) && !"".equals(SSLTruststorePassword)) {
                kProps.put("ssl.truststore.location", SSLTruststoreLocation);
                kProps.put("ssl.truststore.password", SSLTruststorePassword);
            }

            final String jaasConfig = "org.apache.kafka.common.security.plain.PlainLoginModule required \n" +
                    "  username=\"" + SASLUsername + "\" \n" +
                    "  password=\"" + SASLPassword + "\";";
            kProps.put("sasl.jaas.config", jaasConfig);
        }

        this.objMapper = new ObjectMapper();

    }

    @Override
    public void initialize() {
        if (!enabled || kProducer != null) {
            return;
        }
        kProducer = AccessController.doPrivileged((PrivilegedAction<KafkaProducer<String, String>>) () -> {
            //This is necessary to force the Kafka Serializer loader to use the classloader used to load kafkaProducer classes
            kProps.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
            kProps.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
            Thread.currentThread().setContextClassLoader(KafkaProducer.class.getClassLoader());
            return new KafkaProducer<>(kProps);
        });
    }


    @Override
    public void flush() {
        if (enabled && kProducer != null) {
            AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
                kProducer.flush();
                return null;
            });
        }
    }

    @Override
    public void close() {
        if (enabled && kProducer != null) {
            AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
                kProducer.close();
                return null;
            });
        }
    }

    @Override
    public void sendLDPGelf(final LDPGelf ldpGelf) {
        if (!enabled) {
            return;
        }

        if (kProducer == null) {
            throw new ElasticsearchException("Kafka Producer is not ready");
        }


        try {

            AccessController.doPrivileged((PrivilegedExceptionAction<Void>) () -> {
                String document = objMapper.writeValueAsString(ldpGelf.getDocumentMap());
                if (printEnabled) {
                    log.info("{}", document);
                }
                kProducer.send(new ProducerRecord<>(topic, null, ldpGelf.getTimestamp().toInstant().getMillis(), null, document));
                return null;
            });

        } catch (PrivilegedActionException e) {
            if (e.getException() instanceof IOException) {
                throw new ElasticsearchException("Couldn't serialize LDPGelf message", e.getException());
            } else {
                throw new ElasticsearchException("Couldn't use Kafka Audit Output due to exception", e.getException());
            }
        }
    }


}
