package com.petalmd.armor.processor.kafka;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.petalmd.armor.processor.LDPGelf;
import com.petalmd.armor.util.ConfigConstants;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.serialization.StringSerializer;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.common.settings.Settings;

import java.io.IOException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Optional;
import java.util.Properties;

public class KafkaOutputImpl implements KafkaOutput {

    final private Properties props;
    final private boolean enabled;
    final private String topic;
    private KafkaProducer producer;
    private ObjectMapper objMapper;


    public KafkaOutputImpl(final Settings settings) {
        props = new Properties();
        enabled = settings.getAsBoolean(ConfigConstants.ARMOR_LDP_PROCESSOR_KAFKA_ENABLED, false);

        if (enabled) {

            final String bootstrapServers = settings.get(ConfigConstants.ARMOR_LDP_PROCESSOR_KAFKA_BOOTSTRAP_SERVERS);
            final String clientId = settings.get(ConfigConstants.ARMOR_LDP_PROCESSOR_KAFKA_CLIENT_ID);
            final String acksConfig = settings.get(ConfigConstants.ARMOR_LDP_PROCESSOR_KAFKA_ACKS_CONFIG);
            final String batchSize = settings.get(ConfigConstants.ARMOR_LDP_PROCESSOR_KAFKA_BATCH_SIZE,"16384");
            final String lingerMs = settings.get(ConfigConstants.ARMOR_LDP_PROCESSOR_KAFKA_LINGER_MS,"5");
            final String compressionCodec = settings.get(ConfigConstants.ARMOR_LDP_PROCESSOR_KAFKA_COMPRESSION_CODEC,"none");
            topic = settings.get(ConfigConstants.ARMOR_LDP_PROCESSOR_KAFKA_TOPIC);
            props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
            props.put(ProducerConfig.CLIENT_ID_CONFIG, clientId);
            props.put(ProducerConfig.ACKS_CONFIG, acksConfig);
            props.put(ProducerConfig.BATCH_SIZE_CONFIG,batchSize);
            props.put(ProducerConfig.LINGER_MS_CONFIG,lingerMs);
            props.put(ProducerConfig.COMPRESSION_TYPE_CONFIG,compressionCodec);
            props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
            props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
            objMapper = new ObjectMapper();
        } else {
            topic = null;
        }

    }


    public void initialize() {
        if (enabled && producer == null) {

            producer = AccessController.doPrivileged((PrivilegedAction<KafkaProducer>) () -> {
                Thread.currentThread().setContextClassLoader(null);
                return new KafkaProducer<String, String>(props); });
        }
    }

    public void flush() {
        if(enabled && producer != null) {
            AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
                producer.flush();
                return null;
            });
        }
    }

    public void close() {
        if(enabled && producer != null) {
            AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
                producer.close();
                return null;
            });
        }
    }

    public void sendLDPGelf(final LDPGelf ldpGelf) {
        if (!enabled) {
            throw new ElasticsearchException("the Kafka Output is not enabled");
        }

        if (producer == null) {
            throw new ElasticsearchException("Kafka Producer is not ready");
        }

        try {

            AccessController.doPrivileged((PrivilegedExceptionAction<Void>) () -> {
                String document = objMapper.writeValueAsString(ldpGelf.getDocumentMap());
                producer.send(new ProducerRecord(topic, document));
                return null;
            });

        } catch (PrivilegedActionException e) {
            if(e.getException() instanceof IOException) {
                throw new ElasticsearchException("Couldn't serialize LDPGelf message",e.getException());
            } else {
                throw new ElasticsearchException("Couldn't use Kafka Output due to exception", e.getException());
            }
        }
    }


}