package com.petalmd.armor.service;

import com.mongodb.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Filters;
import com.petalmd.armor.filter.lifecycle.KafkaConfig;
import com.petalmd.armor.filter.lifecycle.LifeCycleMongoCodecProvider;
import com.petalmd.armor.util.ConfigConstants;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringSerializer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bson.codecs.configuration.CodecRegistries;
import org.bson.codecs.configuration.CodecRegistry;
import org.elasticsearch.common.component.AbstractLifecycleComponent;
import org.elasticsearch.common.settings.Settings;

import java.io.IOException;
import java.util.Optional;
import java.util.Properties;

/**
 * Created by jehuty0shift on 28/01/2020.
 */
public class KafkaService extends AbstractLifecycleComponent {

    private static final Logger log = LogManager.getLogger(KafkaService.class);
    private final Settings settings;
    private static Producer kafkaProducer = null;
    private KafkaConfig kafkaConfig;
    private boolean enabled;
    private String clientId;

    public KafkaService(final Settings settings, final MongoDBService mongoDBService) {
        this.settings = settings;
        enabled = settings.getAsBoolean(ConfigConstants.ARMOR_KAFKA_SERVICE_ENABLED, false) | mongoDBService.getEngineDatabase().isPresent();
        if (enabled) {
            CodecRegistry cR = CodecRegistries.fromRegistries(CodecRegistries.fromProviders(new LifeCycleMongoCodecProvider()), MongoClient.getDefaultCodecRegistry());
            MongoCollection<KafkaConfig> collection = mongoDBService.getEngineDatabase().get().withCodecRegistry(cR).getCollection("config").withDocumentClass(KafkaConfig.class);
            clientId = settings.get(ConfigConstants.ARMOR_KAFKA_SERVICE_CLIENT_ID);
            if(clientId == null) {
                clientId = "client-" + (int)(Math.random() * 100);
            }
            kafkaConfig = collection.find(Filters.eq("name", "configuration")).first();
            if (kafkaConfig == null || !kafkaConfig.isValid()) {
                log.debug("couldn't find any valid KafkaConfig with the current database {}");
                enabled = false;
            } else {
                log.info("KafkaService is enabled with the following bootstrap servers {}", kafkaConfig.bootstrapServers);
            }
        }
    }


    @Override
    protected void doStart() {
        //no-op
    }

    @Override
    protected void doStop() {
        //no-op
    }

    @Override
    protected void doClose() throws IOException {
        //no-op
    }


    public Optional<Producer> getKafkaProducer() {
        if (!enabled) {
            return Optional.empty();
        }


        if (kafkaProducer != null) {
            return Optional.of(kafkaProducer);
        }

        Properties props = new Properties();

        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, kafkaConfig.bootstrapServers);
        props.put(ProducerConfig.CLIENT_ID_CONFIG, clientId);
        props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());

        if(kafkaConfig.securityProtocol.equals("SASL_SSL")) {
            props.put("security.protocol", kafkaConfig.securityProtocol);
            props.put("sasl.mechanism", "PLAIN");
            final String jaasConfig = "org.apache.kafka.common.security.plain.PlainLoginModule required \n" +
                    "  username=\"" + kafkaConfig.SASLPlainUsername + "\" \n" +
                    "  password=\"" + kafkaConfig.SASLPlainPassword + "\"";
            props.put("sasl.jaas.config",jaasConfig);
        }

        props.put(ProducerConfig.ACKS_CONFIG,"all");

        kafkaProducer = new KafkaProducer<String, String>(props);

        log.info("Kafka Producer created");

        return Optional.of(kafkaProducer);

    }

    public String getTopicPrefix(){
        return kafkaConfig.topicPrefix;
    }


    public static void setKafkaProducer(final Producer newKafkaProducer) {
        kafkaProducer = newKafkaProducer;
    }

}
