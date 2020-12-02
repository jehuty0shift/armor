package com.petalmd.armor.service;

import com.goterl.lazycode.lazysodium.LazySodiumJava;
import com.goterl.lazycode.lazysodium.SodiumJava;
import com.goterl.lazycode.lazysodium.exceptions.SodiumException;
import com.mongodb.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Filters;
import com.petalmd.armor.filter.lifecycle.KafkaConfig;
import com.petalmd.armor.filter.lifecycle.LifeCycleMongoCodecProvider;
import com.petalmd.armor.filter.lifecycle.kser.KSerSecuredMessage;
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
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Created by jehuty0shift on 28/01/2020.
 */
public class KafkaService extends AbstractLifecycleComponent {

    private static final Logger log = LogManager.getLogger(KafkaService.class);
    private static Producer kafkaProducer = null;
    private final List<String> topicList;
    private final LazySodiumJava lsj;
    private final byte[] enginePrivateKey;
    private KafkaConfig kafkaConfig;
    private boolean enabled;
    private String clientId;


    public KafkaService(final Settings settings, final MongoDBService mongoDBService) {
        enabled = settings.getAsBoolean(ConfigConstants.ARMOR_KAFKA_ENGINE_SERVICE_ENABLED, false) | mongoDBService.getEngineDatabase().isPresent();
        topicList = new ArrayList<>();
        if (enabled) {
            CodecRegistry cR = CodecRegistries.fromRegistries(CodecRegistries.fromProviders(new LifeCycleMongoCodecProvider()), MongoClient.getDefaultCodecRegistry());
            MongoCollection<KafkaConfig> collection = AccessController.doPrivileged((PrivilegedAction<MongoCollection>) () ->
                    mongoDBService.getEngineDatabase().get().withCodecRegistry(cR).getCollection("config").withDocumentClass(KafkaConfig.class)
            );
            clientId = settings.get(ConfigConstants.ARMOR_KAFKA_ENGINE_SERVICE_CLIENT_ID);
            if (clientId == null) {
                clientId = "client-" + Double.valueOf(Math.random()).intValue();
            }
            kafkaConfig = AccessController.doPrivileged((PrivilegedAction<KafkaConfig>) () -> collection.find(Filters.eq("name", "configuration")).first());
            if (kafkaConfig == null || !kafkaConfig.isValid()) {
                log.debug("couldn't find any valid KafkaConfig with the current database {}");
                enabled = false;
            } else {
                log.info("KafkaService is enabled with the following bootstrap servers {}", kafkaConfig.bootstrapServers);
            }

            enginePrivateKey = Base64.getDecoder().decode(settings.get(ConfigConstants.ARMOR_KAFKA_ENGINE_SERVICE_PRIVATE_KEY, kafkaConfig==null?"":kafkaConfig.kSerPrivateKey));
            //This one should be wrapped also

            lsj = AccessController.doPrivileged((PrivilegedAction<LazySodiumJava>) () -> {
                        final SodiumJava sodium = new SodiumJava();
                        return new LazySodiumJava(sodium);
                    }
            );

            if (lsj == null) {
                enabled = false;
            }
            final String topicSuffix = settings.get(ConfigConstants.ARMOR_KAFKA_ENGINE_SERVICE_TOPIC_SUFFIX, "api.ms2015");
            final List<String> regionsList = settings.getAsList(ConfigConstants.ARMOR_KAFKA_ENGINE_SERVICE_TOPIC_REGIONS, List.of("eu", "ca"));
            topicList.addAll(regionsList.stream().map(r -> kafkaConfig.topicPrefix + "." + topicSuffix + "." + r).collect(Collectors.toList()));
        } else {
            lsj = null;
            enginePrivateKey = null;
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

    public List<String> getTopicList() {
        return topicList;
    }

    public synchronized Optional<Producer> getKafkaProducer() {
        if (!enabled) {
            return Optional.empty();
        }


        if (kafkaProducer != null) {
            return Optional.of(kafkaProducer);
        }

        Properties props = new Properties();

        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, kafkaConfig.bootstrapServers);
        props.put(ProducerConfig.CLIENT_ID_CONFIG, clientId);

        if (kafkaConfig.securityProtocol.equals("SASL_SSL")) {
            props.put("security.protocol", kafkaConfig.securityProtocol);
            props.put("sasl.mechanism", "PLAIN");
            final String jaasConfig = "org.apache.kafka.common.security.plain.PlainLoginModule required \n" +
                    "  username=\"" + kafkaConfig.SASLPlainUsername + "\" \n" +
                    "  password=\"" + kafkaConfig.SASLPlainPassword + "\";";
            props.put("sasl.jaas.config", jaasConfig);
            //JAVA_HOME/jre/lib/security/cacerts.
            //make it available as an option
            props.put("ssl.truststore.location", System.getenv("JAVA_HOME") + "/lib/security/cacerts");
            props.put("ssl.truststore.password", "changeit");
            //Insecure will have to set it as an option
            props.put("ssl.endpoint.identification.algorithm", "");
        }

        props.put(ProducerConfig.ACKS_CONFIG, "all");

        kafkaProducer = AccessController.doPrivileged((PrivilegedAction<KafkaProducer>) () -> {
            //This is necessary to force the Kafka Serializer loader to use the classloader used to load kafkaProducer classes
            props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
            props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
//            Thread.currentThread().setContextClassLoader(null);
            Thread.currentThread().setContextClassLoader(KafkaProducer.class.getClassLoader());
            return new KafkaProducer<String, String>(props);
        });

        log.info("Kafka Producer created");

        return Optional.of(kafkaProducer);

    }

    public String getTopicPrefix() {
        return kafkaConfig.topicPrefix;
    }


    public static void setKafkaProducer(final Producer newKafkaProducer) {
        kafkaProducer = newKafkaProducer;
    }


    public KSerSecuredMessage buildKserSecuredMessage(final String message) throws SodiumException{
            return new KSerSecuredMessage(message, lsj, enginePrivateKey);
    }


}
