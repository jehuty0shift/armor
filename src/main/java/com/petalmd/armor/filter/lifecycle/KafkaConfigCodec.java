package com.petalmd.armor.filter.lifecycle;

import com.mongodb.MongoClient;
import org.bson.BsonReader;
import org.bson.BsonWriter;
import org.bson.Document;
import org.bson.codecs.Codec;
import org.bson.codecs.DecoderContext;
import org.bson.codecs.DocumentCodec;
import org.bson.codecs.EncoderContext;

/**
 * Created by jehuty0shift on 23/01/2020.
 */
public class KafkaConfigCodec implements Codec<KafkaConfig> {

    private final Codec<Document> documentCodec;


    public KafkaConfigCodec() {documentCodec = new DocumentCodec((MongoClient.getDefaultCodecRegistry()));}


    @Override
    public KafkaConfig decode(BsonReader bsonReader, DecoderContext decoderContext) {
        Document document = documentCodec.decode(bsonReader, decoderContext);

        KafkaConfig kafkaConfig = new KafkaConfig();
        Document dict = document.get("_dict", Document.class);
        kafkaConfig.topicPrefix = dict.getString("KSER_TOPIC_PREFIX");
        Document kSerProducerConfig = dict.get("KSER_PRODUCER_CONFIG",Document.class);
        kafkaConfig.bootstrapServers = kSerProducerConfig.getString("BOOTSTRAP_SERVERS");
        kafkaConfig.SASLMechanism = kSerProducerConfig.getString("SASL_MECHANISM");
        kafkaConfig.SASLPlainUsername = kSerProducerConfig.getString("SASL_PLAIN_USERNAME");
        kafkaConfig.SASLPlainPassword = kSerProducerConfig.getString("SASL_PLAIN_PASSWORD");
        kafkaConfig.securityProtocol = kSerProducerConfig.getString("SECURITY_PROTOCOL");
        kafkaConfig.SASLMechanism = kSerProducerConfig.getString("SASL_MECHANISM");
        kafkaConfig.kSerPrivateKey = dict.getString("KSER_SECRETBOX_KEY");
        if (kafkaConfig.kSerPrivateKey == null) {
            kafkaConfig.kSerPrivateKey = "";
        }
        return kafkaConfig;
    }

    @Override
    public void encode(BsonWriter bsonWriter, KafkaConfig kafkaConfig, EncoderContext encoderContext) {
        //No need
    }

    @Override
    public Class<KafkaConfig> getEncoderClass() {
        return KafkaConfig.class;
    }
}
