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
public class EngineUserCodec implements Codec<EngineUser> {

    private final Codec<Document> documentCodec;


    public EngineUserCodec() {documentCodec = new DocumentCodec((MongoClient.getDefaultCodecRegistry()));}


    @Override
    public EngineUser decode(BsonReader bsonReader, DecoderContext decoderContext) {
        Document document = documentCodec.decode(bsonReader, decoderContext);

        EngineUser engineUser = new EngineUser();

        engineUser.username = document.getString("username");
        engineUser.trusted = document.getBoolean("trusted",false);
        engineUser.region = Region.EU.value.equals(document.getString("region"))?Region.EU:Region.CA;

        return engineUser;
    }

    @Override
    public void encode(BsonWriter bsonWriter, EngineUser engineUser, EncoderContext encoderContext) {
        //No need
    }

    @Override
    public Class<EngineUser> getEncoderClass() {
        return EngineUser.class;
    }
}
