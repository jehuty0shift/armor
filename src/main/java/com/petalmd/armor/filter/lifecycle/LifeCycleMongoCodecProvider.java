package com.petalmd.armor.filter.lifecycle;

import org.bson.codecs.Codec;
import org.bson.codecs.configuration.CodecProvider;
import org.bson.codecs.configuration.CodecRegistry;

/**
 * Created by jehuty0shift on 23/01/2020.
 */
public class LifeCycleMongoCodecProvider implements CodecProvider {

    public LifeCycleMongoCodecProvider() {
    }

    @Override
    public <T> Codec<T> get(Class<T> aClass, CodecRegistry codecRegistry) {
        if(aClass == EngineUser.class) {
            return (Codec<T>) new EngineUserCodec();
        }
        if (aClass == KafkaConfig.class) {
            return (Codec<T>) new KafkaConfigCodec();
        }
        return null;
    }

}
