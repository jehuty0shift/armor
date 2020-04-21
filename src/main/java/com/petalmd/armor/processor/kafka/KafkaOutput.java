package com.petalmd.armor.processor.kafka;

import com.petalmd.armor.processor.LDPGelf;

public interface KafkaOutput {

     void initialize();

     void sendLDPGelf(final LDPGelf ldpGelf);

     void flush();

     void close();

}