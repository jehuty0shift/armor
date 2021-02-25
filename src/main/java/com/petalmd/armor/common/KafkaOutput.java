package com.petalmd.armor.common;

public interface KafkaOutput {

     void initialize();

     void sendLDPGelf(final LDPGelf ldpGelf);

     void flush();

     void close();

}