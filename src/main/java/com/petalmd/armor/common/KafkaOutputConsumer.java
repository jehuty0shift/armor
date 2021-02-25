package com.petalmd.armor.common;

import com.petalmd.armor.common.KafkaOutput;
import com.petalmd.armor.common.LDPGelf;

import java.util.function.Consumer;

public class KafkaOutputConsumer implements KafkaOutput {

    private Consumer<LDPGelf> gelfConsumer;


    public KafkaOutputConsumer(Consumer<LDPGelf> gelfConsumer) {
        this.gelfConsumer = gelfConsumer;
    }


    public void setConsumer(Consumer<LDPGelf> gelfConsumer) {
        this.gelfConsumer = gelfConsumer;
    }

    @Override
    public void initialize() {
        //NO-OP
    }

    @Override
    public void flush() {
        //NO-OP
    }

    @Override
    public void close() {
        //NO-OP
    }

    @Override
    public void sendLDPGelf(LDPGelf ldpGelf) {
        gelfConsumer.accept(ldpGelf);
    }
}
