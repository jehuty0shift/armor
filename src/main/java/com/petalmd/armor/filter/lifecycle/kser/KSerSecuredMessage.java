package com.petalmd.armor.filter.lifecycle.kser;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.goterl.lazycode.lazysodium.LazySodiumJava;
import com.goterl.lazycode.lazysodium.exceptions.SodiumException;
import com.goterl.lazycode.lazysodium.utils.Key;

import java.util.Base64;

/**
 * Created by jehuty0shift on 04/03/2020.
 */

public class KSerSecuredMessage {

    private final String data;

    private final String nonce;

    @JsonCreator
    public KSerSecuredMessage(@JsonProperty("data") final String data, @JsonProperty("nonce") final String nonce) {
        this.data = data;
        this.nonce = nonce;
    }

    public KSerSecuredMessage(final String clearMessage, final LazySodiumJava lsj, final byte[] privateKey) throws SodiumException {

        byte[] nonceBytes = lsj.nonce(24);
        data  = Base64.getEncoder().encodeToString(LazySodiumJava.toBin(lsj.cryptoSecretBoxEasy(clearMessage, nonceBytes, Key.fromBytes(privateKey))));
        nonce = Base64.getEncoder().encodeToString(nonceBytes);
    }

    @JsonProperty
    public String getData() {
        return data;
    }

    @JsonProperty
    public String getNonce() {
        return nonce;
    }
}
