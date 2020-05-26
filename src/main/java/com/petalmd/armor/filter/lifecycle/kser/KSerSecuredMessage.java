package com.petalmd.armor.filter.lifecycle.kser;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.goterl.lazycode.lazysodium.LazySodiumJava;
import com.goterl.lazycode.lazysodium.exceptions.SodiumException;
import com.goterl.lazycode.lazysodium.interfaces.SecretBox;
import com.goterl.lazycode.lazysodium.utils.Key;

import java.util.Base64;

/**
 * Created by jehuty0shift on 04/03/2020.
 */

@JsonAutoDetect
public class KSerSecuredMessage {

    @JsonProperty
    private final String data;

    @JsonProperty
    private final String nonce;

    @JsonCreator
    public KSerSecuredMessage(@JsonProperty("data") final String data, @JsonProperty("nonce") final String nonce) {
        this.data = data;
        this.nonce = nonce;
    }

    public KSerSecuredMessage(final String clearMessage, final LazySodiumJava lazySodium, final Key privateKey) throws SodiumException {
        SecretBox.Lazy secretBox = (SecretBox.Lazy)lazySodium;
        byte[] nonceBytes = lazySodium.randomBytesBuf(SecretBox.NONCEBYTES);
        String secretMessage = secretBox.cryptoSecretBoxEasy(clearMessage, nonceBytes, privateKey);
        byte[] secretMessageBytes = lazySodium.toBinary(secretMessage);
        data = Base64.getEncoder().encodeToString(secretMessageBytes);
        nonce = Base64.getEncoder().encodeToString(nonceBytes);
    }

    public String getData() {
        return data;
    }

    public String getNonce() {
        return nonce;
    }
}
