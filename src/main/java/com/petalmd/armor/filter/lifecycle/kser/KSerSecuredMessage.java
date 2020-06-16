package com.petalmd.armor.filter.lifecycle.kser;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.abstractj.kalium.crypto.Random;
import org.abstractj.kalium.crypto.SecretBox;

import java.security.AccessController;
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

    public KSerSecuredMessage(final String clearMessage, final SecretBox secretBox) {

        Random randomGen = new Random();
        byte[] nonceBytes = randomGen.randomBytes(24);
        byte[] secretMessageBytes = secretBox.encrypt(nonceBytes, clearMessage.getBytes());
        data = Base64.getEncoder().encodeToString(secretMessageBytes);
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