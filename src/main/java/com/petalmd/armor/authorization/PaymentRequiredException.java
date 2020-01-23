package com.petalmd.armor.authorization;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.common.logging.LoggerMessageFormat;
import org.elasticsearch.rest.RestStatus;

/**
 * Created by jehuty0shift on 23/01/2020.
 */
public class PaymentRequiredException extends ElasticsearchException {

    private static final long serialVersionUID = 9178276377400353891L;

    public PaymentRequiredException(String msg, Object... params) {
        super(LoggerMessageFormat.format(msg,params));
    }


    @Override
    public RestStatus status() {
        return RestStatus.PAYMENT_REQUIRED;
    }

}
