package com.yubico.exceptions;

public class YHInvalidResponseException extends YHException {

    public YHInvalidResponseException(final String message) {
        super(message);
    }


    public YHInvalidResponseException(final YHError errorCode) {
        super(errorCode, "The YubiHsm returned an unexpected response. " + errorCode.toString());
    }

    public YHInvalidResponseException(final YHError errorCode, final Throwable cause) {
        super(errorCode, "The YubiHsm returned an unexpected response. " + errorCode.toString(), cause);
    }

}
