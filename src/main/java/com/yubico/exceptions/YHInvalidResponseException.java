package com.yubico.exceptions;

public class YHInvalidResponseException extends Exception {

    private YHError errorCode;

    public YHInvalidResponseException(final String message) {
        super(message);
        this.errorCode = null;
    }


    public YHInvalidResponseException(final YHError errorCode) {
        super("The YubiHsm returned an unexpected response. " + errorCode.toString());
        this.errorCode = errorCode;
    }

    public YHInvalidResponseException(final YHError errorCode, final Throwable cause) {
        super("The YubiHsm returned an unexpected response. " + errorCode.toString(), cause);
        this.errorCode = errorCode;
    }

    public YHError getErrorCode() {
        return errorCode;
    }

}
