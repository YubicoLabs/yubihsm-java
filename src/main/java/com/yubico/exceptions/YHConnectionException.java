package com.yubico.exceptions;

public class YHConnectionException extends Exception {

    private YHError errorCode;

    public YHConnectionException() {
        super("The connection to the YubiHsm failed");
        this.errorCode = null;
    }

    public YHConnectionException(final Throwable cause) {
        super("The connection to the YubiHsm failed", cause);
        this.errorCode = null;
    }

    public YHConnectionException(final YHError errorCode) {
        super("The connection to the YubiHsm failed. Error code: " + errorCode.toString());
        this.errorCode = errorCode;
    }

    public YHConnectionException(final YHError errorCode, final Throwable cause) {
        super("The connection to the YubiHsm failed. Error code: " + errorCode.toString(), cause);
        this.errorCode = errorCode;
    }

    public YHError getErrorCode() {
        return errorCode;
    }

}
