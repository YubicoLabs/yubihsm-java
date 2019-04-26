package com.yubico.exceptions;

public class YHConnectionException extends YHException {

    public YHConnectionException() {
        super("The connection to the YubiHsm failed");
    }

    public YHConnectionException(final Throwable cause) {
        super("The connection to the YubiHsm failed", cause);
    }

    public YHConnectionException(final YHError errorCode) {
        super(errorCode, "The connection to the YubiHsm failed. Error code: " + errorCode.toString());
    }

    public YHConnectionException(final YHError errorCode, final Throwable cause) {
        super(errorCode, "The connection to the YubiHsm failed. Error code: " + errorCode.toString(), cause);
    }

}
