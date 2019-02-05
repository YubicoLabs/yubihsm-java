package com.yubico.exceptions;

public class YubiHsmConnectionException extends Exception {

    private YubiHSMError errorCode;

    public YubiHsmConnectionException() {
        super("The connection to the YubiHSM failed");
        this.errorCode = null;
    }

    public YubiHsmConnectionException(final Throwable cause) {
        super("The connection to the YubiHSM failed", cause);
        this.errorCode = null;
    }

    public YubiHsmConnectionException(final YubiHSMError errorCode) {
        super("The connection to the YubiHSM failed. Error code: " + errorCode.toString());
        this.errorCode = errorCode;
    }

    public YubiHsmConnectionException(final YubiHSMError errorCode, final Throwable cause) {
        super("The connection to the YubiHSM failed. Error code: " + errorCode.toString(), cause);
        this.errorCode = errorCode;
    }

    public YubiHSMError getErrorCode() {
        return errorCode;
    }

}
