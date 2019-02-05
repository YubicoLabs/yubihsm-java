package com.yubico.exceptions;

public class YubiHsmInvalidResponseException extends Exception {

    private YubiHSMError errorCode;

    public YubiHsmInvalidResponseException(final String message) {
        super(message);
        this.errorCode = null;
    }


    public YubiHsmInvalidResponseException(final YubiHSMError errorCode) {
        super("The YubiHSM returned an unexpected response. " + errorCode.toString());
        this.errorCode = errorCode;
    }

    public YubiHsmInvalidResponseException(final YubiHSMError errorCode, final Throwable cause) {
        super("The YubiHSM returned an unexpected response. " + errorCode.toString(), cause);
        this.errorCode = errorCode;
    }

    public YubiHSMError getErrorCode() {
        return errorCode;
    }

}
