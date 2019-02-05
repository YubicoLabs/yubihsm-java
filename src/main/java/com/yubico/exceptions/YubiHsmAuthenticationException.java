package com.yubico.exceptions;

public class YubiHsmAuthenticationException extends Exception {

    private YubiHSMError errorCode;

    public YubiHsmAuthenticationException(final String message) {
        super(message);
    }

    public YubiHsmAuthenticationException(final String message, final Throwable cause) {
        super(message, cause);
    }

    public YubiHsmAuthenticationException(final YubiHSMError errorCode) {
        super("Authentication failed. Error code: " + errorCode.toString());
        this.errorCode = errorCode;
    }

    public YubiHsmAuthenticationException(final YubiHSMError errorCode, final Throwable cause) {
        super("Authentication failed. Error code: " + errorCode.toString(), cause);
        this.errorCode = errorCode;
    }

    public YubiHsmAuthenticationException(final String message, final YubiHSMError errorCode) {
        super(message + ". Error code: " + errorCode.toString());
        this.errorCode = errorCode;
    }

    public YubiHsmAuthenticationException(final String message, final YubiHSMError errorCode, final Throwable cause) {
        super(message + ". Error code: " + errorCode.toString(), cause);
        this.errorCode = errorCode;
    }

    public YubiHSMError getErrorCode() {
        return errorCode;
    }

}
