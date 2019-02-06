package com.yubico.exceptions;

public class YHAuthenticationException extends Exception {

    private YHError errorCode;

    public YHAuthenticationException(final String message) {
        super(message);
    }

    public YHAuthenticationException(final String message, final Throwable cause) {
        super(message, cause);
    }

    public YHAuthenticationException(final YHError errorCode) {
        super("Authentication failed. Error code: " + errorCode.toString());
        this.errorCode = errorCode;
    }

    public YHAuthenticationException(final YHError errorCode, final Throwable cause) {
        super("Authentication failed. Error code: " + errorCode.toString(), cause);
        this.errorCode = errorCode;
    }

    public YHAuthenticationException(final String message, final YHError errorCode) {
        super(message + ". Error code: " + errorCode.toString());
        this.errorCode = errorCode;
    }

    public YHAuthenticationException(final String message, final YHError errorCode, final Throwable cause) {
        super(message + ". Error code: " + errorCode.toString(), cause);
        this.errorCode = errorCode;
    }

    public YHError getErrorCode() {
        return errorCode;
    }

}
