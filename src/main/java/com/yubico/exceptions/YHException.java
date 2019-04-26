package com.yubico.exceptions;

public class YHException extends Exception {

    YHError yhError;

    public YHException() {
        super();
        yhError = null;
    }

    public YHException(final String message) {
        super(message);
        yhError = null;
    }

    public YHException(final Throwable cause) {
        super(cause);
        yhError = null;
    }

    public YHException(final String message, final Throwable cause) {
        super(message, cause);
        yhError = null;
    }

    public YHException(final YHError error) {
        super();
        yhError = error;
    }

    public YHException(final YHError error, final String message) {
        super(message);
        yhError = error;
    }

    public YHException(final YHError error, final Throwable cause) {
        super(cause);
        yhError = error;
    }

    public YHException(final YHError error, final String message, final Throwable cause) {
        super(message, cause);
        yhError = error;
    }

    public YHError getYhError() {
        return yhError;
    }

    public void setYhError(final YHError error) {
        yhError = error;
    }
}
