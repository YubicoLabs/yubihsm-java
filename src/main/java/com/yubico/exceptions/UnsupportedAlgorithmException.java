package com.yubico.exceptions;

public class UnsupportedAlgorithmException extends Exception {

    public UnsupportedAlgorithmException() {
        super();
    }

    public UnsupportedAlgorithmException(final Throwable cause) {
        super(cause);
    }

    public UnsupportedAlgorithmException(final String message) {
        super(message);
    }

    public UnsupportedAlgorithmException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
