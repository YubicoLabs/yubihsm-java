package com.yubico.exceptions;

public class InvalidSessionException extends Exception {

    public InvalidSessionException() {
        super();
    }

    public InvalidSessionException(final Throwable cause) {
        super(cause);
    }

    public InvalidSessionException(final String message) {
        super(message);
    }

    public InvalidSessionException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
