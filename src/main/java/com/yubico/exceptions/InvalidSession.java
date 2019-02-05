package com.yubico.exceptions;

public class InvalidSession extends Exception {

    public InvalidSession() {
        super();
    }

    public InvalidSession(final Throwable cause) {
        super(cause);
    }

    public InvalidSession(final String message) {
        super(message);
    }

    public InvalidSession(final String message, final Throwable cause) {
        super(message, cause);
    }
}
