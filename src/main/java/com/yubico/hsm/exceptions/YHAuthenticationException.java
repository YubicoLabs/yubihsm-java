package com.yubico.hsm.exceptions;

import com.yubico.hsm.yhconcepts.YHError;

public class YHAuthenticationException extends YHException {

    public YHAuthenticationException(final String message) {
        super(message);
    }

    public YHAuthenticationException(final String message, final Throwable cause) {
        super(message, cause);
    }

    public YHAuthenticationException(final YHError errorCode) {
        super(errorCode, "Authentication failed. Error code: " + errorCode.toString());
    }

    public YHAuthenticationException(final YHError errorCode, final Throwable cause) {
        super(errorCode, "Authentication failed. Error code: " + errorCode.toString(), cause);
    }
}
