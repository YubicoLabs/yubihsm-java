package com.yubico.exceptions;

public class YHDeviceException extends Exception {

    private YHError errorCode;

    public YHDeviceException(final YHError errorCode) {
        super("The YubiHsm returned error code " + errorCode.toString());
        this.errorCode = errorCode;
    }


    public YHDeviceException(final YHError errorCode, final Throwable cause) {
        super("The YubiHsm returned error code " + errorCode.toString(), cause);
        this.errorCode = errorCode;
    }

    public YHError getErrorCode() {
        return errorCode;
    }

}