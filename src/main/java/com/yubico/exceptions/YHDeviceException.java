package com.yubico.exceptions;

public class YHDeviceException extends YHException {

    public YHDeviceException(final YHError errorCode) {
        super(errorCode, "The YubiHsm returned error code " + errorCode.toString());
    }


    public YHDeviceException(final YHError errorCode, final Throwable cause) {
        super(errorCode, "The YubiHsm returned error code " + errorCode.toString(), cause);
    }

}