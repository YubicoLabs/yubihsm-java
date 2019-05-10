package com.yubico.hsm.exceptions;

import com.yubico.hsm.yhconcepts.YHError;

public class YHDeviceException extends YHException {

    public YHDeviceException(final YHError errorCode) {
        super(errorCode, "The YubiHsm returned error code " + errorCode.toString());
    }


    public YHDeviceException(final YHError errorCode, final Throwable cause) {
        super(errorCode, "The YubiHsm returned error code " + errorCode.toString(), cause);
    }

}