package com.yubico.exceptions;

public class YubiHsmDeviceException extends Exception {

    private YubiHSMError errorCode;

    public YubiHsmDeviceException(final YubiHSMError errorCode) {
        super("The YubiHSM returned error code " + errorCode.toString());
        this.errorCode = errorCode;
    }


    public YubiHsmDeviceException(final YubiHSMError erroCode, final Throwable cause) {
        super("The YubiHSM returned error code " + erroCode.toString(), cause);
        this.errorCode = erroCode;
    }

    public YubiHSMError getErrorCode() {
        return errorCode;
    }

}