package com.yubico.exceptions;

import java.util.HashMap;
import java.util.Map;

/**
 * Error codes returned by the YubiHSM
 */
public class YubiHSMError {

    public static final YubiHSMError OK = new YubiHSMError((byte) 0x00, "Success");
    public static final YubiHSMError INVALID_COMMAND = new YubiHSMError((byte) 0x01, "Unknown command");
    public static final YubiHSMError INVALID_DATA = new YubiHSMError((byte) 0x02, "Malformed data for the command");
    public static final YubiHSMError INVALID_SESSION = new YubiHSMError((byte) 0x03, "The session has expired or does not exist");
    public static final YubiHSMError AUTHENTICATION_FAILED = new YubiHSMError((byte) 0x04, "Wrong Authentication Key");
    public static final YubiHSMError SESSIONS_FULL = new YubiHSMError((byte) 0x05, "No more available sessions");
    public static final YubiHSMError SESSION_FAILED = new YubiHSMError((byte) 0x06, "Session setup failed");
    public static final YubiHSMError STORAGE_FAILED = new YubiHSMError((byte) 0x07, "Storage full");
    public static final YubiHSMError WRONG_LENGTH = new YubiHSMError((byte) 0x08, "Wrong data length for the command");
    public static final YubiHSMError INSUFFICIENT_PERMISSIONS =
            new YubiHSMError((byte) 0x09, "Insufficient permissions for the command");
    public static final YubiHSMError LOG_FULL = new YubiHSMError((byte) 0x0a, "The log is full and force audit is enabled");
    public static final YubiHSMError OBJECT_NOT_FOUND =
            new YubiHSMError((byte) 0x0b, "No object found matching given ID and Type");
    public static final YubiHSMError INVALID_ID = new YubiHSMError((byte) 0x0c, "Specified ID is reserved");
    public static final YubiHSMError SSH_CA_CONSTRAINT_VIOLATION =
            new YubiHSMError((byte) 0x0e, "Constraints in SSH Template not met");
    public static final YubiHSMError INVALID_OTP = new YubiHSMError((byte) 0x0f, "OTP decryption failed");
    public static final YubiHSMError DEMO_MODE = new YubiHSMError((byte) 0x10, "Demo device must be power-cycled");
    public static final YubiHSMError OBJECT_EXISTS = new YubiHSMError((byte) 0x11, "Unable to overwrite object");

    private byte code;
    private String description;

    public YubiHSMError(final byte code, final String description) {
        this.code = code;
        this.description = description;
    }

    public byte getCode() {
        return code;
    }

    public String getDescription() {
        return description;
    }

    public boolean isOk() {
        return code == OK.getCode();
    }

    public static boolean isOk(final byte code) {
        return code == OK.getCode();
    }

    public static String getDescriptionFromCode(final byte code) {
        final YubiHSMError error = (YubiHSMError) getErrorsMap().get(code);
        if (error != null) {
            return error.getDescription();
        }
        return String.format("Error 0x%02X unknown", code);
    }

    public static YubiHSMError getYubiHSMError(final byte code) {
        return (YubiHSMError) getErrorsMap().get(code);
    }

    public static boolean isKnownError(final byte errorCode) {
        return getErrorsMap().containsKey(errorCode);
    }

    public String toString() {
        return String.format("0x%02X: " + description, code);
    }

    public boolean equals(final YubiHSMError other) {
        return this.getCode() == other.getCode();
    }

    private static Map getErrorsMap() {
        Map errors = new HashMap();
        errors.put((byte) 0x00, OK);
        errors.put((byte) 0x01, INVALID_COMMAND);
        errors.put((byte) 0x02, INVALID_DATA);
        errors.put((byte) 0x03, INVALID_SESSION);
        errors.put((byte) 0x04, AUTHENTICATION_FAILED);
        errors.put((byte) 0x05, SESSIONS_FULL);
        errors.put((byte) 0x06, SESSION_FAILED);
        errors.put((byte) 0x07, STORAGE_FAILED);
        errors.put((byte) 0x08, WRONG_LENGTH);
        errors.put((byte) 0x09, INSUFFICIENT_PERMISSIONS);
        errors.put((byte) 0x0a, LOG_FULL);
        errors.put((byte) 0x0b, OBJECT_NOT_FOUND);
        errors.put((byte) 0x0c, INVALID_ID);
        errors.put((byte) 0x0e, SSH_CA_CONSTRAINT_VIOLATION);
        errors.put((byte) 0x0f, INVALID_OTP);
        errors.put((byte) 0x10, DEMO_MODE);
        errors.put((byte) 0x11, OBJECT_EXISTS);
        return errors;
    }

}
