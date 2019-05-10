package com.yubico.hsm.yhconcepts;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Class representing errors returned by the device
 */
public enum YHError {

    /** Operation successful */
    OK((byte) 0x00, "Success"),
    /** Command unknown */
    INVALID_COMMAND            ((byte) 0x01, "Unknown command"),
    /** Malformed data for the command */
    INVALID_DATA               ((byte) 0x02, "Malformed data for the command"),
    /** The session has expired or does not exist */
    INVALID_SESSION            ((byte) 0x03, "The session has expired or does not exist"),
    /** Wrong Authentication Key */
    AUTHENTICATION_FAILED      ((byte) 0x04, "Wrong Authentication Key"),
    /** No more available sessions */
    SESSIONS_FULL              ((byte) 0x05, "No more available sessions"),
    /** Session setup failed */
    SESSION_FAILED             ((byte) 0x06, "Session setup failed"),
    /** Storage full */
    STORAGE_FAILED             ((byte) 0x07, "Storage full"),
    /** Wrong data length for the command */
    WRONG_LENGTH               ((byte) 0x08, "Wrong data length for the command"),
    /** Insufficient permissions for the command */
    INSUFFICIENT_PERMISSIONS   ((byte) 0x09, "Insufficient permissions for the command"),
    /** The log is full and force audit is enabled */
    LOG_FULL                   ((byte) 0x0a, "The log is full and force audit is enabled"),
    /** No object found matching given ID and Type */
    OBJECT_NOT_FOUND           ((byte) 0x0b, "No object found matching given ID and Type"),
    /** Invalid ID */
    INVALID_ID                 ((byte) 0x0c, "Invalid ID"),
    /** Constraints in SSH Template not met */
    SSH_CA_CONSTRAINT_VIOLATION((byte) 0x0e, "Constraints in SSH Template not met"),
    /** OTP decryption failed */
    INVALID_OTP                ((byte) 0x0f, "OTP decryption failed"),
    /** Demo device must be power-cycled */
    DEMO_MODE                  ((byte) 0x10, "Demo device must be power-cycled"),
    /** Unable to overwrite object */
    OBJECT_EXISTS              ((byte) 0x11, "Unable to overwrite object");

    private final byte errorCode;
    private final String description;

    YHError(final byte code, final String description) {
        this.errorCode = code;
        this.description = description;
    }

    public byte getErrorCode() {
        return errorCode;
    }

    public String getDescription() {
        return description;
    }

    private static final Map<Byte, YHError> BY_VALUE_MAP = new LinkedHashMap<Byte, YHError>();

    static {
        for (YHError err : YHError.values()) {
            BY_VALUE_MAP.put(err.getErrorCode(), err);
        }
    }

    public static YHError forId(byte id) {
        return BY_VALUE_MAP.get(id);
    }

    @Override
    public String toString() {
        return String.format("0x%02x:%s", errorCode, description);
    }

}
