package com.yubico.exceptions;

/**
 * Class representing errors returned by the device
 */
public class YHError {

    private final byte errorCcode;
    private final String description;

    private YHError(final byte code, final String description) {
        this.errorCcode = code;
        this.description = description;
    }

    public byte getErrorCode() {
        return errorCcode;
    }

    public String getDescription() {
        return description;
    }

    /**
     * @return The error code and name as a formatted String
     */
    public String toString() {
        return String.format("0x%02X: " + description, errorCcode);
    }

    /**
     * Compares this error to another error
     *
     * @param other Another YHError object
     * @return True if the error codes of both objects are equal. False otherwise
     */
    public boolean equals(final YHError other) {
        return this.getErrorCode() == other.getErrorCode();
    }

    public int hashCode() {
        return errorCcode;
    }

    /**
     * Returns the YHError object with the specified error code
     *
     * @param errorCode A recognized error code
     * @return An YHError object
     */
    public static YHError getError(final byte errorCode) {
        switch (errorCode) {
            case 0x00: return OK;
            case 0x01: return INVALID_COMMAND;
            case 0x02: return INVALID_DATA;
            case 0x03: return INVALID_SESSION;
            case 0x04: return AUTHENTICATION_FAILED;
            case 0x05: return SESSIONS_FULL;
            case 0x06: return SESSION_FAILED;
            case 0x07: return STORAGE_FAILED;
            case 0x08: return WRONG_LENGTH;
            case 0x09: return INSUFFICIENT_PERMISSIONS;
            case 0x0a: return LOG_FULL;
            case 0x0b: return OBJECT_NOT_FOUND;
            case 0x0c: return INVALID_ID;
            case 0x0e: return SSH_CA_CONSTRAINT_VIOLATION;
            case 0x0f: return INVALID_OTP;
            case 0x10: return DEMO_MODE;
            case 0x11: return OBJECT_EXISTS;
            default: return new YHError(errorCode, "Error unknown");
        }
    }

    /** Operation successful */
    public static final YHError OK = new YHError((byte) 0x00, "Success");
    /** Command unknown */
    public static final YHError INVALID_COMMAND = new YHError((byte) 0x01, "Unknown command");
    /** Malformed data for the command */
    public static final YHError INVALID_DATA = new YHError((byte) 0x02, "Malformed data for the command");
    /** The session has expired or does not exist */
    public static final YHError INVALID_SESSION = new YHError((byte) 0x03, "The session has expired or does not exist");
    /** Wrong Authentication Key */
    public static final YHError AUTHENTICATION_FAILED = new YHError((byte) 0x04, "Wrong Authentication Key");
    /** No more available sessions */
    public static final YHError SESSIONS_FULL = new YHError((byte) 0x05, "No more available sessions");
    /** Session setup failed */
    public static final YHError SESSION_FAILED = new YHError((byte) 0x06, "Session setup failed");
    /** Storage full */
    public static final YHError STORAGE_FAILED = new YHError((byte) 0x07, "Storage full");
    /** Wrong data length for the command */
    public static final YHError WRONG_LENGTH = new YHError((byte) 0x08, "Wrong data length for the command");
    /** Insufficient permissions for the command */
    public static final YHError INSUFFICIENT_PERMISSIONS =
            new YHError((byte) 0x09, "Insufficient permissions for the command");
    /** The log is full and force audit is enabled */
    public static final YHError LOG_FULL = new YHError((byte) 0x0a, "The log is full and force audit is enabled");
    /** No object found matching given ID and Type */
    public static final YHError OBJECT_NOT_FOUND =
            new YHError((byte) 0x0b, "No object found matching given ID and Type");
    /** Invalid ID */
    public static final YHError INVALID_ID = new YHError((byte) 0x0c, "Invalid ID");
    /** Constraints in SSH Template not met */
    public static final YHError SSH_CA_CONSTRAINT_VIOLATION =
            new YHError((byte) 0x0e, "Constraints in SSH Template not met");
    /** OTP decryption failed */
    public static final YHError INVALID_OTP = new YHError((byte) 0x0f, "OTP decryption failed");
    /** Demo device must be power-cycled */
    public static final YHError DEMO_MODE = new YHError((byte) 0x10, "Demo device must be power-cycled");
    /** Unable to overwrite object */
    public static final YHError OBJECT_EXISTS = new YHError((byte) 0x11, "Unable to overwrite object");

}
