package com.yubico.exceptions;

/**
 * Class representing errors returned by the device
 */
public class YHError {

    private final byte code;
    private final String description;

    /**
     * @param code        Error code
     * @param description Error description
     */
    private YHError(final byte code, final String description) {
        this.code = code;
        this.description = description;
    }

    /**
     * @return The error code
     */
    public byte getCode() {
        return code;
    }

    /**
     * @return The error description
     */
    public String getDescription() {
        return description;
    }

    /**
     * @return The error code and name as a formatted String
     */
    public String toString() {
        return String.format("0x%02X: " + description, code);
    }

    /**
     * Compares this error to another error
     *
     * @param other A YHError object
     * @return True of the two error codes are equal. False otherwise
     */
    public boolean equals(final YHError other) {
        return this.getCode() == other.getCode();
    }

    public int hashCode() {
        return super.hashCode();
    }

    /**
     * Returns the error whose code is specified
     *
     * @param code The error code
     * @return The error object whose code is specified
     */
    public static YHError getError(final byte code) {
        switch (code) {
            case 0x00:
                return OK;
            case 0x01:
                return INVALID_COMMAND;
            case 0x02:
                return INVALID_DATA;
            case 0x03:
                return INVALID_SESSION;
            case 0x04:
                return AUTHENTICATION_FAILED;
            case 0x05:
                return SESSIONS_FULL;
            case 0x06:
                return SESSION_FAILED;
            case 0x07:
                return STORAGE_FAILED;
            case 0x08:
                return WRONG_LENGTH;
            case 0x09:
                return INSUFFICIENT_PERMISSIONS;
            case 0x0a:
                return LOG_FULL;
            case 0x0b:
                return OBJECT_NOT_FOUND;
            case 0x0c:
                return INVALID_ID;
            case 0x0e:
                return SSH_CA_CONSTRAINT_VIOLATION;
            case 0x0f:
                return INVALID_OTP;
            case 0x10:
                return DEMO_MODE;
            case 0x11:
                return OBJECT_EXISTS;
            default:
                return new YHError(code, "Error unknown");
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
    /** Specified ID is reserved */
    public static final YHError INVALID_ID = new YHError((byte) 0x0c, "Specified ID is reserved");
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
