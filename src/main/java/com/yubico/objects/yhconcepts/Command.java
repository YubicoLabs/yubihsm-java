package com.yubico.objects.yhconcepts;

/**
 * Class representing commands that are recognized by the device
 */
public class Command extends YHConcept {

    private Command(final byte id, final String name) {
        super(id, name);
    }

    public byte getCommandId() {
        return (byte) getId();
    }

    /**
     * Return the expected response code in case of a successful execution of this command
     */
    public byte getCommandResponse() {
        return (byte) (getCommandId() | 0x80);
    }

    /**
     * Returns whether a command code represents an error
     *
     * @param command The command code to check
     * @return True if the command code represents an error response code. False otherwise
     */
    public static boolean isError(final byte command) {
        return command == ERROR.getCommandId();
    }

    public String toString() {
        return String.format("0x%02X: " + getName(), getCommandId());
    }

    /**
     * Compares this command with another command object
     *
     * @param other Another Command object
     * @return True of this command code equals the other command's code. False otherwise
     */
    public boolean equals(final Command other) {
        if(other == null) {
            return false;
        }
        return this.getCommandId() == other.getCommandId();
    }

    /**
     * Return the Command object with the specified ID
     *
     * @param id The command code
     * @return The Command object whose ID is `id`. Null if the ID is not recognized
     */
    public static Command getCommand(final byte id) {
        switch (id) {
            case 0x01: return ECHO;
            case 0x03: return CREATE_SESSION;
            case 0x04: return AUTHENTICATE_SESSION;
            case 0x05: return SESSION_MESSAGE;
            case 0x06: return DEVICE_INFO;
            case 0x08: return RESET_DEVICE;
            case 0x40: return CLOSE_SESSION;
            case 0x41: return GET_STORAGE_INFO;
            case 0x42: return PUT_OPAQUE;
            case 0x43: return GET_OPAQUE;
            case 0x44: return PUT_AUTHENTICATION_KEY;
            case 0x45: return PUT_ASYMMETRIC_KEY;
            case 0x46: return GENERATE_ASYMMETRIC_KEY;
            case 0x47: return SIGN_PKCS1;
            case 0x48: return LIST_OBJECTS;
            case 0x49: return DECRYPT_PKCS1;
            case 0x4a: return EXPORT_WRAPPED;
            case 0x4b: return IMPORT_WRAPPED;
            case 0x4c: return PUT_WRAP_KEY;
            case 0x4d: return GET_LOG_ENTRIES;
            case 0x4e: return GET_OBJECT_INFO;
            case 0x4f: return SET_OPTION;
            case 0x50: return GET_OPTION;
            case 0x51: return GET_PSEUDO_RANDOM;
            case 0x52: return PUT_HMAC_KEY;
            case 0x53: return SIGN_HMAC;
            case 0x54: return GET_PUBLIC_KEY;
            case 0x55: return SIGN_PSS;
            case 0x56: return SIGN_ECDSA;
            case 0x57: return DERIVE_ECDH;
            case 0x58: return DELETE_OBJECT;
            case 0x59: return DECRYPT_OAEP;
            case 0x5a: return GENERATE_HMAC_KEY;
            case 0x5b: return GENERATE_WRAP_KEY;
            case 0x5c: return VERIFY_HMAC;
            case 0x5d: return SIGN_SSH_CERTIFICATE;
            case 0x5e: return PUT_TEMPLATE;
            case 0x5f: return GET_TEMPLATE;
            case 0x60: return DECRYPT_OTP;
            case 0x61: return CREATE_OTP_AEAD;
            case 0x62: return RANDOMIZE_OTP_AEAD;
            case 0x63: return REWRAP_OTP_AEAD;
            case 0x64: return SIGN_ATTESTATION_CERTIFICATE;
            case 0x65: return PUT_OTP_AEAD_KEY;
            case 0x66: return GENERATE_OTP_AEAD_KEY;
            case 0x67: return SET_LOG_INDEX;
            case 0x68: return WRAP_DATA;
            case 0x69: return UNWRAP_DATA;
            case 0x6a: return SIGN_EDDSA;
            case 0x6b: return BLINK_DEVICE;
            case 0x6c: return CHANGE_AUTHENTICATION_KEY;
            case 0x7f: return ERROR;
            default: return null;
        }

    }

    /** Echo the command input */
    public static final Command ECHO = new Command((byte) 0x01, "Echo");
    /** Create Session */
    public static final Command CREATE_SESSION = new Command((byte) 0x03, "Create Session");
    /** Authenticate Session */
    public static final Command AUTHENTICATE_SESSION = new Command((byte) 0x04, "Authenticate Session");
    /** Send encrypted message to the device */
    public static final Command SESSION_MESSAGE = new Command((byte) 0x05, "Session Message");
    /** Get Device Info */
    public static final Command DEVICE_INFO = new Command((byte) 0x06, "Get Device Info");
    /** Reset Device */
    public static final Command RESET_DEVICE = new Command((byte) 0x08, "Reset Device");
    /** Close Session */
    public static final Command CLOSE_SESSION = new Command((byte) 0x40, "Close Session");
    /** Get Storage Info */
    public static final Command GET_STORAGE_INFO = new Command((byte) 0x041, "Get Storage Info");
    /** Import Opaque object */
    public static final Command PUT_OPAQUE = new Command((byte) 0x42, "Put Opaque");
    /** Get Opaque object */
    public static final Command GET_OPAQUE = new Command((byte) 0x43, "Get Opaque");
    /** Import Authentication Key */
    public static final Command PUT_AUTHENTICATION_KEY = new Command((byte) 0x44, "Put Authentication Key");
    /** Import Asymmetric Key */
    public static final Command PUT_ASYMMETRIC_KEY = new Command((byte) 0x45, "Put Asymmetric Key");
    /** Generate Asymmetric Key */
    public static final Command GENERATE_ASYMMETRIC_KEY = new Command((byte) 0x46, "Generate Asymmetric Key");
    /** Sign using Pkcs1 */
    public static final Command SIGN_PKCS1 = new Command((byte) 0x47, "Sign Pkcs1");
    /** List Objects */
    public static final Command LIST_OBJECTS = new Command((byte) 0x48, "List Objects");
    /** Decrypt using Pkcs1 */
    public static final Command DECRYPT_PKCS1 = new Command((byte) 0x49, "Decrypt Pkcs1");
    /** Export Wrapped object */
    public static final Command EXPORT_WRAPPED = new Command((byte) 0x4a, "Export Wrapped");
    /** Import Wrapped object */
    public static final Command IMPORT_WRAPPED = new Command((byte) 0x4b, "Import Wrapped");
    /** Import Wrap Key */
    public static final Command PUT_WRAP_KEY = new Command((byte) 0x4c, "Put Wrap Key");
    /** Get Log Entries */
    public static final Command GET_LOG_ENTRIES = new Command((byte) 0x4d, "Get Log Entries");
    /** Get Object Info */
    public static final Command GET_OBJECT_INFO = new Command((byte) 0x4e, "Get Object Info");
    /** Set device option */
    public static final Command SET_OPTION = new Command((byte) 0x4f, "Set Option");
    /** Get device option */
    public static final Command GET_OPTION = new Command((byte) 0x50, "Get Option");
    /** Get Pseudo Random bytes */
    public static final Command GET_PSEUDO_RANDOM = new Command((byte) 0x51, "Get Pseudo Random");
    /** Import Hmac Key */
    public static final Command PUT_HMAC_KEY = new Command((byte) 0x52, "Put Hmac Key");
    /** Sign using Hmac */
    public static final Command SIGN_HMAC = new Command((byte) 0x53, "Sign Hmac");
    /** Get Public Key */
    public static final Command GET_PUBLIC_KEY = new Command((byte) 0x54, "Get Public Key");
    /** Sign using Pss */
    public static final Command SIGN_PSS = new Command((byte) 0x55, "Sign Pss");
    /** Sign using Ecdsa */
    public static final Command SIGN_ECDSA = new Command((byte) 0x56, "Sign Ecdsa");
    /** Derive Ecdh */
    public static final Command DERIVE_ECDH = new Command((byte) 0x57, "Derive Ecdh");
    /** Delete Object */
    public static final Command DELETE_OBJECT = new Command((byte) 0x58, "Delete Object");
    /** Decrypt Oaep */
    public static final Command DECRYPT_OAEP = new Command((byte) 0x59, "Decrypt Oaep");
    /** Generate Hmac Key */
    public static final Command GENERATE_HMAC_KEY = new Command((byte) 0x5a, "Generate Hmac Key");
    /** Generate Wrap Key */
    public static final Command GENERATE_WRAP_KEY = new Command((byte) 0x5b, "Generate Wrap Key");
    /** Verify Hmac */
    public static final Command VERIFY_HMAC = new Command((byte) 0x5c, "Verify Hmac");
    /** Sign SSH Certificate */
    public static final Command SIGN_SSH_CERTIFICATE = new Command((byte) 0x5d, "Sign SSH Certificate");
    /** Import Template object, tex X509Certificate */
    public static final Command PUT_TEMPLATE = new Command((byte) 0x5e, "Put Template");
    /** Get Template */
    public static final Command GET_TEMPLATE = new Command((byte) 0x5f, "Get Template");
    /** Decrypt Otp */
    public static final Command DECRYPT_OTP = new Command((byte) 0x60, "Decrypt Otp");
    /** Create Otp Aead */
    public static final Command CREATE_OTP_AEAD = new Command((byte) 0x61, "Create Otp Aead");
    /** Randomize Otp Aead */
    public static final Command RANDOMIZE_OTP_AEAD = new Command((byte) 0x62, "Randomize Otp Aead");
    /** Re-wrap Otp Aead */
    public static final Command REWRAP_OTP_AEAD = new Command((byte) 0x63, "Re-wrap Otp Aead");
    /** Sign Attestation Certificate */
    public static final Command SIGN_ATTESTATION_CERTIFICATE = new Command((byte) 0x64, "Sign Attestation Certificate");
    /** Import Otp Aead Key */
    public static final Command PUT_OTP_AEAD_KEY = new Command((byte) 0x65, "Put Otp Aead Key");
    /** Generate Otp Aead Key */
    public static final Command GENERATE_OTP_AEAD_KEY = new Command((byte) 0x66, "Generate Otp Aead Key");
    /** Set Log Index */
    public static final Command SET_LOG_INDEX = new Command((byte) 0x67, "Set Log Index");
    /** Wrap Data */
    public static final Command WRAP_DATA = new Command((byte) 0x68, "Wrap Data");
    /** Unwrap Data */
    public static final Command UNWRAP_DATA = new Command((byte) 0x69, "Unwrap Data");
    /** Sign using Eddsa */
    public static final Command SIGN_EDDSA = new Command((byte) 0x6a, "Sign Eddsa");
    /** Blink Device */
    public static final Command BLINK_DEVICE = new Command((byte) 0x6b, "Blink Device");
    /** Change Authentication Key */
    public static final Command CHANGE_AUTHENTICATION_KEY = new Command((byte) 0x6c, "Change Authentication Key");
    /** Error */
    public static final Command ERROR = new Command((byte) 0x7f, "Error");
}
