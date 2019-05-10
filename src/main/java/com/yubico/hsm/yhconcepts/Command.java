package com.yubico.hsm.yhconcepts;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Class representing commands that are recognized by the device
 */
public enum Command {
    /** Echo the command input */
    ECHO                        ((byte) 0x01, "Echo"),
    /** Create Session */
    CREATE_SESSION              ((byte) 0x03, "Create Session"),
    /** Authenticate Session */
    AUTHENTICATE_SESSION        ((byte) 0x04, "Authenticate Session"),
    /** Send encrypted message to the device */
    SESSION_MESSAGE             ((byte) 0x05, "Session Message"),
    /** Get Device Info */
    DEVICE_INFO                 ((byte) 0x06, "Get Device Info"),
    /** Reset Device */
    RESET_DEVICE                ((byte) 0x08, "Reset Device"),
    /** Close Session */
    CLOSE_SESSION               ((byte) 0x40, "Close Session"),
    /** Get Storage Info */
    GET_STORAGE_INFO            ((byte) 0x041, "Get Storage Info"),
    /** Import Opaque object */
    PUT_OPAQUE                  ((byte) 0x42, "Put Opaque"),
    /** Get Opaque object */
    GET_OPAQUE                  ((byte) 0x43, "Get Opaque"),
    /** Import Authentication Key */
    PUT_AUTHENTICATION_KEY      ((byte) 0x44, "Put Authentication Key"),
    /** Import Asymmetric Key */
    PUT_ASYMMETRIC_KEY          ((byte) 0x45, "Put Asymmetric Key"),
    /** Generate Asymmetric Key */
    GENERATE_ASYMMETRIC_KEY     ((byte) 0x46, "Generate Asymmetric Key"),
    /** Sign using Pkcs1 */
    SIGN_PKCS1                  ((byte) 0x47, "Sign Pkcs1"),
    /** List Objects */
    LIST_OBJECTS                ((byte) 0x48, "List Objects"),
    /** Decrypt using Pkcs1 */
    DECRYPT_PKCS1               ((byte) 0x49, "Decrypt Pkcs1"),
    /** Export Wrapped object */
    EXPORT_WRAPPED              ((byte) 0x4a, "Export Wrapped"),
    /** Import Wrapped object */
    IMPORT_WRAPPED              ((byte) 0x4b, "Import Wrapped"),
    /** Import Wrap Key */
    PUT_WRAP_KEY                ((byte) 0x4c, "Put Wrap Key"),
    /** Get Log Entries */
    GET_LOG_ENTRIES             ((byte) 0x4d, "Get Log Entries"),
    /** Get Object Info */
    GET_OBJECT_INFO             ((byte) 0x4e, "Get Object Info"),
    /** Set device option */
    SET_OPTION                  ((byte) 0x4f, "Set Option"),
    /** Get device option */
    GET_OPTION                  ((byte) 0x50, "Get Option"),
    /** Get Pseudo Random bytes */
    GET_PSEUDO_RANDOM           ((byte) 0x51, "Get Pseudo Random"),
    /** Import Hmac Key */
    PUT_HMAC_KEY                ((byte) 0x52, "Put Hmac Key"),
    /** Sign using Hmac */
    SIGN_HMAC                   ((byte) 0x53, "Sign Hmac"),
    /** Get Public Key */
    GET_PUBLIC_KEY              ((byte) 0x54, "Get Public Key"),
    /** Sign using Pss */
    SIGN_PSS                    ((byte) 0x55, "Sign Pss"),
    /** Sign using Ecdsa */
    SIGN_ECDSA                  ((byte) 0x56, "Sign Ecdsa"),
    /** Derive Ecdh */
    DERIVE_ECDH                 ((byte) 0x57, "Derive Ecdh"),
    /** Delete Object */
    DELETE_OBJECT               ((byte) 0x58, "Delete Object"),
    /** Decrypt Oaep */
    DECRYPT_OAEP                ((byte) 0x59, "Decrypt Oaep"),
    /** Generate Hmac Key */
    GENERATE_HMAC_KEY           ((byte) 0x5a, "Generate Hmac Key"),
    /** Generate Wrap Key */
    GENERATE_WRAP_KEY           ((byte) 0x5b, "Generate Wrap Key"),
    /** Verify Hmac */
    VERIFY_HMAC                 ((byte) 0x5c, "Verify Hmac"),
    /** Sign SSH Certificate */
    SIGN_SSH_CERTIFICATE        ((byte) 0x5d, "Sign SSH Certificate"),
    /** Import Template object, tex X509Certificate */
    PUT_TEMPLATE                ((byte) 0x5e, "Put Template"),
    /** Get Template */
    GET_TEMPLATE                ((byte) 0x5f, "Get Template"),
    /** Decrypt Otp */
    DECRYPT_OTP                 ((byte) 0x60, "Decrypt Otp"),
    /** Create Otp Aead */
    CREATE_OTP_AEAD             ((byte) 0x61, "Create Otp Aead"),
    /** Randomize Otp Aead */
    RANDOMIZE_OTP_AEAD          ((byte) 0x62, "Randomize Otp Aead"),
    /** Re-wrap Otp Aead */
    REWRAP_OTP_AEAD             ((byte) 0x63, "Re-wrap Otp Aead"),
    /** Sign Attestation Certificate */
    SIGN_ATTESTATION_CERTIFICATE((byte) 0x64, "Sign Attestation Certificate"),
    /** Import Otp Aead Key */
    PUT_OTP_AEAD_KEY            ((byte) 0x65, "Put Otp Aead Key"),
    /** Generate Otp Aead Key */
    GENERATE_OTP_AEAD_KEY       ((byte) 0x66, "Generate Otp Aead Key"),
    /** Set Log Index */
    SET_LOG_INDEX               ((byte) 0x67, "Set Log Index"),
    /** Wrap Data */
    WRAP_DATA                   ((byte) 0x68, "Wrap Data"),
    /** Unwrap Data */
    UNWRAP_DATA                 ((byte) 0x69, "Unwrap Data"),
    /** Sign using Eddsa */
    SIGN_EDDSA                  ((byte) 0x6a, "Sign Eddsa"),
    /** Blink Device */
    BLINK_DEVICE                ((byte) 0x6b, "Blink Device"),
    /** Change Authentication Key */
    CHANGE_AUTHENTICATION_KEY   ((byte) 0x6c, "Change Authentication Key"),
    /** Error */
    ERROR                       ((byte) 0x7f, "Error");

    private final byte id;
    private final String name;

    Command(final byte id, final String name) {
        this.id = id;
        this.name = name;
    }

    public byte getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    /**
     * Return the expected response code in case of a successful execution of this command
     */
    public byte getCommandResponse() {
        return (byte) (id | 0x80);
    }

    /**
     * Returns whether a command code represents an error
     *
     * @param command The command code to check
     * @return True if the command code represents an error response code. False otherwise
     */
    public static boolean isError(final byte command) {
        return command == ERROR.getId();
    }

    private static final Map<Byte, Command> BY_VALUE_MAP = new LinkedHashMap<Byte, Command>();

    static {
        for (Command cmd : Command.values()) {
            BY_VALUE_MAP.put(cmd.getId(), cmd);
        }
    }

    public static Command forId(byte id) {
        return BY_VALUE_MAP.get(id);
    }

    @Override
    public String toString() {
        return String.format("0x%02x:%s", id, name);
    }

}
