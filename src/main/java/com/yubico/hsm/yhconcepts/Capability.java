package com.yubico.hsm.yhconcepts;

import java.util.*;

/**
 * Class representing the capabilities of the objects stored on the device
 */
public enum Capability {

    /** Read Opaque Objects */
    GET_OPAQUE                  (0x0000000000000001L, "get-opaque", "Read Opaque Objects",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY)),
    /** Import Opaque Objects */
    PUT_OPAQUE                  (0x0000000000000002L, "put-opaque", "Write Opaque Objects",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY)),
    /** Import Authentication Key Objects */
    PUT_AUTHENTICATION_KEY      (0x0000000000000004L, "put-authentication-key", "Write Authentication Key Objects",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY)),
    /** Import Asymmetric Key Objects */
    PUT_ASYMMETRIC              (0x0000000000000008L, "put-asymmetric-key", "Write Asymmetric Key Objects",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY)),
    /** Generate Asymmetric Key Objects */
    GENERATE_ASYMMETRIC_KEY     (0x0000000000000010L, "generate-asymmetric-key", "Generate Asymmetric Key Objects",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY)),
    /** Compute signatures using RSA-PKCS1v1.5 */
    SIGN_PKCS                   (0x0000000000000020L, "sign-pkcs", "Compute signatures using RSA-PKCS1v1.5",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY, Type.TYPE_ASYMMETRIC_KEY)),
    /** Compute digital signatures using using RSA-PSS */
    SIGN_PSS                    (0x0000000000000040L, "sign-pss", "Compute digital signatures using using RSA-PSS",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY, Type.TYPE_ASYMMETRIC_KEY)),
    /** Compute digital signatures using ECDSA */
    SIGN_ECDSA                  (0x0000000000000080L, "sign-ecdsa", "Compute digital signatures using ECDSA",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY, Type.TYPE_ASYMMETRIC_KEY)),
    /** Compute digital signatures using EDDSA */
    SIGN_EDDSA                  (0x0000000000000100L, "sign-eddsa", "Compute digital signatures using EDDSA",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY, Type.TYPE_ASYMMETRIC_KEY)),
    /** Decrypt data using RSA-PKCS1v1.5 */
    DECRYPT_PKCS                (0x0000000000000200L, "decrypt-pkcs", "Decrypt data using RSA-PKCS1v1.5",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY, Type.TYPE_ASYMMETRIC_KEY)),
    /** Decrypt data using RSA-OAEP */
    DECRYPT_OAEP                (0x0000000000000400L, "decrypt-oaep", "Decrypt data using RSA-OAEP",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY, Type.TYPE_ASYMMETRIC_KEY)),
    /** Perform ECDH */
    DERIVE_ECDH                 (0x0000000000000800L, "derive-ecdh", "Perform ECDH",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY, Type.TYPE_ASYMMETRIC_KEY)),
    /** Export other Objects under wrap */
    EXPORT_WRAPPED              (0x0000000000001000L, "export-wrapped", "Export other Objects under wrap",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY, Type.TYPE_WRAP_KEY)),
    /** Import wrapped Objects */
    IMPORT_WRAPPED              (0x0000000000002000L, "import-wrapped", "Import wrapped Objects",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY, Type.TYPE_WRAP_KEY)),
    /** Import Wrap Key Objects */
    PUT_WRAP_KEY                (0x0000000000004000L, "put-wrap-key", "Write Wrap Key Objects",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY)),
    /** Generate Wrap Key Objects */
    GENERATE_WRAP_KEY           (0x0000000000008000L, "generate-wrap-key", "Generate Wrap Key Objects",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY)),
    /** Mark an Object as exportable under wrap */
    EXPORTABLE_UNDER_WRAP       (0x0000000000010000L, "exportable-under-wrap", "Mark an Object as exportable under wrap",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY, Type.TYPE_WRAP_KEY, Type.TYPE_ASYMMETRIC_KEY, Type.TYPE_HMAC_KEY,
                                               Type.TYPE_OPAQUE, Type.TYPE_OTP_AEAD_KEY, Type.TYPE_TEMPLATE)),
    /** Write device-global options */
    SET_OPTION                  (0x0000000000020000L, "set-option", "Write device-global options",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY)),
    /** Read device-global options */
    GET_OPTION                  (0x0000000000040000L, "get-option", "Read device-global options",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY)),
    /** Extract random bytes */
    GET_PSEUDO_RANDOM           (0x0000000000080000L, "get-pseudo-random", "Extract random bytes",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY)),
    /** Import HMAC Key Objects */
    PUT_HMAC_KEY                (0x0000000000100000L, "put-mac-key", "Write HMAC Key Objects",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY)),
    /** Generate HMAC Key Objects */
    GENERATE_HMAC_KEY           (0x0000000000200000L, "generate-hmac-key", "Generate HMAC Key Objects",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY)),
    /** Compute HMAC of data */
    SIGN_HMAC                   (0x0000000000400000L, "sign-hmac", "Compute HMAC of data",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY, Type.TYPE_HMAC_KEY)),
    /** Verify HMAC of data */
    VERIFY_HMAC                 (0x0000000000800000L, "verify-hmac", "Verify HMAC of data",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY, Type.TYPE_HMAC_KEY)),
    /** Read the Log Store */
    GET_LOG_ENTRIES             (0x0000000001000000L, "get-log-entries", "Read the Log Store",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY)),
    /** Sign SSH certificates */
    SIGN_SSH_CERTIFICATE        (0x0000000002000000L, "sign-ssh-certificate", "Sign SSH certificates",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY, Type.TYPE_ASYMMETRIC_KEY)),
    /** Read Template Objects */
    GET_TEMPLATE                (0x0000000004000000L, "get-template", "Read Template Objects",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY)),
    /** Import Template Objects */
    PUT_TEMPLATE                (0x0000000008000000L, "put-template", "Write Template Objects",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY)),
    /** Perform a factory reset on the device */
    RESET_DEVICE                (0x0000000010000000L, "reset-device", "Perform a factory reset on the device",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY)),
    /** Decrypt OTP */
    DECRYPT_OTP                 (0x0000000020000000L, "decrypt-otp", "Decrypt OTP",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY, Type.TYPE_OTP_AEAD_KEY)),
    /** Create OTP AEAD */
    CREATE_OTP_AEAD             (0x0000000040000000L, "create-otp-aead", "Create OTP AEAD",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY, Type.TYPE_OTP_AEAD_KEY)),
    /** Create OTP AEAD from random data */
    RANDOMIZE_OTP_AEAD          (0x0000000080000000L, "randomize-otp-aead", "Create OTP AEAD from random data",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY, Type.TYPE_OTP_AEAD_KEY)),
    /** Re-wrap AEADs from one OTP AEAD Key Object to another */
    REWRAP_FROM_OTP_AEAD_KEY    (0x0000000100000000L, "rewrap-from-otp-aead-key", "Re-wrap AEADs from one OTP AEAD Key Object to another",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY, Type.TYPE_OTP_AEAD_KEY)),
    /** Re-wrap AEADs to one OTP AEAD Key Object from another */
    REWRAP_TO_OTP_AEAD_KEY      (0x0000000200000000L, "rewrap-to-otp-aead-key", "Re-wrap AEADs to one OTP AEAD Key Object from another",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY, Type.TYPE_OTP_AEAD_KEY)),
    /** Attest properties of Asymmetric Key Objects */
    SIGN_ATTESTATION_CERTIFICATE(0x0000000400000000L, "sign-attestation-certificate", "Attest properties of Asymmetric Key Objects",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY, Type.TYPE_ASYMMETRIC_KEY)),
    /** Import OTP AEAD Key Objects */
    PUT_OTP_AEAD_KEY            (0x0000000800000000L, "put-otp-aead-key", "Write OTP AEAD Key Objects",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY)),
    /** Generate OTP AEAD Key Objects */
    GENERATE_OTP_AEAD_KEY       (0x0000001000000000L, "generate-otp-aead-key", "Generate OTP AEAD Key Objects",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY)),
    /** Wrap user-provided data */
    WRAP_DATA                   (0x0000002000000000L, "wrap-data", "Wrap user-provided data",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY, Type.TYPE_WRAP_KEY)),
    /** Unwrap user-provided data */
    UNWRAP_DATA                 (0x0000004000000000L, "unwrap-data", "Unwrap user-provided data",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY, Type.TYPE_WRAP_KEY)),
    /** Delete Opaque Objects */
    DELETE_OPAQUE               (0x0000008000000000L, "delete-opaque", "Delete Opaque Objects",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY)),
    /** Delete Authentication Key Objects */
    DELETE_AUTHENTICATION_KEY   (0x0000010000000000L, "delete-authentication-key", "Delete Authentication Key Objects",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY)),
    /** Delete Asymmetric Key Objects */
    DELETE_ASYMMETRIC_KEY       (0x0000020000000000L, "delete-asymmetric-key", "Delete Asymmetric Key Objects",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY)),
    /** Delete Wrap Key Objects */
    DELETE_WRAP_KEY             (0x0000040000000000L, "delete-wrap-key", "Delete Wrap Key Objects",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY)),
    /** Delete HMAC Key Objects */
    DELETE_HMAC_KEY             (0x0000080000000000L, "delete-hmac-key", "Delete HMAC Key Objects",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY)),
    /** Delete Template Objects */
    DELETE_TEMPLATE             (0x0000100000000000L, "delete-template", "Delete Template Objects",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY)),
    /** Delete OTP AEAD Key Objects */
    DELETE_OTP_AEAD_KEY         (0x0000200000000000L, "delete-otp-aead-key", "Delete OTP AEAD Key Objects",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY)),
    /** Replace Authentication Key Objects */
    CHANGE_AUTHENTICATION_KEY   (0x0000400000000000L, "change-authentication-key", "Replace Authentication Key Objects",
                                 Arrays.asList(Type.TYPE_AUTHENTICATION_KEY));

    private final long id;
    private final String name;
    private final String description;
    private final List<Type> applicableObjects;

    public static List<Capability> ALL = Arrays.asList(Capability.values());

    Capability(long id, String name, String description, List<Type> applicableObjects) {
        this.id = id;
        this.name = name;
        this.description = description;
        this.applicableObjects = applicableObjects;
    }

    public long getId() {
        return id;
    }

    public String getName() {
        return this.name;
    }

    public String getDescription() {
        return description;
    }

    public List<Type> getApplicableObjects() {
        return applicableObjects;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder("");
        builder.append(String.format("Capability: 0x%016x \n", getId()));
        builder.append("Name: " + getName()).append("\n");
        builder.append("Description: " + description).append("\n");
        builder.append("Applicable Objects: ");
        for (Type type : applicableObjects) {
            builder.append(type.getName()).append(" ");
        }
        builder.append("\n");
        return builder.toString();
    }

    private static final Map<Long, Capability> BY_VALUE_MAP = new LinkedHashMap<Long, Capability>();

    static {
        for (Capability cap : Capability.values()) {
            BY_VALUE_MAP.put(cap.getId(), cap);
        }
    }

    public static Capability forId(long id) {
        return BY_VALUE_MAP.get(id);
    }
}
