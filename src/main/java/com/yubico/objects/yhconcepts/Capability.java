package com.yubico.objects.yhconcepts;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Class representing the capabilities of the objects stored on the device
 */
public class Capability extends YHConcept {

    private final String description;
    private final List<ObjectType> applicableObjects;

    /**
     * @param id                Capability ID
     * @param name              Capability name
     * @param description       Capability description
     * @param applicableObjects A list of types of objects that can have this capability
     */
    public Capability(final long id, final String name, final String description, final List<ObjectType> applicableObjects) {
        super(id, name);
        this.description = description;
        this.applicableObjects = applicableObjects;
    }

    /**
     * @return The capability ID
     */
    public long getCapabilityId() {
        return (long) getId();
    }

    /**
     * @return The capability description
     */
    public String getDescription() {
        return description;
    }

    /**
     * @return A list of types of objects that can have the capability
     */
    public List<ObjectType> getApplicableObjects() {
        return applicableObjects;
    }

    /**
     * @return A String representation of the capability
     */
    public String toString() {
        StringBuilder builder = new StringBuilder("");
        builder.append(String.format("Capability: 0x%08X \n", getCapabilityId()));
        builder.append("Name: " + getName()).append("\n");
        builder.append("Description: " + description).append("\n");
        builder.append("Applicable Objects: ");
        for (ObjectType type : applicableObjects) {
            builder.append(type.getName()).append(" ");
        }
        builder.append("\n");
        return builder.toString();
    }

    /**
     * Converts a long object into a list of capabilities
     *
     * @param capabilities A list of capabilities
     * @return `capabilities` as a long object
     */
    public static long getCapabilities(final List<Capability> capabilities) {
        long ret = 0L;
        if(capabilities != null) {
            for (Capability c : capabilities) {
                ret = ret | c.getCapabilityId();
            }
        }
        return ret;
    }

    /**
     * Converts a long object into a list of capabilities
     *
     * @param capabilities Capabilities as a long object
     * @return `capabilities` as a List of Capability
     */
    public static List<Capability> getCapabilities(final long capabilities) {
        List<Capability> ret = new ArrayList();
        long c = 1L;
        while (c < capabilities) {
            if ((capabilities & c) == c) {
                ret.add(getCapability(c));
            }
            c = c << 1;
        }
        return ret;

    }

    /**
     * Return the Capability object with the specified ID
     *
     * @param id The capability ID
     * @return The Capability object whose ID is `id`. Null if the ID is unrecognized
     */
    public static Capability getCapability(final long id) {
        if (id == GET_OPAQUE.getCapabilityId()) {
            return GET_OPAQUE;
        }
        if (id == PUT_OPAQUE.getCapabilityId()) {
            return PUT_OPAQUE;
        }
        if (id == PUT_AUTHENTICATION_KEY.getCapabilityId()) {
            return PUT_AUTHENTICATION_KEY;
        }
        if (id == PUT_ASYMMETRIC.getCapabilityId()) {
            return PUT_ASYMMETRIC;
        }
        if (id == GENERATE_ASYMMETRIC_KEY.getCapabilityId()) {
            return GENERATE_ASYMMETRIC_KEY;
        }
        if (id == SIGN_PKCS.getCapabilityId()) {
            return SIGN_PKCS;
        }
        if (id == SIGN_PSS.getCapabilityId()) {
            return SIGN_PSS;
        }
        if (id == SIGN_ECDSA.getCapabilityId()) {
            return SIGN_ECDSA;
        }
        if (id == SIGN_EDDSA.getCapabilityId()) {
            return SIGN_EDDSA;
        }
        if (id == DECRYPT_PKCS.getCapabilityId()) {
            return DECRYPT_PKCS;
        }
        if (id == DECRYPT_OAEP.getCapabilityId()) {
            return DECRYPT_OAEP;
        }
        if (id == DERIVE_ECDH.getCapabilityId()) {
            return DERIVE_ECDH;
        }
        if (id == EXPORT_WRAPPED.getCapabilityId()) {
            return EXPORT_WRAPPED;
        }
        if (id == IMPORT_WRAPPED.getCapabilityId()) {
            return IMPORT_WRAPPED;
        }
        if (id == PUT_WRAP_KEY.getCapabilityId()) {
            return PUT_WRAP_KEY;
        }
        if (id == GENERATE_WRAP_KEY.getCapabilityId()) {
            return GENERATE_WRAP_KEY;
        }
        if (id == EXPORTABLE_UNDER_WRAP.getCapabilityId()) {
            return EXPORTABLE_UNDER_WRAP;
        }
        if (id == SET_OPTION.getCapabilityId()) {
            return SET_OPTION;
        }
        if (id == GET_OPTION.getCapabilityId()) {
            return GET_OPTION;
        }
        if (id == GET_PSEUDO_RANDOM.getCapabilityId()) {
            return GET_PSEUDO_RANDOM;
        }
        if (id == PUT_HMAC_KEY.getCapabilityId()) {
            return PUT_HMAC_KEY;
        }
        if (id == GENERATE_HMAC_KEY.getCapabilityId()) {
            return GENERATE_HMAC_KEY;
        }
        if (id == SIGN_HMAC.getCapabilityId()) {
            return SIGN_HMAC;
        }
        if (id == VERIFY_HMAC.getCapabilityId()) {
            return VERIFY_HMAC;
        }
        if (id == GET_LOG_ENTRIES.getCapabilityId()) {
            return GET_LOG_ENTRIES;
        }
        if (id == SIGN_SSH_CERTIFICATE.getCapabilityId()) {
            return SIGN_SSH_CERTIFICATE;
        }
        if (id == GET_TEMPLATE.getCapabilityId()) {
            return GET_TEMPLATE;
        }
        if (id == PUT_TEMPLATE.getCapabilityId()) {
            return PUT_TEMPLATE;
        }
        if (id == RESET_DEVICE.getCapabilityId()) {
            return RESET_DEVICE;
        }
        if (id == DECRYPT_OTP.getCapabilityId()) {
            return DECRYPT_OTP;
        }
        if (id == CREATE_OTP_AEAD.getCapabilityId()) {
            return CREATE_OTP_AEAD;
        }
        if (id == RANDOMIZE_OTP_AEAD.getCapabilityId()) {
            return RANDOMIZE_OTP_AEAD;
        }
        if (id == REWRAP_FROM_OTP_AEAD_KEY.getCapabilityId()) {
            return REWRAP_FROM_OTP_AEAD_KEY;
        }
        if (id == REWRAP_TO_OTP_AEAD_KEY.getCapabilityId()) {
            return REWRAP_TO_OTP_AEAD_KEY;
        }
        if (id == SIGN_ATTESTATION_CERTIFICATE.getCapabilityId()) {
            return SIGN_ATTESTATION_CERTIFICATE;
        }
        if (id == PUT_OTP_AEAD_KEY.getCapabilityId()) {
            return PUT_OTP_AEAD_KEY;
        }
        if (id == GENERATE_OTP_AEAD_KEY.getCapabilityId()) {
            return GENERATE_OTP_AEAD_KEY;
        }
        if (id == WRAP_DATA.getCapabilityId()) {
            return WRAP_DATA;
        }
        if (id == UNWRAP_DATA.getCapabilityId()) {
            return UNWRAP_DATA;
        }
        if (id == DELETE_OPAQUE.getCapabilityId()) {
            return DELETE_OPAQUE;
        }
        if (id == DELETE_AUTHENTICATION_KEY.getCapabilityId()) {
            return DELETE_AUTHENTICATION_KEY;
        }
        if (id == DELETE_ASYMMETRIC_KEY.getCapabilityId()) {
            return DELETE_ASYMMETRIC_KEY;
        }
        if (id == DELETE_WRAP_KEY.getCapabilityId()) {
            return DELETE_WRAP_KEY;
        }
        if (id == DELETE_HMAC_KEY.getCapabilityId()) {
            return DELETE_HMAC_KEY;
        }
        if (id == DELETE_TEMPLATE.getCapabilityId()) {
            return DELETE_TEMPLATE;
        }
        if (id == DELETE_OTP_AEAD_KEY.getCapabilityId()) {
            return DELETE_OTP_AEAD_KEY;
        }
        if (id == CHANGE_AUTHENTICATION_KEY.getCapabilityId()) {
            return CHANGE_AUTHENTICATION_KEY;
        }
        return null;
    }

    /** Read Opaque Objects */
    public static final Capability GET_OPAQUE =
            new Capability(0x0000000000000001L, "get-opaque", "Read Opaque Objects",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY)));
    /** Import Opaque Objects */
    public static final Capability PUT_OPAQUE =
            new Capability(0x0000000000000002L, "put-opaque", "Write Opaque Objects",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY)));
    /** Import Authentication Key Objects */
    public static final Capability PUT_AUTHENTICATION_KEY =
            new Capability((long) 0x0000000000000004L, "put-authentication-key", "Write Authentication Key Objects",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY)));
    /** Import Asymmetric Key Objects */
    public static final Capability PUT_ASYMMETRIC =
            new Capability(0x0000000000000008L, "put-asymmetric-key", "Write Asymmetric Key Objects",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY)));
    /** Generate Asymmetric Key Objects */
    public static final Capability GENERATE_ASYMMETRIC_KEY =
            new Capability(0x0000000000000010L, "generate-asymmetric-key", "Generate Asymmetric Key Objects",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY)));
    /** Compute signatures using RSA-PKCS1v1.5 */
    public static final Capability SIGN_PKCS =
            new Capability(0x0000000000000020L, "sign-pkcs", "Compute signatures using RSA-PKCS1v1.5",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY, ObjectType.TYPE_ASYMMETRIC_KEY)));
    /** Compute digital signatures using using RSA-PSS */
    public static final Capability SIGN_PSS =
            new Capability(0x0000000000000040L, "sign-pss", "Compute digital signatures using using RSA-PSS",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY, ObjectType.TYPE_ASYMMETRIC_KEY)));
    /** Compute digital signatures using ECDSA */
    public static final Capability SIGN_ECDSA =
            new Capability(0x0000000000000080L, "sign-ecdsa", "Compute digital signatures using ECDSA",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY, ObjectType.TYPE_ASYMMETRIC_KEY)));
    /** Compute digital signatures using EDDSA */
    public static final Capability SIGN_EDDSA =
            new Capability(0x0000000000000100L, "sign-eddsa", "Compute digital signatures using EDDSA",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY, ObjectType.TYPE_ASYMMETRIC_KEY)));
    /** Decrypt data using RSA-PKCS1v1.5 */
    public static final Capability DECRYPT_PKCS =
            new Capability(0x0000000000000200L, "decrypt-pkcs", "Decrypt data using RSA-PKCS1v1.5",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY, ObjectType.TYPE_ASYMMETRIC_KEY)));
    /** Decrypt data using RSA-OAEP */
    public static final Capability DECRYPT_OAEP =
            new Capability(0x0000000000000400L, "decrypt-oaep", "Decrypt data using RSA-OAEP",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY, ObjectType.TYPE_ASYMMETRIC_KEY)));
    /** Perform ECDH */
    public static final Capability DERIVE_ECDH =
            new Capability(0x0000000000000800L, "derive-ecdh", "Perform ECDH",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY, ObjectType.TYPE_ASYMMETRIC_KEY)));
    /** Export other Objects under wrap */
    public static final Capability EXPORT_WRAPPED =
            new Capability(0x0000000000001000L, "export-wrapped", "Export other Objects under wrap",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY, ObjectType.TYPE_WRAP_KEY)));
    /** Import wrapped Objects */
    public static final Capability IMPORT_WRAPPED =
            new Capability(0x0000000000002000L, "import-wrapped", "Import wrapped Objects",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY, ObjectType.TYPE_WRAP_KEY)));
    /** Import Wrap Key Objects */
    public static final Capability PUT_WRAP_KEY =
            new Capability(0x0000000000004000L, "put-wrap-key", "Write Wrap Key Objects",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY)));
    /** Generate Wrap Key Objects */
    public static final Capability GENERATE_WRAP_KEY =
            new Capability(0x0000000000008000L, "generate-wrap-key", "Generate Wrap Key Objects",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY)));
    /** Mark an Object as exportable under wrap */
    public static final Capability EXPORTABLE_UNDER_WRAP =
            new Capability(0x0000000000010000L, "exportable-under-wrap", "Mark an Object as exportable under wrap",
                           new ArrayList<>(
                                   Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY, ObjectType.TYPE_WRAP_KEY, ObjectType.TYPE_ASYMMETRIC_KEY,
                                                 ObjectType.TYPE_HMAC_KEY, ObjectType.TYPE_OPAQUE, ObjectType.TYPE_OTP_AEAD_KEY,
                                                 ObjectType.TYPE_TEMPLATE)));
    /** Write device-global options */
    public static final Capability SET_OPTION =
            new Capability(0x0000000000020000L, "set-option", "Write device-global options",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY)));
    /** Read device-global options */
    public static final Capability GET_OPTION =
            new Capability(0x0000000000040000L, "get-option", "Read device-global options",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY)));
    /** Extract random bytes */
    public static final Capability GET_PSEUDO_RANDOM =
            new Capability(0x0000000000080000L, "get-pseudo-random", "Extract random bytes",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY)));
    /** Import HMAC Key Objects */
    public static final Capability PUT_HMAC_KEY =
            new Capability(0x0000000000100000L, "put-mac-key", "Write HMAC Key Objects",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY)));
    /** Generate HMAC Key Objects */
    public static final Capability GENERATE_HMAC_KEY =
            new Capability(0x0000000000200000L, "generate-hmac-key", "Generate HMAC Key Objects",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY)));
    /** Compute HMAC of data */
    public static final Capability SIGN_HMAC =
            new Capability(0x0000000000400000L, "sign-hmac", "Compute HMAC of data",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY, ObjectType.TYPE_HMAC_KEY)));
    /** Verify HMAC of data */
    public static final Capability VERIFY_HMAC =
            new Capability(0x0000000000800000L, "verify-hmac", "Verify HMAC of data",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY, ObjectType.TYPE_HMAC_KEY)));
    /** Read the Log Store */
    public static final Capability GET_LOG_ENTRIES =
            new Capability(0x0000000001000000L, "get-log-entries", "Read the Log Store",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY)));
    /** Sign SSH certificates */
    public static final Capability SIGN_SSH_CERTIFICATE =
            new Capability(0x0000000002000000L, "sign-ssh-certificate", "Sign SSH certificates",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY, ObjectType.TYPE_ASYMMETRIC_KEY)));
    /** Read Template Objects */
    public static final Capability GET_TEMPLATE =
            new Capability(0x0000000004000000L, "get-template", "Read Template Objects",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY)));
    /** Import Template Objects */
    public static final Capability PUT_TEMPLATE =
            new Capability(0x0000000008000000L, "put-template", "Write Template Objects",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY)));
    /** Perform a factory reset on the device */
    public static final Capability RESET_DEVICE =
            new Capability(0x0000000010000000L, "reset-device", "Perform a factory reset on the device",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY)));
    /** Decrypt OTP */
    public static final Capability DECRYPT_OTP =
            new Capability(0x0000000020000000L, "decrypt-otp", "Decrypt OTP",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY, ObjectType.TYPE_OTP_AEAD_KEY)));
    /** Create OTP AEAD */
    public static final Capability CREATE_OTP_AEAD =
            new Capability(0x0000000040000000L, "create-otp-aead", "Create OTP AEAD",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY, ObjectType.TYPE_OTP_AEAD_KEY)));
    /** Create OTP AEAD from random data */
    public static final Capability RANDOMIZE_OTP_AEAD =
            new Capability(0x0000000080000000L, "randomize-otp-aead", "Create OTP AEAD from random data",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY, ObjectType.TYPE_OTP_AEAD_KEY)));
    /** Re-wrap AEADs from one OTP AEAD Key Object to another */
    public static final Capability REWRAP_FROM_OTP_AEAD_KEY =
            new Capability(0x0000000100000000L, "rewrap-from-otp-aead-key", "Re-wrap AEADs from one OTP AEAD Key Object to another",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY, ObjectType.TYPE_OTP_AEAD_KEY)));
    /** Re-wrap AEADs to one OTP AEAD Key Object from another */
    public static final Capability REWRAP_TO_OTP_AEAD_KEY =
            new Capability(0x0000000200000000L, "rewrap-to-otp-aead-key", "Re-wrap AEADs to one OTP AEAD Key Object from another",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY, ObjectType.TYPE_OTP_AEAD_KEY)));
    /** Attest properties of Asymmetric Key Objects */
    public static final Capability SIGN_ATTESTATION_CERTIFICATE =
            new Capability(0x0000000400000000L, "sign-attestation-certificate", "Attest properties of Asymmetric Key Objects",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY, ObjectType.TYPE_ASYMMETRIC_KEY)));
    /** Import OTP AEAD Key Objects */
    public static final Capability PUT_OTP_AEAD_KEY =
            new Capability(0x0000000800000000L, "put-otp-aead-key", "Write OTP AEAD Key Objects",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY)));
    /** Generate OTP AEAD Key Objects */
    public static final Capability GENERATE_OTP_AEAD_KEY =
            new Capability(0x0000001000000000L, "generate-otp-aead-key", "Generate OTP AEAD Key Objects",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY)));
    /** Wrap user-provided data */
    public static final Capability WRAP_DATA =
            new Capability(0x0000002000000000L, "wrap-data", "Wrap user-provided data",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY, ObjectType.TYPE_WRAP_KEY)));
    /** Unwrap user-provided data */
    public static final Capability UNWRAP_DATA =
            new Capability(0x0000004000000000L, "unwrap-data", "Unwrap user-provided data",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY, ObjectType.TYPE_WRAP_KEY)));
    /** Delete Opaque Objects */
    public static final Capability DELETE_OPAQUE =
            new Capability(0x0000008000000000L, "delete-opaque", "Delete Opaque Objects",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY)));
    /** Delete Authentication Key Objects */
    public static final Capability DELETE_AUTHENTICATION_KEY =
            new Capability(0x0000010000000000L, "delete-authentication-key", "Delete Authentication Key Objects",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY)));
    /** Delete Asymmetric Key Objects */
    public static final Capability DELETE_ASYMMETRIC_KEY =
            new Capability(0x0000020000000000L, "delete-asymmetric-key", "Delete Asymmetric Key Objects",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY)));
    /** Delete Wrap Key Objects */
    public static final Capability DELETE_WRAP_KEY =
            new Capability(0x0000040000000000L, "delete-wrap-key", "Delete Wrap Key Objects",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY)));
    /** Delete HMAC Key Objects */
    public static final Capability DELETE_HMAC_KEY =
            new Capability(0x0000080000000000L, "delete-hmac-key", "Delete HMAC Key Objects",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY)));
    /** Delete Template Objects */
    public static final Capability DELETE_TEMPLATE =
            new Capability(0x0000100000000000L, "delete-template", "Delete Template Objects",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY)));
    /** Delete OTP AEAD Key Objects */
    public static final Capability DELETE_OTP_AEAD_KEY =
            new Capability(0x0000200000000000L, "delete-otp-aead-key", "Delete OTP AEAD Key Objects",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY)));
    /** Replace Authentication Key Objects */
    public static final Capability CHANGE_AUTHENTICATION_KEY =
            new Capability(0x0000400000000000L, "change-authentication-key", "Replace Authentication Key Objects",
                           new ArrayList<>(Arrays.asList(ObjectType.TYPE_AUTHENTICATION_KEY)));

    public static final List<Capability> ALL_CAPABILITIES = new ArrayList(Arrays.asList(GET_OPAQUE, PUT_OPAQUE, PUT_AUTHENTICATION_KEY,
                                                                                        PUT_ASYMMETRIC, GENERATE_ASYMMETRIC_KEY, SIGN_PKCS,
                                                                                        SIGN_PSS, SIGN_ECDSA, SIGN_EDDSA, DECRYPT_PKCS,
                                                                                        DECRYPT_OAEP, DERIVE_ECDH, EXPORT_WRAPPED, IMPORT_WRAPPED,
                                                                                        PUT_WRAP_KEY, GENERATE_WRAP_KEY, EXPORTABLE_UNDER_WRAP,
                                                                                        SET_OPTION, GET_OPTION, GET_PSEUDO_RANDOM, PUT_HMAC_KEY,
                                                                                        GENERATE_HMAC_KEY, SIGN_HMAC, VERIFY_HMAC, GET_LOG_ENTRIES,
                                                                                        SIGN_SSH_CERTIFICATE, GET_TEMPLATE, PUT_TEMPLATE,
                                                                                        RESET_DEVICE, DECRYPT_OTP, CREATE_OTP_AEAD,
                                                                                        RANDOMIZE_OTP_AEAD, REWRAP_FROM_OTP_AEAD_KEY,
                                                                                        REWRAP_TO_OTP_AEAD_KEY, SIGN_ATTESTATION_CERTIFICATE,
                                                                                        PUT_OTP_AEAD_KEY, GENERATE_OTP_AEAD_KEY, WRAP_DATA,
                                                                                        UNWRAP_DATA, DELETE_OPAQUE, DELETE_AUTHENTICATION_KEY,
                                                                                        DELETE_ASYMMETRIC_KEY, DELETE_WRAP_KEY, DELETE_HMAC_KEY,
                                                                                        DELETE_TEMPLATE, DELETE_OTP_AEAD_KEY,
                                                                                        CHANGE_AUTHENTICATION_KEY));
}
