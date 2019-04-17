package com.yubico.objects.yhconcepts;

/**
 * Class representing algorithms supported by the device
 */
public class Algorithm extends YHConcept {

    private Algorithm(final byte id, final String name) {
        super(id, name);
    }

    public byte getAlgorithmId() {
        return (byte) getId();
    }

    /**
     * Returns a String representation of the algorithm
     *
     * @return The ID and name of the algorithm as a formatted String
     */
    public String toString() {
        return String.format("0x%02X: " + getName(), getAlgorithmId());
    }

    /**
     * @return True if this algorithm is a supported RSA algorithm. False otherwise
     */
    public boolean isRsaAlgorithm() {
        return isRsaAlgorithm(getAlgorithmId());
    }

    /**
     * @param algorithmId
     * @return True if `algorithmId` is the ID of a supported RSA algorithm. False otherwise
     */
    public static boolean isRsaAlgorithm(final byte algorithmId) {
        switch (algorithmId) {
            case 9: // RSA_2048
            case 10: // RSA_3072
            case 11: // RSA_4096
                return true;
            default:
                return false;
        }
    }

    /**
     * @return True if this algorithm is a supported EC algorithm. False otherwise
     */
    public boolean isEcAlgorithm() {
        return isEcAlgorithm(getAlgorithmId());
    }

    /**
     * @param algorithmId
     * @return True if `algorithmId` is the ID of a supported EC algorithm. False otherwise
     */
    public static boolean isEcAlgorithm(final byte algorithmId) {
        switch (algorithmId) {
            case 12: // EC_P256
            case 13: // EC_P384
            case 14: // EC_P521
            case 15: // EC_K256
            case 16: // EC_BP256
            case 17: // EC_BP384
            case 18: // EC_BP512
            case 47: // EC_P224
                return true;
            default:
                return false;
        }
    }

    /**
     * @return True if this algorithm is a supported ED algorithm. False otherwise
     */
    public boolean isEdAlgorithm() {
        return isEdAlgorithm(getAlgorithmId());
    }

    /**
     * @param algorithmId
     * @return True `algorithmId` is the ID of a supported ED algorithm. False otherwise
     */
    public static boolean isEdAlgorithm(final byte algorithmId) {
        return algorithmId == EC_ED25519.getAlgorithmId();
    }


    /**
     * @param id An algorithm ID, value 1 to 47
     * @return Algorithm object whose ID is `id`. Null if `id` is not recognized
     */
    public static Algorithm getAlgorithm(final byte id) {
        switch (id) {
            case 1: return RSA_PKCS1_SHA1;
            case 2: return RSA_PKCS1_SHA256;
            case 3: return RSA_PKCS1_SHA384;
            case 4: return RSA_PKCS1_SHA512;
            case 5: return RSA_PSS_SHA1;
            case 6: return RSA_PSS_SHA256;
            case 7: return RSA_PSS_SHA384;
            case 8: return RSA_PSS_SHA512;
            case 9: return RSA_2048;
            case 10: return RSA_3072;
            case 11: return RSA_4096;
            case 12: return EC_P256;
            case 13: return EC_P384;
            case 14: return EC_P521;
            case 15: return EC_K256;
            case 16: return EC_BP256;
            case 17: return EC_BP384;
            case 18: return EC_BP512;
            case 19: return HMAC_SHA1;
            case 20: return HMAC_SHA256;
            case 21: return HMAC_SHA384;
            case 22: return HMAC_SHA512;
            case 23: return EC_ECDSA_SHA1;
            case 24: return EC_ECDH;
            case 25: return RSA_OAEP_SHA1;
            case 26: return RSA_OAEP_SHA256;
            case 27: return RSA_OAEP_SHA384;
            case 28: return RSA_OAEP_SHA512;
            case 29: return AES128_CCM_WRAP;
            case 30: return OPAQUE_DATA;
            case 31: return OPAQUE_X509_CERTIFICATE;
            case 32: return RSA_MGF1_SHA1;
            case 33: return RSA_MGF1_SHA256;
            case 34: return RSA_MGF1_SHA384;
            case 35: return RSA_MGF1_SHA512;
            case 36: return TEMPLATE_SSH;
            case 37: return AES128_YUBICO_OTP;
            case 38: return AES128_YUBICO_AUTHENTICATION;
            case 39: return AES192_YUBICO_OTP;
            case 40: return AES256_YUBICO_OTP;
            case 41: return AES192_CCM_WRAP;
            case 42: return AES256_CCM_WRAP;
            case 43: return EC_ECDSA_SHA256;
            case 44: return EC_ECDSA_SHA384;
            case 45: return EC_ECDSA_SHA512;
            case 46: return EC_ED25519;
            case 47: return EC_P224;
            default: return null;
        }
    }

    /** Algorithm used for signing with RSA-PKCS#1v1.5 */
    public static final Algorithm RSA_PKCS1_SHA1 = new Algorithm((byte) 1, "rsa-pkcs1-sha1");
    /** Algorithm used for signing with RSA-PKCS#1v1.5 */
    public static final Algorithm RSA_PKCS1_SHA256 = new Algorithm((byte) 2, "rsa-pkcs1-sha256");
    /** Algorithm used for signing with RSA-PKCS#1v1.5 */
    public static final Algorithm RSA_PKCS1_SHA384 = new Algorithm((byte) 3, "rsa-pkcs1-sha384");
    /** Algorithm used for signing with RSA-PKCS#1v1.5 */
    public static final Algorithm RSA_PKCS1_SHA512 = new Algorithm((byte) 4, "rsa-pkcs1-sha512");
    /** Algorithm used for signing with RSA-PSS */
    public static final Algorithm RSA_PSS_SHA1 = new Algorithm((byte) 5, "rsa-pss-sha1");
    /** Algorithm used for signing with RSA-PSS */
    public static final Algorithm RSA_PSS_SHA256 = new Algorithm((byte) 6, "rsa-pss-sha256");
    /** Algorithm used for signing with RSA-PSS */
    public static final Algorithm RSA_PSS_SHA384 = new Algorithm((byte) 7, "rsa-pss-sha384");
    /** Algorithm used for signing with RSA-PSS */
    public static final Algorithm RSA_PSS_SHA512 = new Algorithm((byte) 8, "rsa-pss-sha512");
    /** Algorithm for RSA key generation */
    public static final Algorithm RSA_2048 = new Algorithm((byte) 9, "rsa2048");
    /** Algorithm for RSA key generation */
    public static final Algorithm RSA_3072 = new Algorithm((byte) 10, "rsa3072");
    /** Algorithm for RSA key generation */
    public static final Algorithm RSA_4096 = new Algorithm((byte) 11, "rsa4096");
    /** Algorithm for EC key generation. Curve secp256r1 */
    public static final Algorithm EC_P256 = new Algorithm((byte) 12, "ecp256");
    /** Algorithm for EC key generation. Curve secp384r1 */
    public static final Algorithm EC_P384 = new Algorithm((byte) 13, "ecp384");
    /** Algorithm for EC key generation. Curve secp521r1 */
    public static final Algorithm EC_P521 = new Algorithm((byte) 14, "ecp521");
    /** Algorithm for EC key generation. Curve secp256k1 */
    public static final Algorithm EC_K256 = new Algorithm((byte) 15, "eck256");
    /** Algorithm for EC key generation. Curve brainpool256r1 */
    public static final Algorithm EC_BP256 = new Algorithm((byte) 16, "ecbp256");
    /** Algorithm for EC key generation. Curve brainpool384r1 */
    public static final Algorithm EC_BP384 = new Algorithm((byte) 17, "ecbp384");
    /** Algorithm for EC key generation. Curve brainpool512r1 */
    public static final Algorithm EC_BP512 = new Algorithm((byte) 18, "ecbp512");
    /**  */
    public static final Algorithm HMAC_SHA1 = new Algorithm((byte) 19, "hmac-sha1");
    /**  */
    public static final Algorithm HMAC_SHA256 = new Algorithm((byte) 20, "hmac-sha256");
    /**  */
    public static final Algorithm HMAC_SHA384 = new Algorithm((byte) 21, "hmac-sha384");
    /**  */
    public static final Algorithm HMAC_SHA512 = new Algorithm((byte) 22, "hmac-sha512");
    /** Algorithm used for signing with ECDSA */
    public static final Algorithm EC_ECDSA_SHA1 = new Algorithm((byte) 23, "ecdsa-sha1");
    /** Algorithm used for deriving ECDH secret shared key */
    public static final Algorithm EC_ECDH = new Algorithm((byte) 24, "ecdh");
    /** Algorithm used for decryption using RSA-OAEP */
    public static final Algorithm RSA_OAEP_SHA1 = new Algorithm((byte) 25, "rsa-oaep-sha1");
    /** Algorithm used for decryption using RSA-OAEP */
    public static final Algorithm RSA_OAEP_SHA256 = new Algorithm((byte) 26, "rsa-oaep-sha256");
    /** Algorithm used for decryption using RSA-OAEP */
    public static final Algorithm RSA_OAEP_SHA384 = new Algorithm((byte) 27, "rsa-oaep-sha384");
    /** Algorithm used for decryption using RSA-OAEP */
    public static final Algorithm RSA_OAEP_SHA512 = new Algorithm((byte) 28, "rsa-oaep-sha512");
    /**  */
    public static final Algorithm AES128_CCM_WRAP = new Algorithm((byte) 29, "aes128-ccm-wrap");
    /** Algorithm used for storing Opaque objects */
    public static final Algorithm OPAQUE_DATA = new Algorithm((byte) 30, "opaque-data");
    /** Algorithm used to storing an X509Certificate as an Opaque object */
    public static final Algorithm OPAQUE_X509_CERTIFICATE = new Algorithm((byte) 31, "opaque-x509-certificate");
    /** Algorithm used for signing and decryption with RSA-PSS */
    public static final Algorithm RSA_MGF1_SHA1 = new Algorithm((byte) 32, "mgf1-sha1");
    /** Algorithm used for signing and decryption with RSA-PSS */
    public static final Algorithm RSA_MGF1_SHA256 = new Algorithm((byte) 33, "mgf1-sha256");
    /** Algorithm used for signing and decryption with RSA-PSS */
    public static final Algorithm RSA_MGF1_SHA384 = new Algorithm((byte) 34, "mgf1-sha384");
    /** Algorithm used for signing and decryption with RSA-PSS */
    public static final Algorithm RSA_MGF1_SHA512 = new Algorithm((byte) 35, "mgf1-sha512");
    /**  */
    public static final Algorithm TEMPLATE_SSH = new Algorithm((byte) 36, "template-ssh");
    /**  */
    public static final Algorithm AES128_YUBICO_OTP = new Algorithm((byte) 37, "aes128-yubico-otp");
    /** Algorithm used to create Authentication Keys */
    public static final Algorithm AES128_YUBICO_AUTHENTICATION = new Algorithm((byte) 38, "aes128-yubico-authentication");
    /**  */
    public static final Algorithm AES192_YUBICO_OTP = new Algorithm((byte) 39, "aes192-yubico-otp");
    /**  */
    public static final Algorithm AES256_YUBICO_OTP = new Algorithm((byte) 40, "aes256-yubico-otp");
    /**  */
    public static final Algorithm AES192_CCM_WRAP = new Algorithm((byte) 41, "aes192-ccm-wrap");
    /**  */
    public static final Algorithm AES256_CCM_WRAP = new Algorithm((byte) 42, "aes256-ccm-wrap");
    /** Algorithm used to signing with ECDSA */
    public static final Algorithm EC_ECDSA_SHA256 = new Algorithm((byte) 43, "ecdsa-sha256");
    /** Algorithm used to signing with ECDSA */
    public static final Algorithm EC_ECDSA_SHA384 = new Algorithm((byte) 44, "ecdsa-sha384");
    /** Algorithm used to signing with ECDSA */
    public static final Algorithm EC_ECDSA_SHA512 = new Algorithm((byte) 45, "ecdsa-sha512");
    /** Algorithm used to signing with EdDSA */
    public static final Algorithm EC_ED25519 = new Algorithm((byte) 46, "ed25519");
    /** Algorithm for EC key generation. Curve secp224r1 */
    public static final Algorithm EC_P224 = new Algorithm((byte) 47, "ecp224");

}