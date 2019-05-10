package com.yubico.hsm.yhconcepts;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Class representing algorithms supported by the device
 */
public enum Algorithm {

    /** Algorithm used for signing with RSA-PKCS#1v1.5 */
    RSA_PKCS1_SHA1              ((byte) 1, "rsa-pkcs1-sha1"),
    /** Algorithm used for signing with RSA-PKCS#1v1.5 */
    RSA_PKCS1_SHA256            ((byte) 2, "rsa-pkcs1-sha256"),
    /** Algorithm used for signing with RSA-PKCS#1v1.5 */
    RSA_PKCS1_SHA384            ((byte) 3, "rsa-pkcs1-sha384"),
    /** Algorithm used for signing with RSA-PKCS#1v1.5 */
    RSA_PKCS1_SHA512            ((byte) 4, "rsa-pkcs1-sha512"),
    /** Algorithm used for signing with RSA-PSS */
    RSA_PSS_SHA1                ((byte) 5, "rsa-pss-sha1"),
    /** Algorithm used for signing with RSA-PSS */
    RSA_PSS_SHA256              ((byte) 6, "rsa-pss-sha256"),
    /** Algorithm used for signing with RSA-PSS */
    RSA_PSS_SHA384              ((byte) 7, "rsa-pss-sha384"),
    /** Algorithm used for signing with RSA-PSS */
    RSA_PSS_SHA512              ((byte) 8, "rsa-pss-sha512"),
    /** Algorithm for RSA key generation */
    RSA_2048                    ((byte) 9, "rsa2048"),
    /** Algorithm for RSA key generation */
    RSA_3072                    ((byte) 10, "rsa3072"),
    /** Algorithm for RSA key generation */
    RSA_4096                    ((byte) 11, "rsa4096"),
    /** Algorithm for EC key generation. Curve secp256r1 */
    EC_P256                     ((byte) 12, "ecp256"),
    /** Algorithm for EC key generation. Curve secp384r1 */
    EC_P384                     ((byte) 13, "ecp384"),
    /** Algorithm for EC key generation. Curve secp521r1 */
    EC_P521                     ((byte) 14, "ecp521"),
    /** Algorithm for EC key generation. Curve secp256k1 */
    EC_K256                     ((byte) 15, "eck256"),
    /** Algorithm for EC key generation. Curve brainpool256r1 */
    EC_BP256                    ((byte) 16, "ecbp256"),
    /** Algorithm for EC key generation. Curve brainpool384r1 */
    EC_BP384                    ((byte) 17, "ecbp384"),
    /** Algorithm for EC key generation. Curve brainpool512r1 */
    EC_BP512                    ((byte) 18, "ecbp512"),
    HMAC_SHA1                   ((byte) 19, "hmac-sha1"),
    HMAC_SHA256                 ((byte) 20, "hmac-sha256"),
    HMAC_SHA384                 ((byte) 21, "hmac-sha384"),
    HMAC_SHA512                 ((byte) 22, "hmac-sha512"),
    /** Algorithm used for signing with ECDSA */
    EC_ECDSA_SHA1               ((byte) 23, "ecdsa-sha1"),
    /** Algorithm used for deriving ECDH secret shared key */
    EC_ECDH                     ((byte) 24, "ecdh"),
    /** Algorithm used for decryption using RSA-OAEP */
    RSA_OAEP_SHA1               ((byte) 25, "rsa-oaep-sha1"),
    /** Algorithm used for decryption using RSA-OAEP */
    RSA_OAEP_SHA256             ((byte) 26, "rsa-oaep-sha256"),
    /** Algorithm used for decryption using RSA-OAEP */
    RSA_OAEP_SHA384             ((byte) 27, "rsa-oaep-sha384"),
    /** Algorithm used for decryption using RSA-OAEP */
    RSA_OAEP_SHA512             ((byte) 28, "rsa-oaep-sha512"),
    AES128_CCM_WRAP             ((byte) 29, "aes128-ccm-wrap"),
    /** Algorithm used for storing Opaque objects */
    OPAQUE_DATA                 ((byte) 30, "opaque-data"),
    /** Algorithm used to storing an X509Certificate as an Opaque object */
    OPAQUE_X509_CERTIFICATE     ((byte) 31, "opaque-x509-certificate"),
    /** Algorithm used for signing and decryption with RSA-PSS */
    RSA_MGF1_SHA1               ((byte) 32, "mgf1-sha1"),
    /** Algorithm used for signing and decryption with RSA-PSS */
    RSA_MGF1_SHA256             ((byte) 33, "mgf1-sha256"),
    /** Algorithm used for signing and decryption with RSA-PSS */
    RSA_MGF1_SHA384             ((byte) 34, "mgf1-sha384"),
    /** Algorithm used for signing and decryption with RSA-PSS */
    RSA_MGF1_SHA512             ((byte) 35, "mgf1-sha512"),
    TEMPLATE_SSH                ((byte) 36, "template-ssh"),
    AES128_YUBICO_OTP           ((byte) 37, "aes128-yubico-otp"),
    /** Algorithm used to create Authentication Keys */
    AES128_YUBICO_AUTHENTICATION((byte) 38, "aes128-yubico-authentication"),
    AES192_YUBICO_OTP           ((byte) 39, "aes192-yubico-otp"),
    AES256_YUBICO_OTP           ((byte) 40, "aes256-yubico-otp"),
    AES192_CCM_WRAP             ((byte) 41, "aes192-ccm-wrap"),
    AES256_CCM_WRAP             ((byte) 42, "aes256-ccm-wrap"),
    /** Algorithm used to signing with ECDSA */
    EC_ECDSA_SHA256             ((byte) 43, "ecdsa-sha256"),
    /** Algorithm used to signing with ECDSA */
    EC_ECDSA_SHA384             ((byte) 44, "ecdsa-sha384"),
    /** Algorithm used to signing with ECDSA */
    EC_ECDSA_SHA512             ((byte) 45, "ecdsa-sha512"),
    /** Algorithm used to signing with EdDSA */
    EC_ED25519                  ((byte) 46, "ed25519"),
    /** Algorithm for EC key generation. Curve secp224r1 */
    EC_P224                     ((byte) 47, "ecp224");

    private final byte id;
    private final String name;

    Algorithm(byte id, String name) {
        this.id = id;
        this.name = name;
    }

    public byte getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    private static final Map<Byte, Algorithm> BY_VALUE_MAP = new LinkedHashMap<Byte, Algorithm>();

    static {
        for (Algorithm algo : Algorithm.values()) {
            BY_VALUE_MAP.put(algo.getId(), algo);
        }
    }

    public static Algorithm forId(byte id) {
        return BY_VALUE_MAP.get(id);
    }

    @Override
    public String toString() {
        return String.format("0x%02x:%s ", id, name);
    }
}