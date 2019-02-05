package com.yubico.objects;

import java.util.HashMap;
import java.util.Map;

public class Algorithm {

    public static final Algorithm RSA_PKCS1_SHA1 = new Algorithm((byte) 1, "rsa-pkcs1-sha1");
    public static final Algorithm RSA_PKCS1_SHA256 = new Algorithm((byte) 2, "rsa-pkcs1-sha256");
    public static final Algorithm RSA_PKCS1_SHA384 = new Algorithm((byte) 3, "rsa-pkcs1-sha384");
    public static final Algorithm RSA_PKCS1_SHA512 = new Algorithm((byte) 4, "rsa-pkcs1-sha512");
    public static final Algorithm RSA_PSS_SHA1 = new Algorithm((byte) 5, "rsa-pss-sha1");
    public static final Algorithm RSA_PSS_SHA256 = new Algorithm((byte) 6, "rsa-pss-sha256");
    public static final Algorithm RSA_PSS_SHA384 = new Algorithm((byte) 7, "rsa-pss-sha384");
    public static final Algorithm RSA_PSS_SHA512 = new Algorithm((byte) 8, "rsa-pss-sha512");
    public static final Algorithm RSA_2048 = new Algorithm((byte) 9, "rsa2048");
    public static final Algorithm RSA_3072 = new Algorithm((byte) 10, "rsa3072");
    public static final Algorithm RSA_4096 = new Algorithm((byte) 11, "rsa4096");
    public static final Algorithm RSA_OAEP_SHA1 = new Algorithm((byte) 25, "rsa-oaep-sha1");
    public static final Algorithm RSA_OAEP_SHA256 = new Algorithm((byte) 26, "rsa-oaep-sha256");
    public static final Algorithm RSA_OAEP_SHA384 = new Algorithm((byte) 27, "rsa-oaep-sha384");
    public static final Algorithm RSA_OAEP_SHA512 = new Algorithm((byte) 28, "rsa-oaep-sha512");
    public static final Algorithm RSA_MGF1_SHA1 = new Algorithm((byte) 32, "mgf1-sha1");
    public static final Algorithm RSA_MGF1_SHA256 = new Algorithm((byte) 33, "mgf1-sha256");
    public static final Algorithm RSA_MGF1_SHA384 = new Algorithm((byte) 34, "mgf1-sha384");
    public static final Algorithm RSA_MGF1_SHA512 = new Algorithm((byte) 35, "mgf1-sha512");

    public static final Algorithm EC_P256 = new Algorithm((byte) 12, "ecp256");
    public static final Algorithm EC_P384 = new Algorithm((byte) 13, "ecp384");
    public static final Algorithm EC_P521 = new Algorithm((byte) 14, "ecp521");
    public static final Algorithm EC_K256 = new Algorithm((byte) 15, "eck256");
    public static final Algorithm EC_BP256 = new Algorithm((byte) 16, "ecbp256");
    public static final Algorithm EC_BP384 = new Algorithm((byte) 17, "ecbp384");
    public static final Algorithm EC_BP512 = new Algorithm((byte) 18, "ecbp512");

    public static final Algorithm EC_ECDSA_SHA1 = new Algorithm((byte) 23, "ecdsa-sha1");
    public static final Algorithm EC_ECDH = new Algorithm((byte) 24, "ecdh");

    public static final Algorithm HMAC_SHA1 = new Algorithm((byte) 19, "hmac-sha1");
    public static final Algorithm HMAC_SHA256 = new Algorithm((byte) 20, "hmac-sha256");
    public static final Algorithm HMAC_SHA384 = new Algorithm((byte) 21, "hmac-sha384");
    public static final Algorithm HMAC_SHA512 = new Algorithm((byte) 22, "hmac-sha512");

    public static final Algorithm AES128_CCM_WRAP = new Algorithm((byte) 29, "aes128-ccm-wrap");
    public static final Algorithm OPAQUE_DATA = new Algorithm((byte) 30, "opaque-data");
    public static final Algorithm OPAQUE_X509_CERTIFICATE = new Algorithm((byte) 31, "opaque-x509-certificate");
    public static final Algorithm TEMPLATE_SSH = new Algorithm((byte) 36, "template-ssh");
    public static final Algorithm AES128_YUBICO_OTP = new Algorithm((byte) 37, "aes128-yubico-otp");
    public static final Algorithm AES128_YUBICO_AUTHENTICATION = new Algorithm((byte) 38, "aes128-yubico-authentication");
    public static final Algorithm AES192_YUBICO_OTP = new Algorithm((byte) 39, "aes192-yubico-otp");
    public static final Algorithm AES256_YUBICO_OTP = new Algorithm((byte) 40, "aes256-yubico-otp");
    public static final Algorithm AES192_CCM_WRAP = new Algorithm((byte) 41, "aes192-ccm-wrap");
    public static final Algorithm AES256_CCM_WRAP = new Algorithm((byte) 42, "aes256-ccm-wrap");
    public static final Algorithm EC_ECDSA_SHA256 = new Algorithm((byte) 43, "ecdsa-sha256");
    public static final Algorithm EC_ECDSA_SHA384 = new Algorithm((byte) 44, "ecdsa-sha384");
    public static final Algorithm EC_ECDSA_SHA512 = new Algorithm((byte) 45, "ecdsa-sha512");
    public static final Algorithm EC_ED25519 = new Algorithm((byte) 46, "ed25519");
    public static final Algorithm EC_P224 = new Algorithm((byte) 47, "ecp224");

    private byte algorithm;
    private String name;

    public Algorithm(final byte algorithm, final String name) {
        this.algorithm = algorithm;
        this.name = name;
    }

    public byte getAlgorithm() {
        return algorithm;
    }

    public String getName() {
        return name;
    }

    public static String getNameFromAlgorithm(final byte algorithm) {
        Algorithm algo = (Algorithm) getAlgorithmsMap().get(algorithm);
        if (algo != null) {
            return algo.getName();
        }
        return String.format("Algorithm 0x%02X not supported", algorithm);
    }

    public static Algorithm getAlgorithm(final byte algo) {
        return (Algorithm) getAlgorithmsMap().get(algo);
    }

    public static boolean isSuppotedAlgorithm(final byte algorithm) {
        return getAlgorithmsMap().containsKey(algorithm);
    }

    public String toString() {
        return String.format("0x%02X: " + name, algorithm);
    }

    private static Map getAlgorithmsMap() {
        Map algorithms = new HashMap();
        algorithms.put((byte) 1, RSA_PKCS1_SHA1);
        algorithms.put((byte) 2, RSA_PKCS1_SHA256);
        algorithms.put((byte) 3, RSA_PKCS1_SHA384);
        algorithms.put((byte) 4, RSA_PKCS1_SHA512);
        algorithms.put((byte) 5, RSA_PSS_SHA1);
        algorithms.put((byte) 6, RSA_PSS_SHA256);
        algorithms.put((byte) 7, RSA_PSS_SHA384);
        algorithms.put((byte) 8, RSA_PSS_SHA512);
        algorithms.put((byte) 9, RSA_2048);
        algorithms.put((byte) 10, RSA_3072);
        algorithms.put((byte) 11, RSA_4096);
        algorithms.put((byte) 25, RSA_OAEP_SHA1);
        algorithms.put((byte) 26, RSA_OAEP_SHA256);
        algorithms.put((byte) 27, RSA_OAEP_SHA384);
        algorithms.put((byte) 28, RSA_OAEP_SHA512);
        algorithms.put((byte) 32, RSA_MGF1_SHA1);
        algorithms.put((byte) 33, RSA_MGF1_SHA256);
        algorithms.put((byte) 34, RSA_MGF1_SHA384);
        algorithms.put((byte) 35, RSA_MGF1_SHA512);

        algorithms.put((byte) 12, EC_P256);
        algorithms.put((byte) 13, EC_P384);
        algorithms.put((byte) 14, EC_P521);
        algorithms.put((byte) 15, EC_K256);
        algorithms.put((byte) 16, EC_BP256);
        algorithms.put((byte) 17, EC_BP384);
        algorithms.put((byte) 18, EC_BP512);

        algorithms.put((byte) 23, EC_ECDSA_SHA1);
        algorithms.put((byte) 24, EC_ECDH);

        algorithms.put((byte) 19, HMAC_SHA1);
        algorithms.put((byte) 20, HMAC_SHA256);
        algorithms.put((byte) 21, HMAC_SHA384);
        algorithms.put((byte) 22, HMAC_SHA512);

        algorithms.put((byte) 29, AES128_CCM_WRAP);
        algorithms.put((byte) 30, OPAQUE_DATA);
        algorithms.put((byte) 31, OPAQUE_X509_CERTIFICATE);
        algorithms.put((byte) 36, TEMPLATE_SSH);
        algorithms.put((byte) 37, AES128_YUBICO_OTP);
        algorithms.put((byte) 38, AES128_YUBICO_AUTHENTICATION);
        algorithms.put((byte) 39, AES192_YUBICO_OTP);
        algorithms.put((byte) 40, AES256_YUBICO_OTP);
        algorithms.put((byte) 41, AES192_CCM_WRAP);
        algorithms.put((byte) 42, AES256_CCM_WRAP);
        algorithms.put((byte) 43, EC_ECDSA_SHA256);
        algorithms.put((byte) 44, EC_ECDSA_SHA384);
        algorithms.put((byte) 45, EC_ECDSA_SHA512);
        algorithms.put((byte) 46, EC_ED25519);
        algorithms.put((byte) 47, EC_P224);
        return algorithms;
    }

}
