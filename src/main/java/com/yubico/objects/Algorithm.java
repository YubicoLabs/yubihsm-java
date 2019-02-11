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
        Algorithm algo = (Algorithm) getAlgorithm(algorithm);
        if (algo != null) {
            return algo.getName();
        }
        return String.format("Algorithm 0x%02X not supported", algorithm);
    }

    public static boolean isSuppotedAlgorithm(final byte algorithm) {
        return getAlgorithm(algorithm) != null;
    }

    public String toString() {
        return String.format("0x%02X: " + name, algorithm);
    }

    public static Algorithm getAlgorithm(byte id) {
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
            case 25: return RSA_OAEP_SHA1;
            case 26: return RSA_OAEP_SHA256;
            case 27: return RSA_OAEP_SHA384;
            case 28: return RSA_OAEP_SHA512;
            case 32: return RSA_MGF1_SHA1;
            case 33: return RSA_MGF1_SHA256;
            case 34: return RSA_MGF1_SHA384;
            case 35: return RSA_MGF1_SHA512;

            case 12: return EC_P256;
            case 13: return EC_P384;
            case 14: return EC_P521;
            case 15: return EC_K256;
            case 16: return EC_BP256;
            case 17: return EC_BP384;
            case 18: return EC_BP512;

            case 23: return EC_ECDSA_SHA1;
            case 24: return EC_ECDH;

            case 19: return HMAC_SHA1;
            case 20: return HMAC_SHA256;
            case 21: return HMAC_SHA384;
            case 22: return HMAC_SHA512;

            case 29: return AES128_CCM_WRAP;
            case 30: return OPAQUE_DATA;
            case 31: return OPAQUE_X509_CERTIFICATE;
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

}
