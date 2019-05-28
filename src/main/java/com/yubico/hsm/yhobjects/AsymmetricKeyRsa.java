/*
 * Copyright 2019 Yubico AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.yubico.hsm.yhobjects;


import com.yubico.hsm.YHSession;
import com.yubico.hsm.exceptions.*;
import com.yubico.hsm.internal.util.Utils;
import com.yubico.hsm.yhconcepts.Algorithm;
import com.yubico.hsm.yhconcepts.Capability;
import com.yubico.hsm.yhconcepts.Command;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.List;

@Slf4j
public class AsymmetricKeyRsa extends AsymmetricKey {

    private static final int RSA_PUBKEY_EXPONENT = 65537;
    private static final int SIGN_PSS_SALT_LENGTH = 2;

    private static final int BLOCK_SIZE_FOR_RSA2048 = 256;
    private static final int BLOCK_SIZE_FOR_RSA3072 = 384;
    private static final int BLOCK_SIZE_FOR_RSA4096 = 512;

    /**
     * Creates an AsymmetriKeyRsa object
     *
     * @param id           The object ID of this key
     * @param keyAlgorithm A supported RSA key algorithm
     */
    public AsymmetricKeyRsa(final short id, @NonNull final Algorithm keyAlgorithm) {
        if (!isRsaKeyAlgorithm(keyAlgorithm)) {
            throw new IllegalArgumentException("An Asymmetric key algorithm must be a supported RSA algorithm");
        }
        setId(id);
        setType(TYPE);
        setKeyAlgorithm(keyAlgorithm);
    }

    /**
     * Imports a user generated RSA key into the YubiHSM
     *
     * @param session      An authenticated session to communicate with the device over
     * @param id           The desired Object ID of the imported RSA key. Set to 0 to have it generated
     * @param label        The label of the imported RSA key
     * @param domains      The domains where the imported RSA key will be accessible
     * @param keyAlgorithm The algorithm used to generate the imported RSA key
     * @param capabilities The actions that can be performed using the imported RSA key
     * @param privateKey   The private key to import
     * @return ID of the imported RSA key on the device
     * @throws NoSuchAlgorithmException           If the encryption/decryption fails
     * @throws YHDeviceException                  If the device returns an error
     * @throws YHInvalidResponseException         If the response from the device cannot be parsed
     * @throws YHConnectionException              If the connection to the device fails
     * @throws InvalidKeyException                If the encryption/decryption fails
     * @throws YHAuthenticationException          If the session authentication fails
     * @throws NoSuchPaddingException             If the encryption/decryption fails
     * @throws InvalidAlgorithmParameterException If the encryption/decryption fails
     * @throws BadPaddingException                If the encryption/decryption fails
     * @throws IllegalBlockSizeException          If the encryption/decryption fails
     * @throws UnsupportedAlgorithmException      If the specified key algorithm is not an RSA algorithm
     * @throws InvalidKeySpecException            If parsing the private key fails
     */
    public static short importKey(final YHSession session, final short id, final String label, @NonNull final List<Integer> domains,
                                  @NonNull final Algorithm keyAlgorithm, final List<Capability> capabilities, @NonNull final RSAPrivateKey privateKey)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException, UnsupportedAlgorithmException, InvalidKeySpecException {

        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateCrtKeySpec ks = kf.getKeySpec(privateKey, RSAPrivateCrtKeySpec.class);

        final int componentLength = getBlockSize(keyAlgorithm) / 2;
        byte[] p = Utils.getUnsignedByteArrayFromBigInteger(ks.getPrimeP(), componentLength);
        byte[] q = Utils.getUnsignedByteArrayFromBigInteger(ks.getPrimeQ(), componentLength);
        if (p.length != componentLength || q.length != componentLength) {
            throw new InvalidKeyException(
                    "Failed to obtain primes of length " + componentLength + " bytes from the private key. Consider specifying the " +
                    "private key primes in byte arrays of " + componentLength + " bytes each");
        }

        return importKey(session, id, label, domains, keyAlgorithm, capabilities, p, q);
    }

    /**
     * Imports a user generated RSA key into the YubiHSM
     *
     * @param session      An authenticated session to communicate with the device over
     * @param id           The desired Object ID of the imported RSA key. Set to 0 to have it generated
     * @param label        The label of the imported RSA key
     * @param domains      The domains where the imported RSA key will be accessible
     * @param keyAlgorithm The algorithm used to generate the imported RSA key
     * @param capabilities The actions that can be performed using the imported RSA key
     * @param primeP       The secret prime P.
     * @param primeQ       The secret prime Q.
     * @return ID of the imported RSA key on the device
     * @throws NoSuchAlgorithmException           If the encryption/decryption fails
     * @throws YHDeviceException                  If the device returns an error
     * @throws YHInvalidResponseException         If the response from the device cannot be parsed
     * @throws YHConnectionException              If the connection to the device fails
     * @throws InvalidKeyException                If the encryption/decryption fails
     * @throws YHAuthenticationException          If the session authentication fails
     * @throws NoSuchPaddingException             If the encryption/decryption fails
     * @throws InvalidAlgorithmParameterException If the encryption/decryption fails
     * @throws BadPaddingException                If the encryption/decryption fails
     * @throws IllegalBlockSizeException          If the encryption/decryption fails
     * @throws UnsupportedAlgorithmException      If the specified key algorithm is not an RSA algorithm
     */
    public static short importKey(final YHSession session, final short id, final String label, @NonNull final List<Integer> domains,
                                  @NonNull final Algorithm keyAlgorithm, final List<Capability> capabilities, @NonNull final byte[] primeP,
                                  @NonNull final byte[] primeQ)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException, UnsupportedAlgorithmException {
        verifyParametersForNewKeyRsa(domains, keyAlgorithm, primeP, primeQ);
        return putKey(session, id, label, domains, keyAlgorithm, capabilities, primeP, primeQ);
    }

    /**
     * Returns the public component of this RSA key.
     * <p>
     * The RSA public key exponent is 0x10001
     *
     * @param session An authenticated session to communicate with the device over
     * @return The public component of this RSA key as a java.security.PublicKey object
     * @throws NoSuchAlgorithmException           If the encryption/decryption fails
     * @throws YHDeviceException                  If the device returns an error
     * @throws YHInvalidResponseException         If the response from the device cannot be parsed
     * @throws YHConnectionException              If the connection to the device fails
     * @throws InvalidKeyException                If the encryption/decryption fails
     * @throws YHAuthenticationException          If the session authentication fails
     * @throws NoSuchPaddingException             If the encryption/decryption fails
     * @throws InvalidAlgorithmParameterException If the encryption/decryption fails
     * @throws BadPaddingException                If the encryption/decryption fails
     * @throws IllegalBlockSizeException          If the encryption/decryption fails
     * @throws InvalidKeySpecException            If failed to construct the public key object
     */
    public PublicKey getRsaPublicKey(final YHSession session)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidKeySpecException {

        byte[] mod = super.getPublicKey(session);
        byte[] expo = BigInteger.valueOf(RSA_PUBKEY_EXPONENT).toByteArray();

        // There has been a change in Java from 1.8.0_161 (referenced by JDK-8174756):
        // "RSA public key validation In 8u161, the RSA implementation in the SunRsaSign provider will reject any RSA public key that has an
        // exponent that is not in the valid range as defined by PKCS#1 version 2.2. This change will affect JSSE connections as well as
        // applications built on JCE."
        // This basically means that modulus shouldn't be negative. Which is why it is necessary to specifically set the signum value to 1 (to
        // get a positive BigInteger value)
        RSAPublicKeySpec spec = new RSAPublicKeySpec(new BigInteger(1, mod), new BigInteger(1, expo));
        KeyFactory factory = KeyFactory.getInstance("RSA");
        log.info("Returned public RSA key with ID 0x" + Integer.toHexString(getId()));
        return factory.generatePublic(spec);
    }

    /**
     * Signs the hash of the input data using RSA-PKCS#1v1.5.
     *
     * @param session       An authenticated session to communicate with the device over
     * @param data          The raw data to sign
     * @param hashAlgorithm The digest algorithm used to hash the data before signing it. Can be one of
     *                      {@link Algorithm#RSA_PKCS1_SHA1}, {@link Algorithm#RSA_PKCS1_SHA256}, {@link Algorithm#RSA_PKCS1_SHA384},
     *                      {@link Algorithm#RSA_PKCS1_SHA512}
     * @return The signature
     * @throws NoSuchAlgorithmException           If the encryption/decryption fails
     * @throws YHDeviceException                  If the device returns an error
     * @throws YHInvalidResponseException         If the response from the device cannot be parsed
     * @throws YHConnectionException              If the connection to the device fails
     * @throws InvalidKeyException                If the encryption/decryption fails
     * @throws YHAuthenticationException          If the session authentication fails
     * @throws NoSuchPaddingException             If the encryption/decryption fails
     * @throws InvalidAlgorithmParameterException If the encryption/decryption fails
     * @throws BadPaddingException                If the encryption/decryption fails
     * @throws IllegalBlockSizeException          If the encryption/decryption fails
     * @throws UnsupportedAlgorithmException      If the hash Algorithm is not one of {@link Algorithm#RSA_PKCS1_SHA1},
     *                                            {@link Algorithm#RSA_PKCS1_SHA256}, {@link Algorithm#RSA_PKCS1_SHA384},
     *                                            {@link Algorithm#RSA_PKCS1_SHA512}
     */
    public byte[] signPkcs1(final YHSession session, final byte[] data, @NonNull final Algorithm hashAlgorithm)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, UnsupportedAlgorithmException {
        if (!isPkcs1HashAlgorithm(hashAlgorithm)) {
            throw new UnsupportedAlgorithmException(hashAlgorithm.toString());
        }

        final byte[] hashedData = getHashedData(data, hashAlgorithm);
        return signPkcs1(session, hashedData);
    }

    /**
     * Signs the input data using RSA-PKCS#1v1.5. The input data is expected to be a hash of the raw data
     *
     * @param session    An authenticated session to communicate with the device over
     * @param dataDigest The hash of the data to sign
     * @return The signature
     * @throws NoSuchAlgorithmException           If the encryption/decryption fails
     * @throws YHDeviceException                  If the device returns an error
     * @throws YHInvalidResponseException         If the response from the device cannot be parsed
     * @throws YHConnectionException              If the connection to the device fails
     * @throws InvalidKeyException                If the encryption/decryption fails
     * @throws YHAuthenticationException          If the session authentication fails
     * @throws NoSuchPaddingException             If the encryption/decryption fails
     * @throws InvalidAlgorithmParameterException If the encryption/decryption fails
     * @throws BadPaddingException                If the encryption/decryption fails
     * @throws IllegalBlockSizeException          If the encryption/decryption fails
     */
    public byte[] signPkcs1(@NonNull final YHSession session, @NonNull final byte[] dataDigest)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException {

        ByteBuffer bb = ByteBuffer.allocate(OBJECT_ID_SIZE + dataDigest.length);
        bb.putShort(getId());
        bb.put(dataDigest);

        byte[] signature = session.sendSecureCmd(Command.SIGN_PKCS1, bb.array());
        log.info("Signed data with key 0x" + Integer.toHexString(getId()) + " and returned " + signature.length + " bytes signature");
        return signature;
    }

    /**
     * Signs the input data using RSA-PSS as defined in RFC 3447
     *
     * @param session       An authenticated session to communicate with the device over
     * @param mgf1Algorithm The MGF1 algorithm used for signing. Can be one of {@link Algorithm#RSA_MGF1_SHA1}, {@link Algorithm#RSA_MGF1_SHA256},
     *                      {@link Algorithm#RSA_MGF1_SHA384},{@link Algorithm#RSA_MGF1_SHA512}
     * @param saltLength    Length of salt
     * @param data          The raw data to be signed
     * @return The signature
     * @throws NoSuchAlgorithmException           If the encryption/decryption fails
     * @throws YHDeviceException                  If the device returns an error
     * @throws YHInvalidResponseException         If the response from the device cannot be parsed
     * @throws YHConnectionException              If the connection to the device fails
     * @throws InvalidKeyException                If the encryption/decryption fails
     * @throws YHAuthenticationException          If the session authentication fails
     * @throws NoSuchPaddingException             If the encryption/decryption fails
     * @throws InvalidAlgorithmParameterException If the encryption/decryption fails
     * @throws BadPaddingException                If the encryption/decryption fails
     * @throws IllegalBlockSizeException          If the encryption/decryption fails
     * @throws UnsupportedAlgorithmException      If the hash Algorithm is not one of {@link Algorithm#RSA_MGF1_SHA1},
     *                                            {@link Algorithm#RSA_MGF1_SHA256}, {@link Algorithm#RSA_MGF1_SHA384},
     *                                            {@link Algorithm#RSA_MGF1_SHA512}
     */
    public byte[] signPss(@NonNull final YHSession session, @NonNull final Algorithm mgf1Algorithm, final short saltLength, byte[] data)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, UnsupportedAlgorithmException {

        if (!isMgf1Algorithm(mgf1Algorithm)) {
            throw new UnsupportedAlgorithmException("Unsupported hash algorithm to use for MGF1");
        }

        final byte[] hashedData = getHashedData(data, mgf1Algorithm);

        if (hashedData.length != getHashLength(mgf1Algorithm)) {
            throw new InvalidParameterException("Length of hashed data must be 20, 32, 48 or 64");
        }

        ByteBuffer bb = ByteBuffer.allocate(OBJECT_ID_SIZE + OBJECT_ALGORITHM_SIZE + SIGN_PSS_SALT_LENGTH + hashedData.length);
        bb.putShort(getId());
        bb.put(mgf1Algorithm.getId());
        bb.putShort(saltLength);
        bb.put(hashedData);

        byte[] signature = session.sendSecureCmd(Command.SIGN_PSS, bb.array());
        log.info("Signed data with key 0x" + Integer.toHexString(getId()) + " and returned " + signature.length + " bytes signature");
        return signature;
    }

    /**
     * Decrypt data that was encrypted using RSA-PKCS#1v1.5. Length of the data has to be 256, 384 or 512 bytes
     * <p>
     * The data is padded using the PKCS#1v1.5 scheme with Block Type 2. The data is decrypted and conformance to the padding scheme is checked
     * then removed before returning the contained message
     *
     * @param session An authenticated session to communicate with the device over
     * @param enc     Data encrypted using RSA-PKCS#1v1.5
     * @return The decrypted data
     * @throws NoSuchAlgorithmException           If the encryption/decryption fails
     * @throws YHDeviceException                  If the device returns an error
     * @throws YHInvalidResponseException         If the response from the device cannot be parsed
     * @throws YHConnectionException              If the connection to the device fails
     * @throws InvalidKeyException                If the encryption/decryption fails
     * @throws YHAuthenticationException          If the session authentication fails
     * @throws NoSuchPaddingException             If the encryption/decryption fails
     * @throws InvalidAlgorithmParameterException If the encryption/decryption fails
     * @throws BadPaddingException                If the encryption/decryption fails
     * @throws IllegalBlockSizeException          If the encryption/decryption fails
     * @throws UnsupportedAlgorithmException      If the key algorithm is not recognized (This should never happen)
     */
    public byte[] decryptPkcs1(@NonNull final YHSession session, @NonNull byte[] enc)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, UnsupportedAlgorithmException {
        if (enc.length != getBlockSize(getKeyAlgorithm())) {
            throw new IllegalArgumentException("Length of encrypted data must be 256, 384 or 512");
        }

        ByteBuffer bb = ByteBuffer.allocate(OBJECT_ID_SIZE + enc.length);
        bb.putShort(getId());
        bb.put(enc);

        byte[] dec = session.sendSecureCmd(Command.DECRYPT_PKCS1, bb.array());
        log.info("Decrypted data with key 0x" + Integer.toHexString(getId()) + " and returned " + dec.length + " bytes");
        return dec;
    }

    /**
     * Decrypt data using RSA-OAEP. Length of the data has to be 256, 384 or 512 bytes
     *
     * @param session       An authenticated session to communicate with the device over
     * @param enc           Encrypted data. 256, 384 or 512 bytes long
     * @param label         Optional label to be associated with the message
     * @param mgf1Algorithm The hash algorithm to use for MGF1. Can be one of {@link Algorithm#RSA_MGF1_SHA1}, {@link Algorithm#RSA_MGF1_SHA256},
     *                      {@link Algorithm#RSA_MGF1_SHA384},{@link Algorithm#RSA_MGF1_SHA512}
     * @param hashAlgorithm The hash algorithm to use for hashing the label. Can be one of {@link Algorithm#RSA_OAEP_SHA1},
     *                      {@link Algorithm#RSA_OAEP_SHA256}, {@link Algorithm#RSA_OAEP_SHA384}, {@link Algorithm#RSA_OAEP_SHA512}
     * @return The decrypted data
     * @throws NoSuchAlgorithmException           If the encryption/decryption fails
     * @throws YHDeviceException                  If the device returns an error
     * @throws YHInvalidResponseException         If the response from the device cannot be parsed
     * @throws YHConnectionException              If the connection to the device fails
     * @throws InvalidKeyException                If the encryption/decryption fails
     * @throws YHAuthenticationException          If the session authentication fails
     * @throws NoSuchPaddingException             If the encryption/decryption fails
     * @throws InvalidAlgorithmParameterException If the encryption/decryption fails
     * @throws BadPaddingException                If the encryption/decryption fails
     * @throws IllegalBlockSizeException          If the encryption/decryption fails
     * @throws UnsupportedAlgorithmException      If the MGF1 algorithm is not one of {@link Algorithm#RSA_MGF1_SHA1},
     *                                            {@link Algorithm#RSA_MGF1_SHA256}, {@link Algorithm#RSA_MGF1_SHA384},
     *                                            {@link Algorithm#RSA_MGF1_SHA512} or if the hash algorithm is not one of
     *                                            {@link Algorithm#RSA_OAEP_SHA1}, {@link Algorithm#RSA_OAEP_SHA256},
     *                                            {@link Algorithm#RSA_OAEP_SHA384}, {@link Algorithm#RSA_OAEP_SHA512}
     */
    public byte[] decryptOaep(@NonNull final YHSession session, @NonNull final byte[] enc, final String label, @NonNull final Algorithm mgf1Algorithm,
                              @NonNull final Algorithm hashAlgorithm)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, UnsupportedAlgorithmException {

        if (!isOaepHashAlgorithm(hashAlgorithm)) {
            throw new UnsupportedAlgorithmException(hashAlgorithm.toString());
        }
        if (!isMgf1Algorithm(mgf1Algorithm)) {
            throw new UnsupportedAlgorithmException(mgf1Algorithm.toString());
        }

        if (enc.length != getBlockSize(getKeyAlgorithm())) {
            throw new InvalidParameterException("Length of encrypted data must be 256, 384 or 512");
        }

        byte[] hashedLabel = getHashedData(label != null ? label.getBytes() : new byte[0], hashAlgorithm);


        ByteBuffer bb = ByteBuffer.allocate(OBJECT_ID_SIZE + OBJECT_ALGORITHM_SIZE + enc.length + hashedLabel.length);
        bb.putShort(getId());
        bb.put(mgf1Algorithm.getId());
        bb.put(enc);
        bb.put(hashedLabel);

        byte[] dec = session.sendSecureCmd(Command.DECRYPT_OAEP, bb.array());
        log.info("Decrypted data with key 0x" + Integer.toHexString(getId()) + " and returned " + dec.length + " bytes");
        return dec;

    }

    // ------------- Help methods ---------------------------------------

    /**
     * @return The data block size
     */
    private static int getBlockSize(@NonNull final Algorithm algorithm) throws UnsupportedAlgorithmException {
        if (algorithm.equals(Algorithm.RSA_2048)) {
            return BLOCK_SIZE_FOR_RSA2048;
        } else if (algorithm.equals(Algorithm.RSA_3072)) {
            return BLOCK_SIZE_FOR_RSA3072;
        } else if (algorithm.equals(Algorithm.RSA_4096)) {
            return BLOCK_SIZE_FOR_RSA4096;
        } else {
            throw new UnsupportedAlgorithmException("Unsupported RSA Algorithm: " + algorithm.toString());
        }
    }

    /**
     * @return The length of the hash data should be when signing using PSS RSA
     */
    private int getHashLength(@NonNull final Algorithm algorithm) throws UnsupportedAlgorithmException {
        if (algorithm.equals(Algorithm.RSA_MGF1_SHA1) || algorithm.equals(Algorithm.RSA_OAEP_SHA1)) {
            return HASH_LENGTH_FOR_SHA1;
        }
        if (algorithm.equals(Algorithm.RSA_MGF1_SHA256) || algorithm.equals(Algorithm.RSA_OAEP_SHA256)) {
            return HASH_LENGTH_FOR_SHA256;
        }
        if (algorithm.equals(Algorithm.RSA_MGF1_SHA384) || algorithm.equals(Algorithm.RSA_OAEP_SHA384)) {
            return HASH_LENGTH_FOR_SHA384;
        }
        if (algorithm.equals(Algorithm.RSA_MGF1_SHA512) || algorithm.equals(Algorithm.RSA_OAEP_SHA512)) {
            return HASH_LENGTH_FOR_SHA512;
        }
        throw new UnsupportedAlgorithmException("Unsupported hash algorithm to use for MGF1");
    }

    private boolean isOaepHashAlgorithm(@NonNull final Algorithm algorithm) {
        if (algorithm.equals(Algorithm.RSA_OAEP_SHA1) || algorithm.equals(Algorithm.RSA_OAEP_SHA256) || algorithm.equals(Algorithm.RSA_OAEP_SHA384) ||
            algorithm.equals(Algorithm.RSA_OAEP_SHA512)) {
            return true;
        }
        return false;
    }

    private boolean isPkcs1HashAlgorithm(@NonNull final Algorithm algorithm) {
        if (algorithm.equals(Algorithm.RSA_PKCS1_SHA1) || algorithm.equals(Algorithm.RSA_PKCS1_SHA256) ||
            algorithm.equals(Algorithm.RSA_PKCS1_SHA384) || algorithm.equals(Algorithm.RSA_PKCS1_SHA512)) {
            return true;
        }
        return false;
    }

    private boolean isMgf1Algorithm(@NonNull final Algorithm algorithm) {
        if (algorithm.equals(Algorithm.RSA_MGF1_SHA1) || algorithm.equals(Algorithm.RSA_MGF1_SHA256) || algorithm.equals(Algorithm.RSA_MGF1_SHA384) ||
            algorithm.equals(Algorithm.RSA_MGF1_SHA512)) {
            return true;
        }
        return false;
    }

    private static void verifyParametersForNewKeyRsa(@NonNull final List<Integer> domains, @NonNull final Algorithm keyAlgorithm,
                                                     @NonNull final byte[] primeP, @NonNull final byte[] primeQ)
            throws UnsupportedAlgorithmException {
        if (domains.isEmpty()) {
            throw new IllegalArgumentException("Domains parameter cannot be null or empty");
        }
        if (!isRsaKeyAlgorithm(keyAlgorithm)) {
            throw new IllegalArgumentException("Key algorithm must be a supported RSA algorithm");
        }

        final int componentLength = getBlockSize(keyAlgorithm) / 2;
        if (primeP.length != componentLength) {
            throw new IllegalArgumentException(
                    "Invalid parameter. Expected primeP that is " + componentLength + " bytes long, but was " + primeP.length + " bytes");
        }
        if (primeQ.length != componentLength) {
            throw new IllegalArgumentException(
                    "Invalid parameter. Expected primeQ that is " + componentLength + " bytes long, but was " + primeQ.length + " bytes");
        }
    }

}
