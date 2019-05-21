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
import com.yubico.hsm.exceptions.YHAuthenticationException;
import com.yubico.hsm.exceptions.YHConnectionException;
import com.yubico.hsm.exceptions.YHDeviceException;
import com.yubico.hsm.exceptions.YHInvalidResponseException;
import com.yubico.hsm.internal.util.CommandUtils;
import com.yubico.hsm.internal.util.Utils;
import com.yubico.hsm.yhconcepts.Algorithm;
import com.yubico.hsm.yhconcepts.Capability;
import com.yubico.hsm.yhconcepts.Command;
import com.yubico.hsm.yhconcepts.Type;
import com.yubico.hsm.yhdata.YHObjectInfo;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.List;

/**
 * Class representing an Authentication Key Object
 */
@Slf4j
public class AuthenticationKey extends YHObject {

    public static final Type TYPE = Type.TYPE_AUTHENTICATION_KEY;

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int KEY_SIZE = 16;
    private static final byte[] SALT = "Yubico".getBytes();
    private static final int ITERATIONS = 10000;

    /** The long term encryption key of this Authentication Key */
    private byte[] encryptionKey = null;
    /** The long term MAC key of this Authentication Key */
    private byte[] macKey = null;

    /**
     * Creates an AuthenticationKey object
     *
     * @param id     The ID uniquely identifying the authentication key
     * @param encKey The long term encryption key
     * @param macKey The long term MAC key
     */
    public AuthenticationKey(final short id, @NonNull final byte[] encKey, @NonNull final byte[] macKey) {
        super(id, TYPE);
        this.encryptionKey = encKey;
        this.macKey = macKey;
    }

    /**
     * Creates an AuthenticationKey object containing the long term encryption key and MAC key derived from the password
     *
     * @param id       The Object ID of the authentication key
     * @param password The password to derive the long term encryption key and MAC key from
     */
    public AuthenticationKey(final short id, char[] password) throws InvalidKeySpecException, NoSuchAlgorithmException {
        super(id, TYPE);
        Object[] keys = deriveSecretKey(password);
        encryptionKey = (byte[]) keys[0];
        macKey = (byte[]) keys[1];
    }

    /**
     * @return The long term encryption key of this Authentication Key
     */
    public byte[] getEncryptionKey() {
        return encryptionKey;
    }

    /**
     * @return The long term MAC key of this Authentication Key
     */
    public byte[] getMacKey() {
        return macKey;
    }

    private static Object[] deriveSecretKey(@NonNull char[] password) throws InvalidKeySpecException, NoSuchAlgorithmException {
        if (password.length == 0) {
            throw new IllegalArgumentException("Missing password for derivation of authentication key");
        }

        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
        PBEKeySpec keySpec = new PBEKeySpec(password, SALT, ITERATIONS, KEY_SIZE * 2 * 8); // keyLength in bits: 2 keys each KEY_SIZE long * 8 bits
        // in each byte
        SecretKey key = keyFactory.generateSecret(keySpec);
        final byte[] keybytes = key.getEncoded();

        Object[] keys = new Object[2];
        keys[0] = Arrays.copyOfRange(keybytes, 0, KEY_SIZE);
        keys[1] = Arrays.copyOfRange(keybytes, KEY_SIZE, keybytes.length);

        Arrays.fill(password, 'c');
        return keys;
    }

    private static void destroysKeys(byte[] encKey, byte[] macKey) {
        if (encKey != null) {
            Arrays.fill(encKey, (byte) 0x00);
        }
        if (macKey != null) {
            Arrays.fill(macKey, (byte) 0x00);
        }
    }

    /**
     * Destroys the long term keys from the cache memory
     */
    public void destroyKeys() {
        destroysKeys(encryptionKey, macKey);
        log.info("Destroyed long term encryption key and MAC key");
    }

    /**
     * Imports an new Authentication Key into the device
     *
     * @param session               An authenticated session to communicate with the device over
     * @param id                    The desired Object ID of the new Authentication key. Set to 0 to have it generated
     * @param label                 The label of the new Authentication key
     * @param domains               The domains where the new Authentication key can operate
     * @param keyAlgorithm          The algorithm used to derive the long term encryption key and MAC key. Currently, only {
     *                              {@link Algorithm.AES128_YUBICO_AUTHENTICATION}} is supported
     * @param capabilities          The actions that can be performed while inside a session authenticated using the new Authentication key
     * @param delegatedCapabilities The capabilities that can be bestowed on an object created or imported during a session authenticated with the
     *                              new Authentication key
     * @param encryptionKey         Long term encryption key
     * @param macKey                Long term MAC key
     * @return ID of the Authentication Key on the device
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
    public static short importAuthenticationKey(@NonNull final YHSession session, final short id, final String label,
                                                @NonNull final List<Integer> domains, Algorithm keyAlgorithm, final List<Capability> capabilities,
                                                final List<Capability> delegatedCapabilities, @NonNull byte[] encryptionKey, @NonNull byte[] macKey)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException {
        verifyParametersForNewKey(domains, keyAlgorithm, encryptionKey, macKey);

        ByteBuffer bb = ByteBuffer.allocate(
                OBJECT_ID_SIZE + OBJECT_LABEL_SIZE + OBJECT_DOMAINS_SIZE + OBJECT_CAPABILITIES_SIZE + OBJECT_ALGORITHM_SIZE +
                OBJECT_DELEGATED_CAPABILITIES_SIZE + KEY_SIZE + KEY_SIZE);
        bb.putShort(id);
        bb.put(Arrays.copyOf(Utils.getLabel(label).getBytes(), OBJECT_LABEL_SIZE));
        bb.putShort(Utils.getShortFromList(domains));
        bb.putLong(Utils.getLongFromCapabilities(capabilities));
        bb.put(keyAlgorithm == null ? Algorithm.AES128_YUBICO_AUTHENTICATION.getId() : keyAlgorithm.getId());
        bb.putLong(Utils.getLongFromCapabilities(delegatedCapabilities));
        bb.put(encryptionKey);
        bb.put(macKey);

        byte[] resp = session.sendSecureCmd(Command.PUT_AUTHENTICATION_KEY, bb.array());
        CommandUtils.verifyResponseLength(Command.PUT_AUTHENTICATION_KEY, resp.length, OBJECT_ID_SIZE);

        bb = ByteBuffer.wrap(resp);
        short newid = bb.getShort();

        destroysKeys(encryptionKey, macKey);

        log.info("Created Authentication key with ID 0x" + Integer.toHexString(newid));

        return newid;
    }

    /**
     * Imports an new Authentication Key into the device
     *
     * @param session               An authenticated session to communicate with the device over
     * @param id                    The desired Object ID of the new Authentication key. Set to 0 to have it generated
     * @param label                 The label of the new Authentication key
     * @param domains               The domains where the new Authentication key can operate
     * @param keyAlgorithm          The algorithm used to derive the long term encryption key and MAC key. Currently, only {
     *                              {@link Algorithm.AES128_YUBICO_AUTHENTICATION}} is supported
     * @param capabilities          The actions that can be performed while inside a session authenticated using the new Authentication key
     * @param delegatedCapabilities The capabilities that can be bestowed on an object created or imported during a session authenticated with the
     *                              new Authentication key
     * @param password              The password to derive the long term encryption key and MAC key from
     * @return ID of the Authentication Key on the device
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
     * @throws InvalidKeySpecException            If the derivation of the long term keys from the password fails
     */
    public static short importAuthenticationKey(final YHSession session, final short id, final String label,
                                                @NonNull final List<Integer> domains, Algorithm keyAlgorithm, final List<Capability> capabilities,
                                                final List<Capability> delegatedCapabilities, char[] password)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException, InvalidKeySpecException {
        Object[] secretKeys = deriveSecretKey(password);
        byte[] encKey = (byte[]) secretKeys[0];
        byte[] macKey = (byte[]) secretKeys[1];
        short newid = importAuthenticationKey(session, id, label, domains, keyAlgorithm, capabilities, delegatedCapabilities, encKey, macKey);

        Arrays.fill(password, 'c');

        return newid;
    }

    /**
     * Changes the long term encryption key and MAC key of an Authentication Key
     *
     * @param session       An authenticated session to communicate with the device over
     * @param id            The ID of the Authentication Key to change
     * @param encryptionKey Long term encryption key
     * @param macKey        Long term MAC key
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
    public static void changeAuthenticationKey(final @NonNull YHSession session, final short id, @NonNull byte[] encryptionKey,
                                               @NonNull byte[] macKey)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException {

        if (encryptionKey.length != KEY_SIZE || macKey.length != KEY_SIZE) {
            throw new InvalidParameterException("Long term encryption key and MAC key have to be of size " + KEY_SIZE);
        }

        YHObjectInfo keyinfo = getObjectInfo(session, id, TYPE);

        ByteBuffer bb = ByteBuffer.allocate(OBJECT_ID_SIZE + OBJECT_ALGORITHM_SIZE + KEY_SIZE + KEY_SIZE);
        bb.putShort(id);
        bb.put(keyinfo.getAlgorithm().getId());
        bb.put(encryptionKey);
        bb.put(macKey);
        byte[] resp = session.sendSecureCmd(Command.CHANGE_AUTHENTICATION_KEY, bb.array());
        CommandUtils.verifyResponseLength(Command.CHANGE_AUTHENTICATION_KEY, resp.length, OBJECT_ID_SIZE);

        bb = ByteBuffer.wrap(resp);
        short changedId = bb.getShort();
        if (changedId != id) {
            throw new YHInvalidResponseException(
                    "Object ID of the changed Authentication key is incorrect. Expected ID is 0x" + Integer.toHexString(id) + " but was 0x" +
                    Integer.toHexString(changedId));
        }

        destroysKeys(encryptionKey, macKey);

        log.info("Changed Authentication key with ID 0x" + Integer.toHexString(id));
    }

    /**
     * Changes the long term encryption key and MAC key of an Authentication Key
     *
     * @param session  An authenticated session to communicate with the device over
     * @param id       The ID of the Authentication Key to change
     * @param password The password to derive the long term encryption key and MAC key from
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
     * @throws InvalidKeySpecException            If the derivation of the long term keys from the password fails
     */
    public static void changeAuthenticationKey(final YHSession session, short id, char[] password)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException, InvalidKeySpecException {
        Object[] secretKeys = deriveSecretKey(password);
        byte[] encKey = (byte[]) secretKeys[0];
        byte[] macKey = (byte[]) secretKeys[1];
        changeAuthenticationKey(session, id, encKey, macKey);

        Arrays.fill(password, 'c');
    }

    private static void verifyParametersForNewKey(@NonNull final List<Integer> domains, @NonNull final Algorithm keyAlgorithm,
                                                  @NonNull final byte[] encryptionKey, @NonNull final byte[] macKey) {
        if (domains.isEmpty()) {
            throw new IllegalArgumentException("Domains parameter cannot be null or empty");
        }
        if (keyAlgorithm != null && !keyAlgorithm.equals(Algorithm.AES128_YUBICO_AUTHENTICATION)) {
            throw new IllegalArgumentException(
                    "Currently, the only supported Authentication Key parameter is " + Algorithm.AES128_YUBICO_AUTHENTICATION.toString());
        }
        if (encryptionKey.length != KEY_SIZE || macKey.length != KEY_SIZE) {
            throw new IllegalArgumentException("Each of the long term encryption key and MAC key have to be of size " + KEY_SIZE + ". Instead, " +
                                               "found " + encryptionKey.length + " bytes encryption key and " + macKey.length + " bytes MAC key");
        }
    }

}