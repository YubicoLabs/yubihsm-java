package com.yubico.objects.yhobjects;

import com.yubico.YHSession;
import com.yubico.exceptions.YHAuthenticationException;
import com.yubico.exceptions.YHConnectionException;
import com.yubico.exceptions.YHDeviceException;
import com.yubico.exceptions.YHInvalidResponseException;
import com.yubico.internal.util.Utils;
import com.yubico.objects.yhconcepts.Algorithm;
import com.yubico.objects.yhconcepts.Capability;
import com.yubico.objects.yhconcepts.Command;
import com.yubico.objects.yhconcepts.ObjectType;
import lombok.NonNull;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

/**
 * Class representing an Authentication Key Object
 */
public class AuthenticationKey extends YHObject {
    private static Logger log = Logger.getLogger(AuthenticationKey.class.getName());

    public static final ObjectType TYPE = ObjectType.TYPE_AUTHENTICATION_KEY;

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
        List keys = deriveSecretKey(password);
        encryptionKey = (byte[]) keys.get(0);
        macKey = (byte[]) keys.get(1);
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

    private static List deriveSecretKey(@NonNull char[] password) throws InvalidKeySpecException, NoSuchAlgorithmException {
        if (password.length == 0) {
            throw new IllegalArgumentException("Missing password for derivation of authentication key");
        }

        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
        PBEKeySpec keySpec = new PBEKeySpec(password, SALT, ITERATIONS, KEY_SIZE * 2 * 8); // keyLength in bits: 2 keys each KEY_SIZE long * 8 bits
        // in each byte
        SecretKey key = keyFactory.generateSecret(keySpec);
        final byte[] keybytes = key.getEncoded();

        ArrayList keys = new ArrayList();
        keys.add(Arrays.copyOfRange(keybytes, 0, KEY_SIZE));
        keys.add(Arrays.copyOfRange(keybytes, KEY_SIZE, keybytes.length));

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
        log.info("Destroyed long term encryption key and MAC key from cache");
    }

    /**
     * Imports an new Authentication Key into the device
     *
     * @param session       An authenticated session to communicate with the device over
     * @param keyInfo       The metadata of the Authentication key. Set the ID to 0 to have it generated
     * @param encryptionKey Long term encryption key
     * @param macKey        Long term MAC key
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
    public static short importAuthenticationKey(@NonNull final YHSession session, @NonNull final YHObjectInfo keyInfo,
                                                @NonNull byte[] encryptionKey, @NonNull byte[] macKey)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException {
        verifyObjectInfoForNewKey(keyInfo);
        if (encryptionKey.length != KEY_SIZE || macKey.length != KEY_SIZE) {
            throw new IllegalArgumentException("Each of the long term encryption key and MAC key have to be of size " + KEY_SIZE);
        }

        ByteBuffer bb = ByteBuffer.allocate(93); // 2 bytes objectID + 40 bytes label + 2 bytes domains + 8 bytes capabilities + 1 byte algorithm +
        // 8 bytes delegated capabilities + 16 bytes encryption key + 16 bytes MAC key
        bb.putShort(keyInfo.getId());
        bb.put(Arrays.copyOf(keyInfo.getLabel().getBytes(), YHObjectInfo.LABEL_LENGTH));
        bb.putShort(Utils.getShortFromList(keyInfo.getDomains()));
        bb.putLong(Capability.getCapabilities(keyInfo.getCapabilities()));
        bb.put(keyInfo.getAlgorithm().getAlgorithmId());
        bb.putLong(Capability.getCapabilities(keyInfo.getDelegatedCapabilities()));
        bb.put(encryptionKey);
        bb.put(macKey);

        byte[] resp = session.sendSecureCmd(Command.PUT_AUTHENTICATION_KEY, bb.array());
        bb = ByteBuffer.wrap(resp);
        short id = bb.getShort();

        destroysKeys(encryptionKey, macKey);

        log.info("Created an Authentication key with ID 0x" + Integer.toHexString(id));

        return id;
    }

    /**
     * Imports an new Authentication Key into the device
     *
     * @param session  An authenticated session to communicate with the device over
     * @param keyinfo  The metadata of the Authentication key. Set the ID to 0 to have it generated
     * @param password The password to derive the long term encryption key and MAC key from
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
    public static short importAuthenticationKey(final YHSession session, final YHObjectInfo keyinfo, char[] password)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException, InvalidKeySpecException {
        List secretKey = deriveSecretKey(password);
        byte[] encKey = (byte[]) secretKey.get(0);
        byte[] macKey = (byte[]) secretKey.get(1);
        short id = importAuthenticationKey(session, keyinfo, encKey, macKey);

        Arrays.fill(password, 'c');

        return id;
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

        ByteBuffer bb = ByteBuffer.allocate(35);
        bb.putShort(id);
        bb.put(keyinfo.getAlgorithm().getAlgorithmId());
        bb.put(encryptionKey);
        bb.put(macKey);
        session.sendSecureCmd(Command.CHANGE_AUTHENTICATION_KEY, bb.array());

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
        List secretKey = deriveSecretKey(password);
        byte[] encKey = (byte[]) secretKey.get(0); // Arrays.copyOfRange(secretKey, 0, KEY_SIZE);
        byte[] macKey = (byte[]) secretKey.get(1); // Arrays.copyOfRange(secretKey, KEY_SIZE, secretKey.length);
        changeAuthenticationKey(session, id, encKey, macKey);

        Arrays.fill(password, 'c');
    }

    /**
     * Converts the input parameters into an ObjectInfo object. This object is meant to be used when adding a new Authentication key
     *
     * @param id The object ID of the key. Use 0 to have the ID generated
     * @param label The key label
     * @param domains The domains where the key will be accessible
     * @param capabilities The capabilities of the Authentication key
     * @param delegatedCapabilities The delegated capabilities of the Authentication key
     * @return An ObjectInfo object
     */
    public static YHObjectInfo getObjectInfoForNewKey(final short id, final String label, @NonNull final List<Integer> domains,
                                                      final List<Capability> capabilities, final List<Capability> delegatedCapabilities) {
        if (domains.isEmpty()) {
            throw new IllegalArgumentException("An Authentication key must be accessible on at least 1 domain to be useful");
        }
        return new YHObjectInfo(id, TYPE, Utils.getLabel(label), domains, Algorithm.AES128_YUBICO_AUTHENTICATION, capabilities,
                                delegatedCapabilities);
    }

    private static void verifyObjectInfoForNewKey(@NonNull final YHObjectInfo keyinfo) {
        if (keyinfo.getType() != null && !keyinfo.getType().equals(TYPE)) {
            throw new IllegalArgumentException("The key information does not belong to an Authentication key");
        }
        if (keyinfo.getDomains() == null || keyinfo.getDomains().isEmpty()) {
            throw new IllegalArgumentException("Domains parameter cannot be null or empty");
        }
        if (keyinfo.getAlgorithm() != null && !keyinfo.getAlgorithm().equals(Algorithm.AES128_YUBICO_AUTHENTICATION)) {
            throw new IllegalArgumentException(
                    "Currently, the only supported Authentication Key parameter is " + Algorithm.AES128_YUBICO_AUTHENTICATION.toString());
        }
    }

}