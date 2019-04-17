package com.yubico.objects.yhobjects;

import com.yubico.YHSession;
import com.yubico.exceptions.YHAuthenticationException;
import com.yubico.exceptions.YHConnectionException;
import com.yubico.exceptions.YHDeviceException;
import com.yubico.exceptions.YHInvalidResponseException;
import com.yubico.internal.util.Utils;
import com.yubico.objects.yhconcepts.*;

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
import java.util.logging.Logger;

/**
 * Class representing an Authentication Key Object
 */
public class AuthenticationKey extends YHObject {

    private static Logger logger = Logger.getLogger(AuthenticationKey.class.getName());

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
     * Creates an AuthenticationKey object containing the key's properties, without setting the long term encryption key and MAC key
     *
     * @param objectId              The ID uniquely identifying the authentication key
     * @param capabilities          What operations are allowed over a session authenticated with this authentication key
     * @param size                  The size of the authentication key in bytes
     * @param domains               The domains that this authentication key kan operate within
     * @param algorithm             The algorithm used to generate this authentication key
     * @param sequence              The number of previous authentication keys that had had the same ID
     * @param origin                Where the authentication key has been generated originally
     * @param label                 They authentication key label
     * @param delegatedCapabilities What capabilities can be bestowed on other objects that were created over a session authenticated with this
     *                              authentication key
     */
    public AuthenticationKey(final short objectId, final List<Capability> capabilities, final short size, final List<Integer> domains,
                             final Algorithm algorithm, final byte sequence, final ObjectOrigin origin, final String label,
                             final List<Capability> delegatedCapabilities) {
        super(objectId, TYPE, capabilities, size, domains, algorithm, sequence, origin, label, delegatedCapabilities);
    }

    /**
     * Creates an AuthenticationKey object containing the key's properties, without setting the long term encryption key and MAC key
     *
     * @param data Byte The object data as a byte array in the form of {8 bytes capabilities + 2 bytes object ID + 2 bytes object size + 2 bytes domains
     *             + 1 byte type + 1 byte algorithm + 1 byte sequence + 1 byte object origin + 40 bytes label + 8 bytes delegated capabilities}
     */
    public AuthenticationKey(final byte[] data) {
        super(data);
    }


    /**
     * Creates an AuthenticationKey object containing the long term encryption key and MAC key
     *
     * @param id     The ID uniquely identifying the authentication key
     * @param encKey The long term encryption key
     * @param macKey The long term MAC key
     */
    public AuthenticationKey(final short id, final byte[] encKey, final byte[] macKey) {
        super(id, TYPE);
        this.encryptionKey = encKey;
        this.macKey = macKey;
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

    /**
     * Derives the long term encryption key and MAC key from the given password
     *
     * @param password The password to derive the long term encryption key and MAC key from
     * @throws NoSuchAlgorithmException When failing to derive the encryption key and the MAC key
     * @throws InvalidKeySpecException  When failing to derive the encryption key and the MAC key
     */
    public void deriveAuthenticationKey(char[] password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] secretKey = deriveSecretKey(password);
        encryptionKey = Arrays.copyOfRange(secretKey, 0, KEY_SIZE);
        macKey = Arrays.copyOfRange(secretKey, KEY_SIZE, secretKey.length);

        password = new char[password.length];
    }

    private static byte[] deriveSecretKey(char[] password) throws InvalidKeySpecException, NoSuchAlgorithmException {
        if (password == null || password.length == 0) {
            throw new InvalidParameterException("Missing password for derivation of authentication key");
        }

        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
        PBEKeySpec keySpec = new PBEKeySpec(password, SALT, ITERATIONS, KEY_SIZE * 2 * 8); // keyLength in bits
        SecretKey key = keyFactory.generateSecret(keySpec);
        return key.getEncoded();
    }

    /**
     * @return True if the long term encryption key and MAC key are set. False otherwise
     */
    public boolean isInitializedForSession() {
        return encryptionKey != null && macKey != null;
    }

    /**
     * Wipes the long term keys from the cache memory
     */
    public void destroyKeys() {
        encryptionKey = new byte[encryptionKey.length];
        encryptionKey = null;
        macKey = new byte[macKey.length];
        macKey = null;
        logger.info("Destroyed long term encryption key and MAC key from cache");
    }

    /**
     * Imports an new Authentication Key into the device
     *
     * @param session               An authenticated session to communicate with the device over
     * @param id                    The ID of the Authentication Key. 0 if the ID is to be generated by the device
     * @param label                 The Authentication Key label
     * @param domains               The domains where the Authentication Key will be operating within
     * @param capabilities          The capabilities of the Authentication Key
     * @param delegatedCapabilities Capabilities that the Authentication Key can bestow on other objects
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
    public static short importAuthenticationKey(final YHSession session, short id, final String label, final List<Integer> domains,
                                                final List<Capability> capabilities,
                                                final List<Capability> delegatedCapabilities, byte[] encryptionKey, byte[] macKey)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException {
        Utils.checkNullValue(session, "Session is null. Creating a new authentication key must be done over an authenticated session");
        Utils.checkEmptyList(domains, "Missing domains parameter. Authentication Key must be able to operate within at least one domain");
        Utils.checkEmptyList(capabilities, "Missing capabilities");
        Utils.checkEmptyByteArray(encryptionKey, "Missing encryption key. To create a new authentication key, a 16 byte encryption key is needed");
        Utils.checkEmptyByteArray(macKey, "Missing MAC key. To create a new authentication key, a 16 byte MAC key is needed");
        if (encryptionKey.length != KEY_SIZE || macKey.length != KEY_SIZE) {
            throw new InvalidParameterException("Long term encryption key and MAC key have to be of size " + KEY_SIZE);
        }

        ByteBuffer bb = ByteBuffer.allocate(93);
        bb.putShort(id);
        bb.put(Arrays.copyOf(getLabel(label).getBytes(), LABEL_LENGTH));
        bb.putShort(Utils.getShortFromList(domains));
        bb.putLong(Capability.getCapabilities(capabilities));
        bb.put(Algorithm.AES128_YUBICO_AUTHENTICATION.getAlgorithmId());
        bb.putLong(Capability.getCapabilities(delegatedCapabilities));
        bb.put(encryptionKey);
        bb.put(macKey);

        byte[] resp = session.sendSecureCmd(Command.PUT_AUTHENTICATION_KEY, bb.array());
        bb = ByteBuffer.wrap(resp);
        id = bb.getShort();

        encryptionKey = new byte[encryptionKey.length];
        macKey = new byte[macKey.length];

        logger.info("Created an Authentication key with ID 0x"  + Integer.toHexString(id));

        return id;
    }

    /**
     * Imports an new Authentication Key into the device
     *
     * @param session               An authenticated session to communicate with the device over
     * @param id                    The ID of the Authentication Key. 0 if the ID is to be generated by the device
     * @param label                 The Authentication Key label
     * @param domains               The domains where the Authentication Key will be operating within
     * @param capabilities          The capabilities of the Authentication Key
     * @param delegatedCapabilities Capabilities that the Authentication Key can bestow on other objects
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
    public static short importAuthenticationKey(final YHSession session, short id, final String label, final List<Integer> domains,
                                                final List<Capability> capabilities, final List<Capability> delegatedCapabilities, char[] password)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException, InvalidKeySpecException {
        byte[] secretKey = deriveSecretKey(password);
        byte[] encKey = Arrays.copyOfRange(secretKey, 0, KEY_SIZE);
        byte[] macKey = Arrays.copyOfRange(secretKey, KEY_SIZE, secretKey.length);
        id = importAuthenticationKey(session, id, label, domains, capabilities, delegatedCapabilities, encKey, macKey);

        password = new char[password.length];

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
    public static void changeAuthenticationKey(final YHSession session, short id, byte[] encryptionKey, byte[] macKey)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException {
        Utils.checkNullValue(session, "Session is null. Creating a new authentication key must be done over an authenticated session");
        Utils.checkEmptyByteArray(encryptionKey, "Missing encryption key. To create a new authentication key, a 16 byte encryption key is needed");
        Utils.checkEmptyByteArray(macKey, "Missing MAC key. To create a new authentication key, a 16 byte MAC key is needed");
        if (encryptionKey.length != KEY_SIZE || macKey.length != KEY_SIZE) {
            throw new InvalidParameterException("Long term encryption key and MAC key have to be of size " + KEY_SIZE);
        }

        ByteBuffer bb = ByteBuffer.allocate(35);
        bb.putShort(id);
        bb.put(Algorithm.AES128_YUBICO_AUTHENTICATION.getAlgorithmId());
        bb.put(encryptionKey);
        bb.put(macKey);
        session.sendSecureCmd(Command.CHANGE_AUTHENTICATION_KEY, bb.array());

        encryptionKey = new byte[encryptionKey.length];
        macKey = new byte[macKey.length];

        logger.info("Changed Authentication key with ID 0x"  + Integer.toHexString(id));
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
        byte[] secretKey = deriveSecretKey(password);
        byte[] encKey = Arrays.copyOfRange(secretKey, 0, KEY_SIZE);
        byte[] macKey = Arrays.copyOfRange(secretKey, KEY_SIZE, secretKey.length);
        changeAuthenticationKey(session, id, encKey, macKey);

        password = new char[password.length];
    }

}