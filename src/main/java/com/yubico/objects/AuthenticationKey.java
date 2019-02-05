package com.yubico.objects;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * Class defining the Authentication Key Object
 */
public class AuthenticationKey {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int KEY_SIZE = 16;
    private static final byte[] SALT = "Yubico".getBytes();
    private static final int ITERATIONS = 10000;

    /**
     * The Authentication Key's ObjectID on the device
     */
    private short authKeyID;
    /**
     * The long term encryption key of this Authentication Key
     */
    private byte[] encryptionKey;
    /**
     * The long term MAC key of this Authentication Key
     */
    private byte[] macKey;

    private AuthenticationKey(final short id, final byte[] encKey, final byte[] macKey) {
        this.authKeyID = id;
        this.encryptionKey = encKey;
        this.macKey = macKey;
    }

    /**
     * Return an instance of the Authentication Key whose ID is `keyId`
     *
     * @param keyId         The Authentication Key's ObjectID on the device
     * @param encryptionKey The long term encryption key of this Authentication Key
     * @param macKey        The long term MAC key of this Authentication Key
     * @return An instance of this Authentication Key
     */
    public static AuthenticationKey getInstance(final short keyId, final byte[] encryptionKey, final byte[] macKey) {
        return new AuthenticationKey(keyId, encryptionKey, macKey);
    }

    /**
     * Return an instance of the Authentication Key whose ID is `keyId`
     *
     * @param keyId    The Authentication Key's ObjectID on the device
     * @param password The password to derive the long term encryption key and MAC key from
     * @return An instance of this Authentication Key
     * @throws NoSuchAlgorithmException When failing to derive the encryption key and the MAC key
     * @throws InvalidKeySpecException  When failing to derive the encryption key and the MAC key
     */
    public static AuthenticationKey getInstance(final short keyId, final char[] password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
        PBEKeySpec keySpec = new PBEKeySpec(password, SALT, ITERATIONS, KEY_SIZE * 2 * 8);
        SecretKey key = keyFactory.generateSecret(keySpec);
        final byte[] keyBytes = key.getEncoded();

        ByteBuffer encKey = ByteBuffer.allocate(KEY_SIZE);
        encKey.put(keyBytes, 0, KEY_SIZE);

        ByteBuffer macKey = ByteBuffer.allocate(KEY_SIZE);
        macKey.put(keyBytes, KEY_SIZE, KEY_SIZE);

        return new AuthenticationKey(keyId, encKey.array(), macKey.array());
    }

    /**
     * @return The Authentication Key ID
     */
    public short getAuthKeyID() {
        return authKeyID;
    }

    /**
     * @return The Authentication Key long term encryption key
     */
    public byte[] getEncryptionKey() {
        return encryptionKey;
    }

    /**
     * @return The Authentication Key long term MAC key
     */
    public byte[] getMacKey() {
        return macKey;
    }

}



