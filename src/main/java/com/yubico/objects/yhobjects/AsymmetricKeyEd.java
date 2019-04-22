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
import lombok.NonNull;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.logging.Logger;

public class AsymmetricKeyEd extends AsymmetricKey {
    private static Logger log = Logger.getLogger(AsymmetricKeyEd.class.getName());

    /**
     * Creates an AsymmetriKeyEd object
     *
     * @param id           The object ID of this key
     * @param keyAlgorithm A supported ED key algorithm
     */
    public AsymmetricKeyEd(final short id, @NonNull final Algorithm keyAlgorithm) {
        if (!keyAlgorithm.isEdAlgorithm()) {
            throw new IllegalArgumentException("An Asymmetric key algorithm must be a supported ED algorithm");
        }
        setId(id);
        setType(TYPE);
        setKeyAlgorithm(keyAlgorithm);
    }

    /**
     * Imports a user generated ED key into the YubiHSM
     *
     * @param session An authenticated session to communicate with the device over
     * @param keyinfo The metadata of the key to import. Set the ID to 0 to have it generated
     * @param k       The private key integer k.
     * @return ID of the ED key on the device
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
    public static short importKey(final YHSession session, @NonNull final YHObjectInfo keyinfo, @NonNull final byte[] k)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException {
        verifyObjectInfoForNewKeyEd(keyinfo);
        if (k.length != 32) {
            throw new InvalidParameterException("Invalid parameter: k");
        }
        return putKey(session, keyinfo, k, null);
    }

    /**
     * Returns the public component of this ED key.
     * <p>
     * This is the same as calling getPublicKey in AsymmetricKey.java
     *
     * @param session An authenticated session to communicate with the device over
     * @return The public component of this ED key as a byte array
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
    public byte[] getEdPublicKey(final YHSession session)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException {
        return super.getPublicKey(session);
    }

    /**
     * Signs the input data using EdDSA. Currently, only Ed25519 is supported
     *
     * @param session An authenticated session to communicate with the device over
     * @param data    The raw data to sign
     * @return The signature, 64 bytes
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
    public byte[] signEddsa(@NonNull final YHSession session, @NonNull final byte[] data)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException {
        ByteBuffer bb = ByteBuffer.allocate(2 + data.length);
        bb.putShort(getId());
        bb.put(data);

        byte[] signature = session.sendSecureCmd(Command.SIGN_EDDSA, bb.array());
        log.info("Signed data with key 0x" + Integer.toHexString(getId()));
        return signature;
    }

    /**
     * Converts the input parameters into an ObjectInfo object. This object is meant to be used when generating or importing a new ED key
     *
     * @param id           The object ID of the key. Use 0 to have the ID generated
     * @param label        The key label
     * @param domains      The domains where the key will be accessible
     * @param keyAlgorithm The key generation algorithm
     * @param capabilities The capabilities of the ED key
     * @return An ObjectInfo object
     */
    public static YHObjectInfo getObjectInfoForNewKey(final short id, final String label, @NonNull final List<Integer> domains,
                                                      @NonNull final Algorithm keyAlgorithm, final List<Capability> capabilities) {
        if (domains.isEmpty()) {
            throw new IllegalArgumentException("An Asymmetric key must be accessible on at least 1 domain to be useful");
        }
        if (!keyAlgorithm.isEdAlgorithm()) {
            throw new IllegalArgumentException("Algorithm must be a supported ED algorithm");
        }
        return new YHObjectInfo(id, TYPE, Utils.getLabel(label), domains, keyAlgorithm, capabilities, null);
    }

    private static void verifyObjectInfoForNewKeyEd(@NonNull final YHObjectInfo keyinfo) {
        verifyObjectInfoForNewKey(keyinfo);
        if (!keyinfo.getAlgorithm().isEdAlgorithm()) {
            throw new IllegalArgumentException("Key algorithm must be a supported ED algorithm");
        }
    }
}
