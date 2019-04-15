package com.yubico.objects.yhobjects;

import com.yubico.YHSession;
import com.yubico.exceptions.*;
import com.yubico.internal.util.Utils;
import com.yubico.objects.yhconcepts.Algorithm;
import com.yubico.objects.yhconcepts.Capability;
import com.yubico.objects.yhconcepts.Command;

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

    static Logger logger = Logger.getLogger(AsymmetricKeyEd.class.getName());

    private AsymmetricKeyEd(final YHObject key) {
        super(key);
    }

    /**
     * Returns an instance of this ED Key
     *
     * @param key The key properties
     * @return An instance of the ED Key
     * @throws UnsupportedAlgorithmException If the algorithm specified in the properties is not an RSA key algorithm. Currently, only ed25519 is
     *                                       supported
     */
    public static AsymmetricKeyEd getInstance(final YHObject key) throws UnsupportedAlgorithmException {
        if (key.getAlgorithm() != null && key.getAlgorithm().isEdAlgorithm()) {
            return new AsymmetricKeyEd(key);
        }
        throw new UnsupportedAlgorithmException("The object is not an ED key");
    }

    /**
     * Imports a user generated ED key into the YubiHSM
     *
     * @param session      An authenticated session to communicate with the device over
     * @param id           The ID of the Asymmetric Key. 0 if the ID is to be generated by the device
     * @param label        The Asymmetric Key label
     * @param domains      The domains where the Asymmetric Key will be operating within
     * @param capabilities The capabilities of the Asymmetric Key
     * @param algorithm    The algorithm used to generate the asymmetric key
     * @param k            The private key integer k.
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
     * @throws UnsupportedAlgorithmException      If the specified key algorithm is not an ED algorithm
     */
    public static short importKey(final YHSession session, short id, final String label, final List<Integer> domains,
                                  final List<Capability> capabilities, final Algorithm algorithm, final byte[] k)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException, UnsupportedAlgorithmException {
        checkNullParameters(session, domains, capabilities, algorithm);
        Utils.checkEmptyByteArray(k, "Missing parameter: k");
        if (!algorithm.isEdAlgorithm()) {
            throw new UnsupportedAlgorithmException("Specified algorithm is not a supported ED algorithm");
        }

        if (k.length != 32) {
            throw new InvalidParameterException("Invalid parameter: k");
        }
        return putKey(session, id, getLabel(label), domains, capabilities, algorithm, k, null);
    }

    /**
     * Returns the public component of this ED key.
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
    @Override
    public Object getPublicKey(final YHSession session)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException {
        ByteBuffer bb = ByteBuffer.allocate(2);
        bb.putShort(getId());

        byte[] resp = session.sendSecureCmd(Command.GET_PUBLIC_KEY, bb.array());
        bb = ByteBuffer.wrap(resp);
        final Algorithm algorithm = Algorithm.getAlgorithm(bb.get());
        if (algorithm==null || !algorithm.equals(getAlgorithm())) {
            throw new YHInvalidResponseException("The public key algorithm returned by the device does not match the private key algorithm");
        }

        byte[] pubkey = new byte[bb.remaining()];
        bb.get(pubkey);
        logger.info("Returned public EC key with ID 0x" + Integer.toHexString(getId()));
        return pubkey;

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
    public byte[] signEddsa(final YHSession session, final byte[] data)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException {
        if (!getAlgorithm().isEdAlgorithm()) {
            throw new UnsupportedOperationException("This operation is only available for ED keys");
        }

        ByteBuffer bb = ByteBuffer.allocate(2 + data.length);
        bb.putShort(getId());
        bb.put(data);

        byte[] signature = session.sendSecureCmd(Command.SIGN_EDDSA, bb.array());
        logger.info("Signed data with key 0x" + Integer.toHexString(getId()));
        return signature;
    }
}
