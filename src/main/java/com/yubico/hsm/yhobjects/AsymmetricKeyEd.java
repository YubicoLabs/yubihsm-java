package com.yubico.hsm.yhobjects;

import com.yubico.hsm.YHSession;
import com.yubico.hsm.exceptions.YHAuthenticationException;
import com.yubico.hsm.exceptions.YHConnectionException;
import com.yubico.hsm.exceptions.YHDeviceException;
import com.yubico.hsm.exceptions.YHInvalidResponseException;
import com.yubico.hsm.yhconcepts.Algorithm;
import com.yubico.hsm.yhconcepts.Capability;
import com.yubico.hsm.yhconcepts.Command;
import lombok.NonNull;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
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
        if (!isEdAlgorithm(keyAlgorithm)) {
            throw new IllegalArgumentException("An Asymmetric key algorithm must be a supported ED algorithm");
        }
        setId(id);
        setType(TYPE);
        setKeyAlgorithm(keyAlgorithm);
    }

    /**
     * Imports a user generated ED key into the YubiHSM
     *
     * @param session              An authenticated session to communicate with the device over
     * @param id                   The desired Object ID of the imported ED key. Set to 0 to have it generated
     * @param label                The label of the imported ED key
     * @param domains              The domains where the imported ED key will be accessible
     * @param keyAlgorithm         The algorithm used to generate the imported ED key
     * @param capabilities         The actions that can be performed using the imported ED key
     * @param privateKeyParameters The private key to import.
     * @return ID of the imported ED key on the device
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
    public static short importKey(final YHSession session, final short id, final String label, @NonNull final List<Integer> domains,
                                  @NonNull final Algorithm keyAlgorithm, final List<Capability> capabilities, @NonNull final
                                  Ed25519PrivateKeyParameters privateKeyParameters)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException {
        return importKey(session, id, label, domains, keyAlgorithm, capabilities, privateKeyParameters.getEncoded());
    }

    /**
     * Imports a user generated ED key into the YubiHSM
     *
     * @param session      An authenticated session to communicate with the device over
     * @param id           The desired Object ID of the imported ED key. Set to 0 to have it generated
     * @param label        The label of the imported ED key
     * @param domains      The domains where the imported ED key will be accessible
     * @param keyAlgorithm The algorithm used to generate the imported ED key
     * @param capabilities The actions that can be performed using the imported ED key
     * @param k            The private key integer k.
     * @return ID of the imported ED key on the device
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
    public static short importKey(final YHSession session, final short id, final String label, @NonNull final List<Integer> domains,
                                  @NonNull final Algorithm keyAlgorithm, final List<Capability> capabilities, @NonNull final byte[] k)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException {
        verifyParametersForNewKeyEd(domains, keyAlgorithm, k);
        return putKey(session, id, label, domains, keyAlgorithm, capabilities, k, null);
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
        ByteBuffer bb = ByteBuffer.allocate(OBJECT_ID_SIZE + data.length);
        bb.putShort(getId());
        bb.put(data);

        byte[] signature = session.sendSecureCmd(Command.SIGN_EDDSA, bb.array());
        log.info("Signed data with key 0x" + Integer.toHexString(getId()));
        return signature;
    }

    private static void verifyParametersForNewKeyEd(@NonNull final List<Integer> domains, @NonNull final Algorithm keyAlgorithms,
                                                    @NonNull final byte[] k) {
        if (domains.isEmpty()) {
            throw new IllegalArgumentException("Domains parameter cannot be null or empty");
        }
        if (!isEdAlgorithm(keyAlgorithms)) {
            throw new IllegalArgumentException("Key algorithm must be a supported ED algorithm");
        }

        if (k.length != 32) {
            throw new IllegalArgumentException("Invalid parameter. Expected private key integer k that is " + 32 + " bytes long, but" +
                                               " was " + k.length + " bytes");
        }
    }
}
