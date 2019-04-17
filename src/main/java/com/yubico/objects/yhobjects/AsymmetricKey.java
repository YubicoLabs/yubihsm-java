package com.yubico.objects.yhobjects;

import com.yubico.YHCore;
import com.yubico.YHSession;
import com.yubico.exceptions.*;
import com.yubico.internal.util.Utils;
import com.yubico.objects.yhconcepts.Algorithm;
import com.yubico.objects.yhconcepts.Capability;
import com.yubico.objects.yhconcepts.Command;
import com.yubico.objects.yhconcepts.ObjectType;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

public class AsymmetricKey extends YHObject {
    private static Logger logger = Logger.getLogger(AsymmetricKey.class.getName());

    public static final ObjectType TYPE = ObjectType.TYPE_ASYMMETRIC_KEY;

    /**
     * Creates an AsymmetricKey object
     *
     * @param key The key properties
     */
    public AsymmetricKey(YHObject key) {
        super(key.getId(), key.getType(), key.getCapabilities(), key.getObjectSize(), key.getDomains(), key.getAlgorithm(),
              key.getSequence(), key.getOrigin(), key.getLabel(), key.getDelegatedCapabilities());
    }

    /**
     * Generates an asymmetric key on the YubiHSM
     *
     * @param session      An authenticated session to communicate with the device over
     * @param id           The ID of the Asymmetric Key. 0 if the ID is to be generated by the device
     * @param label        The Asymmetric Key label
     * @param domains      The domains where the Asymmetric Key will be operating within
     * @param capabilities The capabilities of the Asymmetric Key
     * @param algorithm    The algorithm used to generate the asymmetric key
     * @return ID of the Asymmetric Key generated on the device
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
    public static short generateAsymmetricKey(final YHSession session, short id, String label, final List<Integer> domains,
                                              final List<Capability> capabilities, final Algorithm algorithm)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException {
        checkNullParameters(session, domains, capabilities, algorithm);

        ByteBuffer bb = ByteBuffer.allocate(53);
        bb.putShort(id);
        bb.put(Arrays.copyOf(getLabel(label).getBytes(), LABEL_LENGTH));
        bb.putShort(Utils.getShortFromList(domains));
        bb.putLong(Capability.getCapabilities(capabilities));
        bb.put(algorithm.getAlgorithmId());

        byte[] resp = session.sendSecureCmd(Command.GENERATE_ASYMMETRIC_KEY, bb.array());
        bb = ByteBuffer.wrap(resp);
        id = bb.getShort();

        logger.info("Generated asymmetric key with ID 0x" + Integer.toHexString(id));
        return id;
    }

    /**
     * Return the public key of this asymmetric key as a byte array
     *
     * @param session An authenticated session to communicate with the device over
     * @return The public key as a byte array
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
    public Object getPublicKey(final YHSession session)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidKeySpecException, InvalidParameterSpecException, UnsupportedAlgorithmException,
                   NoSuchProviderException {
        ByteBuffer bb = ByteBuffer.allocate(2);
        bb.putShort(getId());

        byte[] resp = session.sendSecureCmd(Command.GET_PUBLIC_KEY, bb.array());
        bb = ByteBuffer.wrap(resp);
        final Algorithm algorithm = Algorithm.getAlgorithm(bb.get());
        if (algorithm == null || !algorithm.equals(getAlgorithm())) {
            throw new YHInvalidResponseException("The public key algorithm was " + algorithm.toString() + ", which does not match the private key " +
                                                 "algorithm " + getAlgorithm().toString());
        }

        byte[] pubKey = new byte[bb.remaining()];
        bb.get(pubKey);
        logger.info("Returned public key bytes with ID 0x" + Integer.toHexString(getId()));
        return pubKey;
    }

    /**
     * Returns an X509Certificate signed by this Asymmetric key and contains the public key of the Asymmetric key whose ID is 'keyToAttest'
     * <p>
     * For this to work, there has to be an template X509Certificate object stored with the same ID as this Asymmetric key. There are no requirements
     * regarding this template certificate apart from it having to be an X509Certificate
     *
     * @param session     An authenticated session to communicate with the device over
     * @param keyToAttest The object ID of the key that is to be attested
     * @return A certificate signed by this Asymmetric key and contains the public key of the 'keyToAttest'
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
    public X509Certificate signAttestationCertificate(final YHSession session, final short keyToAttest)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, CertificateException, InvalidSessionException {
        return signAttestationCertificate(session, keyToAttest, getId());
    }

    /**
     * Returns an X509Certificate signed by the Asymmetric key whose ID is 'attestingKey' and contains the public key of the Asymmetric key whose
     * ID is 'keyToAttest'
     * <p>
     * For this to work, there has to be an template X509Certificate object stored with the same ID as 'attestingKey'. There are no requirements
     * regarding this template certificate apart from it having to be an X509Certificate
     *
     * @param session      An authenticated session to communicate with the device over
     * @param keyToAttest  The object ID of the key that is to be attested
     * @param attestingKey The object ID of the key that will sign the attestation certificate
     * @return A certificate signed by 'attestingKey' and contains the public key of the 'keyToAttest'
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
    public static X509Certificate signAttestationCertificate(final YHSession session, final short keyToAttest, final short attestingKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, CertificateException, InvalidSessionException {
        if (keyToAttest == 0) {
            throw new InvalidParameterException("Missing Asymmetric key to attest");
        }

        try {
            YHCore.getObjectInfo(session, attestingKey, ObjectType.TYPE_OPAQUE);
        } catch (YHDeviceException e) {
            if (e.getErrorCode().equals(YHError.OBJECT_NOT_FOUND)) {
                throw new UnsupportedOperationException("To sign attestation certificates, there has to exist a template X509Certificate with ID " +
                                                        "0x" + Integer.toHexString(attestingKey) + ". Please use the Opaque class to import such a " +
                                                        "template certificate and try again");
            } else {
                throw e;
            }
        }

        ByteBuffer bb = ByteBuffer.allocate(4);
        bb.putShort(keyToAttest);
        bb.putShort(attestingKey);

        byte[] cert = session.sendSecureCmd(Command.SIGN_ATTESTATION_CERTIFICATE, bb.array());
        return getCertFromBytes(cert);
    }

    private static X509Certificate getCertFromBytes(final byte[] certBytes) throws CertificateException {
        ByteArrayInputStream in = new ByteArrayInputStream(certBytes);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(in);
    }

    /**
     * Throws an InvalidParameterException if any of the input parameters are null
     */
    protected static void checkNullParameters(final YHSession session, final List<Integer> domains, final List<Capability> capabilities,
                                              final Algorithm algorithm) {
        Utils.checkNullValue(session, "Session is null. Creating a new authentication key must be done over an authenticated session");
        Utils.checkEmptyList(domains, "For a key to be useful, it must be accessible in at least one domain");
        Utils.checkNullValue(capabilities, "Missing capabilities");
        Utils.checkNullValue(algorithm, "Missing key algorithm");
    }

    /**
     * Sends the Put Asymmetric Key command to the device
     */
    protected static short putKey(final YHSession session, short id, final String label, final List<Integer> domains,
                                  final List<Capability> capabilities, final Algorithm algorithm, final byte[] p1, final byte[] p2)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException {

        int length = 53 + p1.length; // 2 + 40 + 2 + 8 + 1 + p1 length
        if (p2 != null) {
            length += p2.length;
        }

        ByteBuffer bb = ByteBuffer.allocate(length);
        bb.putShort(id);
        bb.put(Arrays.copyOf(label.getBytes(), LABEL_LENGTH));
        bb.putShort(Utils.getShortFromList(domains));
        bb.putLong(Capability.getCapabilities(capabilities));
        bb.put(algorithm.getAlgorithmId());
        bb.put(p1);
        if (p2 != null) {
            bb.put(p2);
        }

        byte[] resp = session.sendSecureCmd(Command.PUT_ASYMMETRIC_KEY, bb.array());
        bb = ByteBuffer.wrap(resp);
        id = bb.getShort();

        logger.info("Imported asymmetric key with ID 0x" + Integer.toHexString(id) + " and algorithm " + algorithm.toString());
        return id;
    }

    /**
     * @return The digest of the input data
     */
    protected byte[] getHashedData(final byte[] data, final Algorithm algorithm) throws NoSuchAlgorithmException {
        MessageDigest digest;
        // TODO When implementation is done, if this scenario does not happen, remove the default
        if (algorithm == null) {
            return data;
        } else if (algorithm.equals(Algorithm.RSA_PKCS1_SHA1) || algorithm.equals(Algorithm.RSA_MGF1_SHA1) ||
                   algorithm.equals(Algorithm.EC_ECDSA_SHA1) || algorithm.equals(Algorithm.RSA_OAEP_SHA1)) {
            digest = MessageDigest.getInstance("SHA-1");
        } else if (algorithm.equals(Algorithm.RSA_PKCS1_SHA256) || algorithm.equals(Algorithm.RSA_MGF1_SHA256) ||
                   algorithm.equals(Algorithm.EC_ECDSA_SHA256) || algorithm.equals(Algorithm.RSA_OAEP_SHA256)) {
            digest = MessageDigest.getInstance("SHA-256");
        } else if (algorithm.equals(Algorithm.RSA_PKCS1_SHA384) || algorithm.equals(Algorithm.RSA_MGF1_SHA384) ||
                   algorithm.equals(Algorithm.EC_ECDSA_SHA384) || algorithm.equals(Algorithm.RSA_OAEP_SHA384)) {
            digest = MessageDigest.getInstance("SHA-384");
        } else if (algorithm.equals(Algorithm.RSA_PKCS1_SHA512) || algorithm.equals(Algorithm.RSA_MGF1_SHA512) ||
                   algorithm.equals(Algorithm.EC_ECDSA_SHA512) || algorithm.equals(Algorithm.RSA_OAEP_SHA512)) {
            digest = MessageDigest.getInstance("SHA-512");
        } else {
            throw new InvalidParameterException("Unsupported hash algorithm " + algorithm.toString());
        }
        return digest.digest(data);
    }

}
