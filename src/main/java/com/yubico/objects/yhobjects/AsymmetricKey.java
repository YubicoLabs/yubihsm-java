package com.yubico.objects.yhobjects;

import com.yubico.YHSession;
import com.yubico.exceptions.*;
import com.yubico.internal.util.Utils;
import com.yubico.objects.yhconcepts.Algorithm;
import com.yubico.objects.yhconcepts.Capability;
import com.yubico.objects.yhconcepts.Command;
import com.yubico.objects.yhconcepts.ObjectType;
import lombok.NonNull;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

public class AsymmetricKey extends YHObject {
    private static Logger log = Logger.getLogger(AsymmetricKey.class.getName());

    public static final ObjectType TYPE = ObjectType.TYPE_ASYMMETRIC_KEY;

    private Algorithm keyAlgorithm;

    protected AsymmetricKey() {}

    /**
     * Creates an AsymmetricKey object
     *
     * @param id           The Object ID of this key
     * @param keyAlgorithm A supported RSA, EC or ED key algorithm
     */
    public AsymmetricKey(final short id, @NonNull final Algorithm keyAlgorithm) {
        if (!isAsymmetricKeyAlgorithm(keyAlgorithm)) {
            throw new IllegalArgumentException("An Asymmetric key algorithm must be a supported RSA, EC or ED algorithm");
        }
        setId(id);
        setType(TYPE);
        this.keyAlgorithm = keyAlgorithm;
    }

    public Algorithm getKeyAlgorithm() {
        return keyAlgorithm;
    }

    protected void setKeyAlgorithm(@NonNull final Algorithm algorithm) {
        this.keyAlgorithm = algorithm;
    }

    public static boolean isAsymmetricKeyAlgorithm(final Algorithm algorithm) {
        return isRsaKeyAlgorithm(algorithm) || isEcAlgorithm(algorithm) || isEdAlgorithm(algorithm);
    }

    /**
     * @return True `algorithm` is a supported algorithm for RSA keys. False otherwise
     */
    public static boolean isRsaKeyAlgorithm(final Algorithm algorithm) {
        List rsaAlgorithms = Arrays.asList(Algorithm.RSA_2048, Algorithm.RSA_3072, Algorithm.RSA_4096);
        return rsaAlgorithms.contains(algorithm);
    }

    /**
     * @return True if `algorithm` is a supported algorithm for EC keys. False otherwise
     */
    public static boolean isEcAlgorithm(final Algorithm algorithm) {
        List ecAlgorithsms = Arrays.asList(Algorithm.EC_P256, Algorithm.EC_P384, Algorithm.EC_P521, Algorithm.EC_K256, Algorithm.EC_BP256,
                                           Algorithm.EC_BP384, Algorithm.EC_BP512, Algorithm.EC_P224);
        return ecAlgorithsms.contains(algorithm);
    }

    /**
     * @return True `algorithm` is a supported algorithm for ED keys. False otherwise
     */
    public static boolean isEdAlgorithm(final Algorithm algorithm) {
        return algorithm.equals(Algorithm.EC_ED25519);
    }


    /**
     * Generates an asymmetric key on the YubiHSM
     *
     * @param session      An authenticated session to communicate with the device over
     * @param id           The desired object ID for the new Asymmetric key. Set to 0 to have it generated
     * @param label        The label of the new Asymmetric key. Must be a maximum of 40 characters
     * @param domains      The domains where the new Asymmetric key can be available
     * @param keyAlgorithm The algorithm used to generate the new Asymmetric key
     * @param capabilities The actions that can be performed using the new Asymmetric key
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
    public static short generateAsymmetricKey(@NonNull final YHSession session, final short id, final String label,
                                              @NonNull final List<Integer> domains, @NonNull final Algorithm keyAlgorithm,
                                              final List<Capability> capabilities)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException {
        verifyParametersForNewKey(domains, keyAlgorithm);

        ByteBuffer bb =
                ByteBuffer.allocate(OBJECT_ID_SIZE + OBJECT_LABEL_SIZE + OBJECT_DOMAINS_SIZE + OBJECT_CAPABILITIES_SIZE + OBJECT_ALGORITHM_SIZE);
        bb.putShort(id);
        bb.put(Arrays.copyOf(Utils.getLabel(label).getBytes(), OBJECT_LABEL_SIZE));
        bb.putShort(Utils.getShortFromList(domains));
        bb.putLong(Capability.getCapabilities(capabilities));
        bb.put(keyAlgorithm.getAlgorithmId());

        byte[] resp = session.sendSecureCmd(Command.GENERATE_ASYMMETRIC_KEY, bb.array());
        if (resp.length != OBJECT_ID_SIZE) {
            throw new YHInvalidResponseException(
                    "Response to " + Command.GENERATE_ASYMMETRIC_KEY.getName() + " command expected to contains " + OBJECT_ID_SIZE +
                    " bytes, but was " +
                    resp.length + " bytes instead");
        }

        bb = ByteBuffer.wrap(resp);
        short newid = bb.getShort();

        log.info("Generated asymmetric key with ID 0x" + Integer.toHexString(newid) + " using " + keyAlgorithm.getName() + " algorithm");
        return newid;
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
     */
    public byte[] getPublicKey(@NonNull final YHSession session)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException {
        ByteBuffer bb = ByteBuffer.allocate(OBJECT_ID_SIZE);
        bb.putShort(getId());

        byte[] resp = session.sendSecureCmd(Command.GET_PUBLIC_KEY, bb.array());
        bb = ByteBuffer.wrap(resp);
        final Algorithm algorithm = Algorithm.getAlgorithm(bb.get());
        if (algorithm == null || !algorithm.equals(getKeyAlgorithm())) {
            throw new YHInvalidResponseException("The public key algorithm was " + algorithm.toString() + ", which does not match the private key " +
                                                 "algorithm " + getKeyAlgorithm().toString());
        }

        byte[] pubKey = new byte[bb.remaining()];
        bb.get(pubKey);
        log.info("Returned public key bytes with ID 0x" + Integer.toHexString(getId()) + " and algorithm " + algorithm.toString());
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
     */
    public X509Certificate signAttestationCertificate(final YHSession session, final short keyToAttest)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, CertificateException {
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
     */
    public static X509Certificate signAttestationCertificate(@NonNull final YHSession session, final short keyToAttest, final short attestingKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, CertificateException {
        if (keyToAttest == 0) {
            throw new IllegalArgumentException("Missing Asymmetric key to attest");
        }

        try {
            getObjectInfo(session, attestingKey, ObjectType.TYPE_OPAQUE);
        } catch (YHDeviceException e) {
            if (e.getYhError().equals(YHError.OBJECT_NOT_FOUND)) {
                throw new UnsupportedOperationException("To sign attestation certificates, there has to exist a template X509Certificate with ID " +
                                                        "0x" + Integer.toHexString(attestingKey) + ". Please use the Opaque class to import such a " +
                                                        "template certificate and try again");
            } else {
                throw e;
            }
        }

        ByteBuffer bb = ByteBuffer.allocate(OBJECT_ID_SIZE + OBJECT_ID_SIZE);
        bb.putShort(keyToAttest);
        bb.putShort(attestingKey);

        byte[] cert = session.sendSecureCmd(Command.SIGN_ATTESTATION_CERTIFICATE, bb.array());
        return getCertFromBytes(cert);
    }

    private static X509Certificate getCertFromBytes(@NonNull final byte[] certBytes) throws CertificateException {
        ByteArrayInputStream in = new ByteArrayInputStream(certBytes);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(in);
    }

    /**
     * Sends the Put Asymmetric Key command to the device
     */
    protected static short putKey(@NonNull final YHSession session, final short id, final String label, @NonNull final List<Integer> domains,
                                  @NonNull final Algorithm keyAlgorithm, final List<Capability> capabilities, @NonNull final byte[] p1,
                                  final byte[] p2)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException {
        verifyParametersForNewKey(domains, keyAlgorithm);

        int length = OBJECT_ID_SIZE + OBJECT_LABEL_SIZE + OBJECT_DOMAINS_SIZE + OBJECT_CAPABILITIES_SIZE + OBJECT_ALGORITHM_SIZE + p1.length;
        if (p2 != null) {
            length += p2.length;
        }

        ByteBuffer bb = ByteBuffer.allocate(length);
        bb.putShort(id);
        bb.put(Arrays.copyOf(Utils.getLabel(label).getBytes(), OBJECT_LABEL_SIZE));
        bb.putShort(Utils.getShortFromList(domains));
        bb.putLong(Capability.getCapabilities(capabilities));
        bb.put(keyAlgorithm.getAlgorithmId());
        bb.put(p1);
        if (p2 != null) {
            bb.put(p2);
        }

        byte[] resp = session.sendSecureCmd(Command.PUT_ASYMMETRIC_KEY, bb.array());
        if (resp.length != OBJECT_ID_SIZE) {
            throw new YHInvalidResponseException(
                    "Response to " + Command.PUT_ASYMMETRIC_KEY.getName() + " command expected to contains " + OBJECT_ID_SIZE + " bytes, but " +
                    "was " + resp.length + " bytes instead");
        }
        bb = ByteBuffer.wrap(resp);
        short newid = bb.getShort();

        log.info("Imported asymmetric key with ID 0x" + Integer.toHexString(newid) + " and algorithm " + keyAlgorithm.getName());
        return newid;
    }

    /**
     * @return The digest of the input data
     */
    protected byte[] getHashedData(final byte[] data, @NonNull final Algorithm algorithm) throws NoSuchAlgorithmException {
        MessageDigest digest;
        if (algorithm.equals(Algorithm.RSA_PKCS1_SHA1) || algorithm.equals(Algorithm.RSA_MGF1_SHA1) ||
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

    private static void verifyParametersForNewKey(@NonNull final List<Integer> domains, Algorithm keyAlgorithm) {
        if (domains.isEmpty()) {
            throw new IllegalArgumentException("Domains parameter cannot be null or empty");
        }
        if (!isAsymmetricKeyAlgorithm(keyAlgorithm)) {
            throw new IllegalArgumentException("Key algorithm must be a supported RSA, EC or ED algorithm");
        }
    }

}
