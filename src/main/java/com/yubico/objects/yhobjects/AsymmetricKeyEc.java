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
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.*;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

public class AsymmetricKeyEc extends AsymmetricKey {

    private static Logger logger = Logger.getLogger(AsymmetricKeyEc.class.getName());

    /**
     * Created an AsymmetricKeyEc object
     *
     * @param keyinfo
     */
    public AsymmetricKeyEc(final YHObject keyinfo) {
        super(keyinfo);
    }

    /**
     * Returns an instance of this EC Key
     *
     * @param key The key properties
     * @return An instance of the EC Key
     * @throws UnsupportedAlgorithmException If the algorithm specified in the properties is not an EC key algorithm
     */
    public static AsymmetricKeyEc getInstance(final YHObject key) throws UnsupportedAlgorithmException {
        if (key.getAlgorithm() != null && key.getAlgorithm().isEcAlgorithm()) {
            return new AsymmetricKeyEc(key);
        }
        throw new UnsupportedAlgorithmException("The object is not an EC key");
    }

    /**
     * Imports a user generated EC key into the YubiHSM
     *
     * @param session      An authenticated session to communicate with the device over
     * @param id           The ID of the Asymmetric Key. 0 if the ID is to be generated by the device
     * @param label        The Asymmetric Key label
     * @param domains      The domains where the Asymmetric Key will be operating within
     * @param capabilities The capabilities of the Asymmetric Key
     * @param algorithm    The algorithm used to generate the asymmetric key
     * @param d            The private key integer d
     * @return ID of the EC key on the device
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
     * @throws UnsupportedAlgorithmException      If the specified key algorithm is not an EC algorithm
     */
    public static short importKey(final YHSession session, short id, final String label, final List<Integer> domains,
                                  final List<Capability> capabilities, final Algorithm algorithm, final byte[] d)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException, UnsupportedAlgorithmException {
        checkNullParameters(session, domains, capabilities, algorithm);
        Utils.checkEmptyByteArray(d, "Missing parameter d");
        if (!algorithm.isEcAlgorithm()) {
            throw new UnsupportedAlgorithmException("Specified algorithm is not a supported EC algorithm");
        }

        if (d.length != getEcComponentLength(algorithm)) {
            throw new InvalidParameterException("Invalid parameter: d");
        }

        if (!algorithm.isEcAlgorithm()) {
            throw new InvalidParameterException("Specified algorithm is not a supported EC algorithm");
        }

        return putKey(session, id, getLabel(label), domains, capabilities, algorithm, d, null);
    }

    /**
     * Returns the public component of this EC key
     *
     * @param session An authenticated session to communicate with the device over
     * @return The public component of this EC key as a java.security.PublicKey object
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
     * @throws InvalidParameterSpecException      If failed to construct the public key object
     * @throws UnsupportedAlgorithmException      If the asymmetric key algorithm is not recognized
     * @throws NoSuchProviderException            If BouncyCastle was not find as a security provider
     */
    @Override
    public Object getPublicKey(final YHSession session)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidKeySpecException, InvalidParameterSpecException, NoSuchProviderException {
        ByteBuffer bb = ByteBuffer.allocate(2);
        bb.putShort(getId());

        byte[] resp = session.sendSecureCmd(Command.GET_PUBLIC_KEY, bb.array());
        bb = ByteBuffer.wrap(resp);
        final Algorithm algorithm = Algorithm.getAlgorithm(bb.get());
        if (algorithm == null || !algorithm.equals(getAlgorithm())) {
            throw new YHInvalidResponseException("The public key algorithm returned by the device does not match the private key algorithm");
        }

        byte[] x = new byte[bb.remaining() / 2];
        bb.get(x);
        byte[] y = new byte[bb.remaining()];
        bb.get(y);

        ECPoint pubPoint = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
        if (algorithm.equals(Algorithm.EC_BP256) || algorithm.equals(Algorithm.EC_BP384) || algorithm.equals(Algorithm.EC_BP512)) {
            return getEcBrainpoolPublicKey(pubPoint);
        } else {
            return getEcPublicKey(pubPoint);
        }

    }

    /**
     * Signs the input data using ECDSA
     *
     * @param session       An authenticated session to communicate with the device over
     * @param data          The raw data to sign
     * @param hashAlgorithm The digest algorithm used to hash the data before signing it. Can be one of
     *                      {{@link Algorithm.EC_ECDSA_SHA1}}, {{@link Algorithm.EC_ECDSA_SHA256}}, {{@link Algorithm.EC_ECDSA_SHA384}},
     *                      {{@link Algorithm.EC_ECDSA_SHA512}}
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
    public byte[] signEcdsa(final YHSession session, final byte[] data, final Algorithm hashAlgorithm)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException {
        if (!getAlgorithm().isEcAlgorithm()) {
            throw new UnsupportedOperationException("This operation is only available for EC keys");
        }

        final byte[] hashedData = getHashedData(data, hashAlgorithm);
        return signEcdsa(session, hashedData);
    }

    /**
     * Signs the input data using ECDSA. The input data is expected to be a hash of the raw data
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
    public byte[] signEcdsa(final YHSession session, final byte[] dataDigest)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException {
        if (!getAlgorithm().isEcAlgorithm()) {
            throw new UnsupportedOperationException("This operation is only available for EC keys");
        }

        ByteBuffer bb = ByteBuffer.allocate(2 + dataDigest.length);
        bb.putShort(getId());
        bb.put(dataDigest);

        byte[] signature = session.sendSecureCmd(Command.SIGN_ECDSA, bb.array());
        logger.info("Signed data with key 0x" + Integer.toHexString(getId()));
        return signature;
    }

    /**
     * Perform an ECDH operation on this private key and the public component of another EC key
     *
     * @param session   An authenticated session to communicate with the device over
     * @param publicKey The public component of another EC key
     * @return The shared secret
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
    public byte[] deriveEcdh(final YHSession session, final byte[] publicKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException {
        if (!getAlgorithm().isEcAlgorithm()) {
            throw new UnsupportedOperationException("This operation is only available for EC keys");
        }

        ByteBuffer bb = ByteBuffer.allocate(2 + publicKey.length);
        bb.putShort(getId());
        bb.put(publicKey);

        byte[] ecdh = session.sendSecureCmd(Command.DERIVE_ECDH, bb.array());
        logger.info("Derived ECDH key from private key 0x" + Integer.toHexString(getId()) + " and public key " + Utils.getPrintableBytes(publicKey));
        return ecdh;
    }


    // -------------------- help methods -------------------------------------

    /**
     * Converts the ECPoint into a PublicKey object using the java native libraries. Used for the following algorithms:
     *
     * <ul>
     * <li>{{@link Algorithm.EC_P224}}</li>
     * <li>{{@link Algorithm.EC_P256}}</li>
     * <li>{{@link Algorithm.EC_P384}}</li>
     * <li>{{@link Algorithm.EC_P521}}</li>
     * <li>{{@link Algorithm.EC_K256}}</li>
     * </ul>
     *
     * @param point The EC public component
     * @return The public key
     * @throws NoSuchAlgorithmException
     * @throws InvalidParameterSpecException
     * @throws InvalidKeySpecException
     */
    private PublicKey getEcPublicKey(final ECPoint point)
            throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeySpecException {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec(getCurveFromAlgorithm(getAlgorithm())));
        ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, ecParameters);
        KeyFactory kf = KeyFactory.getInstance("EC");
        logger.info("Returned public EC key with ID 0x" + Integer.toHexString(getId()));
        return kf.generatePublic(pubSpec);
    }

    /**
     * Converts the ECPoint into a PublicKey object using the BouncyCastle provider. Used for the following algorithms:
     *
     * <ul>
     * <li>{{@link Algorithm.EC_BP256}}</li>
     * <li>{{@link Algorithm.EC_BP384}}</li>
     * <li>{{@link Algorithm.EC_BP512}}</li>
     * </ul>
     *
     * @param point The EC public component
     * @return The public key
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidParameterSpecException
     * @throws InvalidKeySpecException
     */
    private PublicKey getEcBrainpoolPublicKey(final ECPoint point)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidParameterSpecException, InvalidKeySpecException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC", "BC");
        parameters.init(new ECGenParameterSpec(getCurveFromAlgorithm(getAlgorithm())));
        ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, ecParameters);
        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
        logger.info("Returned public EC key with ID 0x" + Integer.toHexString(getId()));
        return kf.generatePublic(pubSpec);
    }

    /**
     * @return The expected length of the private key component
     */
    private static int getEcComponentLength(final Algorithm algorithm) {
        if (algorithm.equals(Algorithm.EC_P224)) {
            return 28;
        } else if (algorithm.equals(Algorithm.EC_P256) || algorithm.equals(Algorithm.EC_K256) || algorithm.equals(Algorithm.EC_BP256)) {
            return 32;
        } else if (algorithm.equals(Algorithm.EC_P384) || algorithm.equals(Algorithm.EC_BP384)) {
            return 48;
        } else if (algorithm.equals(Algorithm.EC_BP512)) {
            return 64;
        } else if (algorithm.equals(Algorithm.EC_P521)) {
            return 66;
        } else {
            throw new InvalidParameterException("Unsupported EC algorithm: " + algorithm.toString());
        }
    }

    private String getCurveFromAlgorithm(final Algorithm algorithm) {
        if (algorithm.equals(Algorithm.EC_P224)) {
            return "secp224r1";
        }
        if (algorithm.equals(Algorithm.EC_P256)) {
            return "secp256r1";
        }
        if (algorithm.equals(Algorithm.EC_P384)) {
            return "secp384r1";
        }
        if (algorithm.equals(Algorithm.EC_P521)) {
            return "secp521r1";
        }
        if (algorithm.equals(Algorithm.EC_K256)) {
            return "secp256k1";
        }
        if (algorithm.equals(Algorithm.EC_BP256)) {
            return "brainpoolP256r1";
        }
        if (algorithm.equals(Algorithm.EC_BP384)) {
            return "brainpoolP384r1";
        }
        if (algorithm.equals(Algorithm.EC_BP512)) {
            return "brainpoolP512r1";
        }
        return "";
    }
}
