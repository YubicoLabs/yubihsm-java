package com.yubico.hsm.yhobjects;

import com.yubico.hsm.YHSession;
import com.yubico.hsm.exceptions.*;
import com.yubico.hsm.internal.util.Utils;
import com.yubico.hsm.yhconcepts.Algorithm;
import com.yubico.hsm.yhconcepts.Capability;
import com.yubico.hsm.yhconcepts.Command;
import lombok.NonNull;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

public class AsymmetricKeyEc extends AsymmetricKey {
    private static Logger log = Logger.getLogger(AsymmetricKeyEc.class.getName());

    /**
     * Creates an AsymmetriKeyEc object
     *
     * @param id           The object ID of this key
     * @param keyAlgorithm A supported EC key algorithm
     */
    public AsymmetricKeyEc(final short id, @NonNull final Algorithm keyAlgorithm) {
        if (!isEcAlgorithm(keyAlgorithm)) {
            throw new IllegalArgumentException("An Asymmetric key algorithm must be a supported EC algorithm");
        }
        setId(id);
        setType(TYPE);
        setKeyAlgorithm(keyAlgorithm);
    }


    /**
     * Imports a user generated EC key into the YubiHSM
     *
     * @param session      An authenticated session to communicate with the device over
     * @param id           The desired Object ID of the imported EC key. Set to 0 to have it generated
     * @param label        The label of the imported EC key
     * @param domains      The domains where the imported EC key will be accessible
     * @param keyAlgorithm The algorithm used to generate the imported EC key
     * @param capabilities The actions that can be performed using the imported EC key
     * @param d            The private key integer d
     * @return ID of the imported EC key on the device
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
     * @throws UnsupportedAlgorithmException      If the key algorithm is not recognized.
     */
    public static short importKey(final YHSession session, final short id, final String label, @NonNull final List<Integer> domains,
                                  @NonNull final Algorithm keyAlgorithm, final List<Capability> capabilities, @NonNull final byte[] d)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException, UnsupportedAlgorithmException {
        verifyParametersForNewEcKey(domains, keyAlgorithm, d);
        return putKey(session, id, label, domains, keyAlgorithm, capabilities, d, null);
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
     * @throws NoSuchProviderException            If BouncyCastle was not find as a security provider
     */
    public PublicKey getEcPublicKey(@NonNull final YHSession session)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidKeySpecException, InvalidParameterSpecException, NoSuchProviderException,
                   UnsupportedAlgorithmException {

        byte[] xy = super.getPublicKey(session);
        byte[] x = Arrays.copyOfRange(xy, 0, xy.length / 2);
        byte[] y = Arrays.copyOfRange(xy, xy.length / 2, xy.length);

        ECPoint pubPoint = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
        return getEcPublicKeyFromPoint(pubPoint, isBrainpoolKeyAlgorithm(getKeyAlgorithm()));
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
     * @throws UnsupportedAlgorithmException      If the hash algorithm is not supported
     */
    public byte[] signEcdsa(final YHSession session, final byte[] data, @NonNull final Algorithm hashAlgorithm)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, UnsupportedAlgorithmException {
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
    public byte[] signEcdsa(@NonNull final YHSession session, @NonNull final byte[] dataDigest)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException {
        ByteBuffer bb = ByteBuffer.allocate(OBJECT_ID_SIZE + dataDigest.length);
        bb.putShort(getId());
        bb.put(dataDigest);

        byte[] signature = session.sendSecureCmd(Command.SIGN_ECDSA, bb.array());
        log.info("Signed data with key 0x" + Integer.toHexString(getId()));
        return signature;
    }

    /**
     * Perform an ECDH operation on this private key and the public component of another EC key
     *
     * @param session   An authenticated session to communicate with the device over
     * @param publicKey The public key to perform the exchange with
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
    public byte[] deriveEcdh(@NonNull final YHSession session, @NonNull final ECPublicKey publicKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, UnsupportedAlgorithmException {
        return deriveEcdh(session, getUncompressedEcPublicKey(publicKey, getEcComponentLength(getKeyAlgorithm())));
    }

    /**
     * Perform an ECDH operation on this private key and the public component of another EC key
     *
     * @param session   An authenticated session to communicate with the device over
     * @param publicKey Uncompressed public key to perform the exchange with (57, 65, 97, 129 or 133 bytes)
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
    public byte[] deriveEcdh(@NonNull final YHSession session, @NonNull final byte[] publicKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, UnsupportedAlgorithmException {
        int pubKeyLength = getEcComponentLength(getKeyAlgorithm()) * 2 + 1;
        if(publicKey.length != pubKeyLength) {
            throw new IllegalArgumentException("The public key is expected to be " + pubKeyLength + " bytes long but was " + publicKey.length + " " +
                                               "bytes");
        }

        ByteBuffer bb = ByteBuffer.allocate(OBJECT_ID_SIZE + publicKey.length);
        bb.putShort(getId());
        bb.put(publicKey);

        byte[] ecdh = session.sendSecureCmd(Command.DERIVE_ECDH, bb.array());
        log.info("Derived ECDH key from private key 0x" + Integer.toHexString(getId()) + " and public key " + Utils.getPrintableBytes(publicKey));
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
    private PublicKey getEcPublicKeyFromPoint(@NonNull final ECPoint point, final boolean isBrainpool)
            throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeySpecException, NoSuchProviderException,
                   UnsupportedAlgorithmException {
        AlgorithmParameters parameters;
        if(isBrainpool) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            parameters = AlgorithmParameters.getInstance("EC", "BC");
        } else {
            parameters = AlgorithmParameters.getInstance("EC");
        }
        parameters.init(new ECGenParameterSpec(getCurveFromAlgorithm(getKeyAlgorithm())));
        ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, ecParameters);

        PublicKey pubkey;
        if(isBrainpool) {
            KeyFactory kf = KeyFactory.getInstance("EC", "BC");
            pubkey = kf.generatePublic(pubSpec);
        } else {
            KeyFactory kf = KeyFactory.getInstance("EC");
            pubkey = kf.generatePublic(pubSpec);
        }
        log.info("Returned public EC key with ID 0x" + String.format("%02x", getId()));
        return pubkey;
    }

    /**
     * @return The expected length of the private key component
     */
    private static int getEcComponentLength(@NonNull final Algorithm algorithm) throws UnsupportedAlgorithmException {
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
            throw new UnsupportedAlgorithmException("Unsupported EC algorithm: " + algorithm.toString());
        }
    }

    private String getCurveFromAlgorithm(@NonNull final Algorithm algorithm) throws UnsupportedAlgorithmException {
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
        throw new UnsupportedAlgorithmException(algorithm.getName() + " algorithm is not a supported EC key algorithm");
    }

    private boolean isBrainpoolKeyAlgorithm(@NonNull final Algorithm algorithm) {
        return algorithm.equals(Algorithm.EC_BP256) || algorithm.equals(Algorithm.EC_BP384) || algorithm.equals(Algorithm.EC_BP512);
    }

    private byte[] getUncompressedEcPublicKey(PublicKey publicKey, int length) {
        ECPublicKey pubkey = (ECPublicKey) publicKey;
        ECPoint point = pubkey.getW();
        byte[] x = Utils.getUnsignedByteArrayFromBigInteger(point.getAffineX(), length);
        byte[] y = Utils.getUnsignedByteArrayFromBigInteger(point.getAffineY(), length);
        ByteBuffer bb = ByteBuffer.allocate(1 + x.length + y.length);
        bb.put((byte) 0x04).put(x).put(y);
        return bb.array();
    }

    private static void verifyParametersForNewEcKey(@NonNull final List<Integer> domains, @NonNull final Algorithm keyAlgorithm,
                                                    @NonNull final byte[] d) throws UnsupportedAlgorithmException {
        if (domains.isEmpty()) {
            throw new IllegalArgumentException("Domains parameter cannot be null or empty");
        }
        if (!isEcAlgorithm(keyAlgorithm)) {
            throw new IllegalArgumentException("Key algorithm must be a supported EC algorithm");
        }

        int componentLength = getEcComponentLength(keyAlgorithm);
        if (d.length != componentLength) {
            throw new IllegalArgumentException("Invalid parameter. Expected private key integer d that is " + componentLength + " bytes long, but" +
                                               " was " + d.length + " bytes");
        }
    }
}
