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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

public class Opaque extends YHObject {
    private static Logger log = Logger.getLogger(Opaque.class.getName());

    public static final ObjectType TYPE = ObjectType.TYPE_OPAQUE;
    private static final int MAX_OPAQUE_DATA_LENGTH = 1968;

    private Algorithm algorithm;

    /**
     * Creates an Opaque object
     *
     * @param id        The object ID of this key
     * @param algorithm A supported Opaque object algorithm. Can be {{@link Algorithm.OPAQUE_X509_CERTIFICATE}} or {{@link Algorithm.OPAQUE_DATA}}
     */
    public Opaque(final short id, @NonNull final Algorithm algorithm) {
        if (!isOpaqueAlgorithm(algorithm)) {
            throw new IllegalArgumentException("An Asymmetric key algorithm must be a supported RSA algorithm");
        }
        setId(id);
        setType(TYPE);
        this.algorithm = algorithm;
    }

    public Algorithm getAlgorithm() {
        return algorithm;
    }

    public static boolean isOpaqueAlgorithm(final Algorithm algorithm) {
        if (algorithm == null) {
            return false;
        }
        return algorithm.equals(Algorithm.OPAQUE_DATA) || algorithm.equals(Algorithm.OPAQUE_X509_CERTIFICATE);
    }

    /**
     * Imports certificate into the YubiHSM as an Opaque object.
     *
     * @param session     An authenticated session to communicate with the device over
     * @param id          The ID of the certificate. 0 if the ID is to be generated by the device
     * @param label       The certificate label
     * @param domains     The domains where the certificate will be operating within
     * @param certificate The certificate to import
     * @return ID of the Opaque object on the device
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
     * @throws CertificateEncodingException       If parsing the certificate fails
     */
    public static short importCertificate(@NonNull final YHSession session, short id, final String label, @NonNull final List<Integer> domains,
                                          @NonNull final X509Certificate certificate)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException, CertificateEncodingException {
        Utils.checkEmptyList(domains, "For an object to be useful, it must be accessible in at least one domain");

        return putOpaque(session, id, label, domains, null, Algorithm.OPAQUE_X509_CERTIFICATE, certificate.getEncoded());
    }

    /**
     * Imports an opaque object into the YubiHSM. An Opaque Object is an unchecked kind of Object, normally used to store raw data in the device.
     *
     * @param session      An authenticated session to communicate with the device over
     * @param id           The ID of the Opaque object. 0 if the ID is to be generated by the device
     * @param label        The Opaque object label
     * @param domains      The domains where the Opaque object will be operating within
     * @param capabilities The capabilities of the Opaque object
     * @param algorithm    The algorithm of the Opaque object
     * @param opaqueData   The Opaque object to import
     * @return ID of the Opaque object on the device
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
     * @throws UnsupportedAlgorithmException      If the specified key algorithm is not an RSA algorithm
     * @throws CertificateException               If parsing the data as a certificate fails. Applicable if the algorithm is {{@link Algorithm.OPAQUE_X509_CERTIFICATE}}
     */
    public static short importOpaque(@NonNull final YHSession session, short id, final String label, @NonNull final List<Integer> domains,
                                     final List<Capability> capabilities, @NonNull final Algorithm algorithm, @NonNull final byte[] opaqueData)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException, UnsupportedAlgorithmException, CertificateException {
        if (!isOpaqueAlgorithm(algorithm)) {
            throw new UnsupportedAlgorithmException(algorithm.getName() + " is not a supported algorithm for Opaque objects");
        }

        Utils.checkEmptyByteArray(opaqueData, "Missing parameter: opaqueData");
        if (opaqueData.length > MAX_OPAQUE_DATA_LENGTH) {
            throw new InvalidParameterException("Opaque objects larger than " + MAX_OPAQUE_DATA_LENGTH + " bytes are currently not supported");
        }

        if (algorithm.equals(Algorithm.OPAQUE_X509_CERTIFICATE)) {
            return importCertificate(session, id, label, domains, getCertFromBytes(opaqueData));
        }
        return putOpaque(session, id, label, domains, capabilities, algorithm, opaqueData);
    }

    /**
     * Sends the Put Opaque Key command to the device
     */
    private static short putOpaque(@NonNull final YHSession session, short id, final String label, @NonNull final List<Integer> domains,
                                   final List<Capability> capabilities, @NonNull final Algorithm algorithm, @NonNull final byte[] opaqueData)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException {
        Utils.checkEmptyList(domains, "An object has to be accessible in at least one domain to be useful");

        ByteBuffer bb = ByteBuffer.allocate(53 + opaqueData.length); // 2 + 40 + 2 + 8 + 1 + opaque data
        bb.putShort(id);
        bb.put(Arrays.copyOf(Utils.getLabel(label).getBytes(), YHObjectInfo.LABEL_LENGTH));
        bb.putShort(Utils.getShortFromList(domains));
        bb.putLong(Capability.getCapabilities(capabilities));
        bb.put(algorithm.getAlgorithmId());
        bb.put(opaqueData);

        byte[] resp = session.sendSecureCmd(Command.PUT_OPAQUE, bb.array());
        bb = ByteBuffer.wrap(resp);
        id = bb.getShort();

        log.info("Imported opaque object with ID 0x" + Integer.toHexString(id) + " and algorithm " + algorithm.toString());
        return id;
    }

    /**
     * Retrieves an Opaque object from the YubiHSM.
     *
     * @param session An authenticated session to communicate with the device over
     * @return This Opaque object as a byte array
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
    public byte[] getOpaque(@NonNull final YHSession session)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException {
        ByteBuffer bb = ByteBuffer.allocate(2);
        bb.putShort(getId());

        byte[] resp = session.sendSecureCmd(Command.GET_OPAQUE, bb.array());
        log.info("Returned Opaque object with ID 0x" + Integer.toHexString(getId()));
        return resp;
    }

    /**
     * Retrieves an Opaque object from the YubiHSM.
     *
     * @param session An authenticated session to communicate with the device over
     * @return This Opaque object as a byte array
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
    public X509Certificate getCertificate(final YHSession session)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, CertificateException {
        if (!getAlgorithm().equals(Algorithm.OPAQUE_X509_CERTIFICATE)) {
            throw new UnsupportedOperationException("Opaque object is not an X509Certificate");
        }

        byte[] certBytes = getOpaque(session);
        return getCertFromBytes(certBytes);
    }

    private static X509Certificate getCertFromBytes(@NonNull final byte[] certBytes) throws CertificateException {
        ByteArrayInputStream in = new ByteArrayInputStream(certBytes);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(in);
    }
}

