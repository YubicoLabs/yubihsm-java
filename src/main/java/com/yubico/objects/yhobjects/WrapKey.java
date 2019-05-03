package com.yubico.objects.yhobjects;

import com.yubico.YHSession;
import com.yubico.exceptions.*;
import com.yubico.internal.util.Utils;
import com.yubico.objects.WrapData;
import com.yubico.objects.yhconcepts.Algorithm;
import com.yubico.objects.yhconcepts.Capability;
import com.yubico.objects.yhconcepts.Command;
import com.yubico.objects.yhconcepts.ObjectType;
import lombok.NonNull;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

public class WrapKey extends YHObject {
    private static Logger log = Logger.getLogger(WrapKey.class.getName());

    public static final ObjectType TYPE = ObjectType.TYPE_WRAP_KEY;

    private final int IMPORT_WRAPPED_RESPONSE_LENGTH = 3;

    /**
     * Creates a WrapKey object
     *
     * @param id The Object ID of this key
     */
    public WrapKey(final short id) {
        super(id, TYPE);
    }

    /**
     * @return True if `algorithm` is one of {{@link Algorithm.AES128_CCM_WRAP}}, {{@link Algorithm.AES192_CCM_WRAP}} or {
     * {@link Algorithm.AES256_CCM_WRAP}}. False otherwise
     */
    public static boolean isWrapKeyAlgorithm(final Algorithm algorithm) {
        return algorithm.equals(Algorithm.AES128_CCM_WRAP) || algorithm.equals(Algorithm.AES192_CCM_WRAP) ||
               algorithm.equals(Algorithm.AES256_CCM_WRAP);
    }


    /**
     * Generates a Wrap key on the YubiHSM
     *
     * @param session               An authenticated session to communicate with the device over
     * @param id                    The desired ID for the new Wrap key. Set to 0 to have it generated
     * @param label                 The label of the new Wrap key
     * @param domains               The domains through which the new Wrap key can be accessible
     * @param wrapKeyAlgorithm      The algorithm used to generate the new Wrap key. Can be one of {{@link Algorithm.AES128_CCM_WRAP}}, {
     *                              {@link Algorithm.AES192_CCM_WRAP}} or {{@link Algorithm.AES256_CCM_WRAP}}
     * @param capabilities          The actions that can be performed by the new Wrap key
     * @param delegatedCapabilities The capabilities of the object that the new Wrap key will be able to perform actions on
     * @return ID of the Wrap key generated on the device
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
    public static short generateWrapKey(@NonNull final YHSession session, final short id, final String label, @NonNull final List<Integer> domains,
                                        @NonNull final Algorithm wrapKeyAlgorithm, final List<Capability> capabilities,
                                        final List<Capability> delegatedCapabilities)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException, UnsupportedAlgorithmException {
        verifyParametersForNewKey(domains, wrapKeyAlgorithm, null);

        ByteBuffer bb = ByteBuffer.allocate(
                OBJECT_ID_SIZE + OBJECT_LABEL_SIZE + OBJECT_DOMAINS_SIZE + OBJECT_CAPABILITIES_SIZE + OBJECT_ALGORITHM_SIZE +
                OBJECT_DELEGATED_CAPABILITIES_SIZE);
        bb.putShort(id);
        bb.put(Arrays.copyOf(Utils.getLabel(label).getBytes(), OBJECT_LABEL_SIZE));
        bb.putShort(Utils.getShortFromList(domains));
        bb.putLong(Capability.getCapabilities(capabilities));
        bb.put(wrapKeyAlgorithm.getAlgorithmId());
        bb.putLong(Capability.getCapabilities(delegatedCapabilities));

        byte[] resp = session.sendSecureCmd(Command.GENERATE_WRAP_KEY, bb.array());
        if (resp.length != OBJECT_ID_SIZE) {
            throw new YHInvalidResponseException(
                    "Response to " + Command.GENERATE_WRAP_KEY.getName() + " command expected to contains " + OBJECT_ID_SIZE + " bytes, but was " +
                    resp.length + " bytes instead");
        }

        bb = ByteBuffer.wrap(resp);
        short newid = bb.getShort();

        log.info("Generated Wrap key with ID 0x" + Integer.toHexString(newid) + " using " + wrapKeyAlgorithm.getName() + " algorithm");
        return newid;
    }

    /**
     * Imports a Wrap key into the YubiHSM
     *
     * @param session               An authenticated session to communicate with the device over
     * @param id                    The desired ID for the imported Wrap key. Set to 0 to have it generated
     * @param label                 The label of the imported Wrap key
     * @param domains               The domains through which the imported Wrap key can be accessible
     * @param wrapKeyAlgorithm      The algorithm used to generate the imported Wrap key. Can be one of {{@link Algorithm.AES128_CCM_WRAP}}, {
     *                              {@link Algorithm.AES192_CCM_WRAP}} or {{@link Algorithm.AES256_CCM_WRAP}}
     * @param capabilities          The actions that can be performed by the imported Wrap key
     * @param delegatedCapabilities The capabilities of the object that the imported Wrap key will be able to perform actions on
     * @param wrapKey               The Wrap key. 16, 24 or 32 bytes depending on the key algorithm
     * @return ID of the imported Wrap key
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
    public static short importWrapKey(@NonNull final YHSession session, final short id, final String label, @NonNull final List<Integer> domains,
                                      @NonNull final Algorithm wrapKeyAlgorithm, final List<Capability> capabilities,
                                      final List<Capability> delegatedCapabilities, @NonNull final byte[] wrapKey)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException, UnsupportedAlgorithmException {
        verifyParametersForNewKey(domains, wrapKeyAlgorithm, wrapKey);

        ByteBuffer bb =
                ByteBuffer.allocate(OBJECT_ID_SIZE + OBJECT_LABEL_SIZE + OBJECT_DOMAINS_SIZE + OBJECT_CAPABILITIES_SIZE + OBJECT_ALGORITHM_SIZE +
                                    OBJECT_DELEGATED_CAPABILITIES_SIZE + wrapKey.length);
        bb.putShort(id);
        bb.put(Arrays.copyOf(Utils.getLabel(label).getBytes(), OBJECT_LABEL_SIZE));
        bb.putShort(Utils.getShortFromList(domains));
        bb.putLong(Capability.getCapabilities(capabilities));
        bb.put(wrapKeyAlgorithm.getAlgorithmId());
        bb.putLong(Capability.getCapabilities(delegatedCapabilities));
        bb.put(wrapKey);

        byte[] resp = session.sendSecureCmd(Command.PUT_WRAP_KEY, bb.array());
        if (resp.length != OBJECT_ID_SIZE) {
            throw new YHInvalidResponseException(
                    "Response to " + Command.PUT_WRAP_KEY.getName() + " command expected to contains " + OBJECT_ID_SIZE + " bytes, but was " +
                    resp.length + " bytes instead");
        }

        bb = ByteBuffer.wrap(resp);
        short newid = bb.getShort();

        log.info("Imported Wrap key with ID 0x" + Integer.toHexString(newid));
        return newid;
    }

    /**
     * Encrypt/wrap data with this wrap key using AES-CCM
     *
     * @param session An authenticated session to communicate with the device over
     * @param data    The data to encrypt/wrap
     * @return The wrapped data, 13 bytes nonce and 16 bytes MAC
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
    public WrapData wrapData(@NonNull final YHSession session, @NonNull final byte[] data)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException {
        Utils.checkEmptyByteArray(data, "The data to wrap must be at least 1 byte long");
        log.finer("Wrapping the data: " + Utils.getPrintableBytes(data) + " with Wrap key 0x" + Integer.toHexString(getId()));

        ByteBuffer bb = ByteBuffer.allocate(OBJECT_ID_SIZE + data.length);
        bb.putShort(getId());
        bb.put(data);

        byte[] resp = session.sendSecureCmd(Command.WRAP_DATA, bb.array());
        WrapData wd = new WrapData(resp, true);
        log.finer("Got wrapped data: " + wd.toString());
        return wd;
    }

    /**
     * Decrypt/unwrap data with this wrap key using AES-CCM
     *
     * @param session     An authenticated session to communicate with the device over
     * @param wrappedData Previously encrypted data containing 13 bytes nonce and 16 bytes MAC
     * @return Unwrapped data
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
    public byte[] unwrapData(@NonNull final YHSession session, @NonNull final WrapData wrappedData)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException {
        return unwrapData(session, wrappedData.getNonce(), wrappedData.getWrappedData(), wrappedData.getMac());
    }

    /**
     * Decrypt/unwrap data with this wrap key using AES-CCM
     *
     * @param session     An authenticated session to communicate with the device over
     * @param nonce       13 bytes nonce
     * @param wrappedData Data to be unwrapped
     * @param mac         16 bytes MAC
     * @return Unwrapped data
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
    public byte[] unwrapData(@NonNull final YHSession session, @NonNull final byte[] nonce, @NonNull final byte[] wrappedData,
                             @NonNull final byte[] mac)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException {
        if (nonce.length != WrapData.NONCE_LENGTH) {
            throw new IllegalArgumentException("Nonce must be " + WrapData.NONCE_LENGTH + " bytes long");
        }
        if (mac.length != WrapData.MAC_LENGTH) {
            throw new IllegalArgumentException("Mac must be " + WrapData.MAC_LENGTH + " bytes long");
        }
        Utils.checkEmptyByteArray(wrappedData, "The wrapped data must be at least 1 byte long");

        log.finer("Unwrapping the data: [nonce] " + Utils.getPrintableBytes(nonce) + " - [wrapped data] " + Utils.getPrintableBytes(wrappedData) +
                  " - [mac] " + Utils.getPrintableBytes(mac) + " using Wrap key 0x" + Integer.toHexString(getId()));

        ByteBuffer bb = ByteBuffer.allocate(OBJECT_ID_SIZE + WrapData.NONCE_LENGTH + wrappedData.length + WrapData.MAC_LENGTH);
        bb.putShort(getId());
        bb.put(nonce);
        bb.put(wrappedData);
        bb.put(mac);

        byte[] unwrapped = session.sendSecureCmd(Command.UNWRAP_DATA, bb.array());
        log.finer("Got unwrapped data: " + Utils.getPrintableBytes(unwrapped));
        return unwrapped;
    }

    /**
     * Exports an object from the YubiHSM, encrypted/wrapped with this wrap key using AES-CCM
     *
     * @param session      An authenticated session to communicate with the device over
     * @param idToExport   Object ID of the object to be exported
     * @param typeToExport The type of the object to be exported
     * @return The wrapped object and a 13 bytes nonce
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
    public WrapData exportWrapped(@NonNull final YHSession session, final short idToExport, @NonNull final ObjectType typeToExport)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException {
        log.info("Exporting " + typeToExport.getName() + " with ID 0x" + Integer.toHexString(idToExport) + " using the wrap key 0x" +
                 Integer.toHexString(getId()));

        ByteBuffer bb = ByteBuffer.allocate(OBJECT_ID_SIZE + OBJECT_TYPE_SIZE + OBJECT_ID_SIZE);
        bb.putShort(getId());
        bb.put(typeToExport.getTypeId());
        bb.putShort(idToExport);

        byte[] resp = session.sendSecureCmd(Command.EXPORT_WRAPPED, bb.array());
        WrapData wrapData = new WrapData(resp, false);

        log.finer("Got wrapped object: " + wrapData.toString());
        return wrapData;
    }

    /**
     * Imports an object that had been exported by another YubiHSM and encrypted/wrapped with this wrap key using AES-CCM
     *
     * @param session       An authenticated session to communicate with the device over
     * @param wrappedObject Previously exported object containing a 13 bytes nonce
     * @return A reference to the imported object
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
    public YHObject importWrapped(@NonNull final YHSession session, @NonNull final WrapData wrappedObject)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException {
        return importWrapped(session, wrappedObject.getNonce(), wrappedObject.getWrappedData());
    }

    /**
     * Imports an object that had been exported by another YubiHSM and encrypted/wrapped with this wrap key using AES-CCM
     *
     * @param session       An authenticated session to communicate with the device over
     * @param nonce         13 bytes nonce
     * @param wrappedObject The wrapped object to be imported
     * @return A reference to the imported object
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
    public YHObject importWrapped(@NonNull final YHSession session, @NonNull final byte[] nonce, @NonNull final byte[] wrappedObject)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException {
        if (nonce.length != WrapData.NONCE_LENGTH) {
            throw new IllegalArgumentException("Nonce must be " + WrapData.NONCE_LENGTH + " bytes long");
        }

        log.info("Importing a wrapped object using wrap key with ID 0x" + Integer.toHexString(getId()));

        ByteBuffer bb = ByteBuffer.allocate(OBJECT_ID_SIZE + WrapData.NONCE_LENGTH + wrappedObject.length);
        bb.putShort(getId());
        bb.put(nonce);
        bb.put(wrappedObject);

        byte[] resp = session.sendSecureCmd(Command.IMPORT_WRAPPED, bb.array());
        if (resp.length != IMPORT_WRAPPED_RESPONSE_LENGTH) {
            throw new YHInvalidResponseException(
                    "Response to " + Command.IMPORT_WRAPPED.getName() + " command expected to contains " + IMPORT_WRAPPED_RESPONSE_LENGTH + " " +
                    "bytes, but was " + resp.length + " bytes instead");
        }

        bb = ByteBuffer.wrap(resp);
        ObjectType type = ObjectType.getObjectType(bb.get());
        if (type == null) {
            throw new YHInvalidResponseException("Unwrapped object was of an unknown type");
        }
        short id = bb.getShort();

        YHObject imported = new YHObject(id, type);
        log.info("Imported " + type.getName() + " with ID 0x" + Integer.toHexString(id));
        return imported;
    }

    private static void verifyParametersForNewKey(@NonNull final List<Integer> domains, @NonNull final Algorithm wrapKeyAlgorithm,
                                                  final byte[] wrapKey)
            throws UnsupportedAlgorithmException {
        if (domains.isEmpty()) {
            throw new IllegalArgumentException("Domains parameter cannot be null or empty");
        }
        if (!isWrapKeyAlgorithm(wrapKeyAlgorithm)) {
            throw new UnsupportedAlgorithmException("Algorithm " + wrapKeyAlgorithm.toString() + " is not a supported Wrap key algorithm");
        }

        if (wrapKey != null) {
            final int keylen = getWrapKeyLength(wrapKeyAlgorithm);
            if (wrapKey.length != keylen) {
                throw new IllegalArgumentException("Wrap key is expected to be " + keylen + " bytes long but was " + wrapKey.length + " bytes");
            }
        }
    }

    private static int getWrapKeyLength(@NonNull final Algorithm algorithm) throws UnsupportedAlgorithmException {
        if (algorithm.equals(Algorithm.AES128_CCM_WRAP)) {
            return 16;
        }
        if (algorithm.equals(Algorithm.AES192_CCM_WRAP)) {
            return 24;
        }
        if (algorithm.equals(Algorithm.AES256_CCM_WRAP)) {
            return 32;
        }
        throw new UnsupportedAlgorithmException("Algorithm " + algorithm.toString() + " is not a Wrap key algorithm");
    }
}
