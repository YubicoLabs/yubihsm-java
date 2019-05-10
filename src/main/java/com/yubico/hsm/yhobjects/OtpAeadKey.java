package com.yubico.hsm.yhobjects;

import com.yubico.hsm.YHSession;
import com.yubico.hsm.exceptions.*;
import com.yubico.hsm.internal.util.Utils;
import com.yubico.hsm.yhconcepts.Algorithm;
import com.yubico.hsm.yhconcepts.Capability;
import com.yubico.hsm.yhconcepts.Command;
import com.yubico.hsm.yhconcepts.Type;
import com.yubico.hsm.yhdata.YubicoOtpData;
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

public class OtpAeadKey extends YHObject {
    private static Logger log = Logger.getLogger(OtpAeadKey.class.getName());

    public static final Type TYPE = Type.TYPE_OTP_AEAD_KEY;

    private static final int NEW_KEY_NONCE_ID_LENGTH = 4;
    private static final int OTP_LENGTH = 16;
    private static final int OTP_AEAD_LENGTH = 36;
    private static final int CREATE_OTP_PRIVATE_ID_LENGTH = 6;
    private final int DECRYPT_OTP_RESPONSE_LENGTH = 6;

    /**
     * Creates an Opaque object
     *
     * @param id        The object ID of this key
     */
    public OtpAeadKey(final short id) {
        setId(id);
        setType(TYPE);
    }

    public static boolean isOtpAeadKeyAlgorithm(final Algorithm algorithm) {
        if (algorithm == null) {
            return false;
        }
        return algorithm.equals(Algorithm.AES128_YUBICO_OTP) || algorithm.equals(Algorithm.AES192_YUBICO_OTP) ||
               algorithm.equals(Algorithm.AES256_YUBICO_OTP);
    }

    /**
     * Generates an OTP AEAD key on the YubiHSM
     *
     * @param session      An authenticated session to communicate with the device over
     * @param id           The desired ID for the new OTP AEAD key. Set to 0 to have it generated
     * @param label        The label of the new OTP AEAD key
     * @param domains      The domains through which the new OTP AEAD key can be accessible
     * @param keyAlgorithm The algorithm used to generate the new OTP AEAD key. Can be one of {{@link Algorithm.AES128_YUBICO_OTP}}, {
     *                     {@link Algorithm.AES192_YUBICO_OTP}} or {{@link Algorithm.AES256_YUBICO_OTP}}
     * @param capabilities The actions that can be performed by the new OTP AEAD key
     * @param nonceId      A 4 bytes nonce
     * @return ID of the OTP AEAD key generated on the device
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
    public static short generateOtpAeadKey(@NonNull final YHSession session, final short id, final String label, @NonNull final List<Integer> domains,
                                           @NonNull final Algorithm keyAlgorithm, final List<Capability> capabilities, final int nonceId)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException, UnsupportedAlgorithmException {
        verifyParametersForNewKey(domains, keyAlgorithm, null, null);

        ByteBuffer bb = ByteBuffer.allocate(
                OBJECT_ID_SIZE + OBJECT_LABEL_SIZE + OBJECT_DOMAINS_SIZE + OBJECT_CAPABILITIES_SIZE + OBJECT_ALGORITHM_SIZE +
                NEW_KEY_NONCE_ID_LENGTH);
        bb.putShort(id);
        bb.put(Arrays.copyOf(Utils.getLabel(label).getBytes(), OBJECT_LABEL_SIZE));
        bb.putShort(Utils.getShortFromList(domains));
        bb.putLong(Utils.getLongFromCapabilities(capabilities));
        bb.put(keyAlgorithm.getId());
        bb.putInt(nonceId);

        byte[] resp = session.sendSecureCmd(Command.GENERATE_OTP_AEAD_KEY, bb.array());
        if (resp.length != OBJECT_ID_SIZE) {
            throw new YHInvalidResponseException(
                    "Response to " + Command.GENERATE_OTP_AEAD_KEY.getName() + " command expected to contains " + OBJECT_ID_SIZE + " bytes, but was" +
                    " " + resp.length + " bytes instead");
        }
        bb = ByteBuffer.wrap(resp);
        short newid = bb.getShort();

        log.info("Generated OTP AEAD key with ID 0x" + Integer.toHexString(newid) + " using " + keyAlgorithm.getName() + " algorithm and nonce ID " +
                 nonceId);
        return newid;
    }

    /**
     * Imports an OTP AEAD key on the YubiHSM
     *
     * @param session      An authenticated session to communicate with the device over
     * @param id           The desired ID for the imported OTP AEAD key. Set to 0 to have it generated
     * @param label        The label of the imported OTP AEAD key
     * @param domains      The domains through which the imported OTP AEAD key can be accessible
     * @param keyAlgorithm The algorithm used to generate the imported OTP AEAD key. Can be one of {{@link Algorithm.AES128_YUBICO_OTP}}, {
     *                     {@link Algorithm.AES192_YUBICO_OTP}} or {{@link Algorithm.AES256_YUBICO_OTP}}
     * @param capabilities The actions that can be performed by the imported OTP AEAD key
     * @param nonceId      A 4 bytes nonce
     * @param key          The OTP AEAD key. 16, 24 or 32 bytes depending on the key algorithm
     * @return ID of the imported OTP AEAD key
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
    public static short importOtpAeadKey(@NonNull final YHSession session, final short id, final String label, @NonNull final List<Integer> domains,
                                         @NonNull final Algorithm keyAlgorithm, final List<Capability> capabilities,
                                         @NonNull final byte[] nonceId, @NonNull final byte[] key)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException, UnsupportedAlgorithmException {
        verifyParametersForNewKey(domains, keyAlgorithm, nonceId, key);

        ByteBuffer bb = ByteBuffer.allocate(
                OBJECT_ID_SIZE + OBJECT_LABEL_SIZE + OBJECT_DOMAINS_SIZE + OBJECT_CAPABILITIES_SIZE + OBJECT_ALGORITHM_SIZE +
                NEW_KEY_NONCE_ID_LENGTH + key.length);
        bb.putShort(id);
        bb.put(Arrays.copyOf(Utils.getLabel(label).getBytes(), OBJECT_LABEL_SIZE));
        bb.putShort(Utils.getShortFromList(domains));
        bb.putLong(Utils.getLongFromCapabilities(capabilities));
        bb.put(keyAlgorithm.getId());
        bb.put(nonceId);
        bb.put(key);

        byte[] resp = session.sendSecureCmd(Command.PUT_OTP_AEAD_KEY, bb.array());
        if (resp.length != OBJECT_ID_SIZE) {
            throw new YHInvalidResponseException(
                    "Response to " + Command.PUT_OTP_AEAD_KEY.getName() + " command expected to contains " + OBJECT_ID_SIZE + " bytes, but was " +
                    resp.length + " bytes instead");
        }
        bb = ByteBuffer.wrap(resp);
        short newid = bb.getShort();

        log.info("Imported OTP AEAD key with ID 0x" + Integer.toHexString(newid) + " using algorithm " + keyAlgorithm.getName() + " and nonce ID " +
                 nonceId);
        return newid;
    }

    /**
     * Creates a Yubico OTP AEAD using the provided data and this OTP AEAD key
     *
     * @param session      An authenticated session to communicate with the device over
     * @param otpKey       16 bytes OTP key
     * @param otpPrivateId 6 bytes OTP private ID
     * @return Nonce concatenated with AEAD (36 bytes)
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
    public byte[] createOtpAed(@NonNull final YHSession session, @NonNull final byte[] otpKey, @NonNull final byte[] otpPrivateId)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException {
        if (otpKey.length != OTP_LENGTH) {
            throw new IllegalArgumentException("OTP key must be " + OTP_LENGTH + " bytes long");
        }
        if (otpPrivateId.length != CREATE_OTP_PRIVATE_ID_LENGTH) {
            throw new IllegalArgumentException("OTP private ID must be " + CREATE_OTP_PRIVATE_ID_LENGTH + " bytes long");
        }

        log.fine("Creating Yubico OTP AEAD using OTP key " + Utils.getPrintableBytes(otpKey) + " and OTP private ID " +
                 Utils.getPrintableBytes(otpPrivateId) + " and using key with ID 0x" + Integer.toHexString(getId()));

        ByteBuffer bb =
                ByteBuffer.allocate(OBJECT_ID_SIZE + OTP_LENGTH + CREATE_OTP_PRIVATE_ID_LENGTH);
        bb.putShort(getId());
        bb.put(otpKey);
        bb.put(otpPrivateId);

        byte[] resp = session.sendSecureCmd(Command.CREATE_OTP_AEAD, bb.array());
        if (resp.length != OTP_AEAD_LENGTH) {
            throw new YHInvalidResponseException(
                    "Response to " + Command.CREATE_OTP_AEAD.getName() + " command is expected to be " + OTP_AEAD_LENGTH + " bytes " +
                    "long but was " + resp.length + " bytes instead");
        }

        log.info("Created Yubico OTP AEAD using key with ID 0x" + Integer.toHexString(getId()));
        log.fine("Created Yubico OTP AEAD " + Utils.getPrintableBytes(resp) + " using key with key with ID 0x" + Integer.toHexString(getId()));
        return resp;
    }

    /**
     * Create a new OTP AEAD using random data for key and private ID
     *
     * @param session An authenticated session to communicate with the device over
     * @return Nonce concatenated with AEAD (36 bytes)
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
    public byte[] randomizeOtpAed(@NonNull final YHSession session)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException {

        ByteBuffer bb = ByteBuffer.allocate(OBJECT_ID_SIZE);
        bb.putShort(getId());

        byte[] resp = session.sendSecureCmd(Command.RANDOMIZE_OTP_AEAD, bb.array());
        if (resp.length != OTP_AEAD_LENGTH) {
            throw new YHInvalidResponseException(
                    "Response to " + Command.RANDOMIZE_OTP_AEAD.getName() + " command is expected to be " + OTP_AEAD_LENGTH +
                    " bytes long but was " + resp.length + " bytes instead");
        }

        log.info("Created Yubico OTP AEAD using random data and key with ID 0x" + Integer.toHexString(getId()));
        return resp;
    }

    /**
     * Decrypts a Yubico OTP
     *
     * @param session   An authenticated session to communicate with the device over
     * @param nonceAead 36 bytes nonce concatenated with AEAD
     * @param otp       16 bytes OTP
     * @return Counters and timer information
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
    public YubicoOtpData decryptOtp(@NonNull final YHSession session, @NonNull final byte[] nonceAead, @NonNull final byte[] otp)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException {

        if (nonceAead.length != OTP_AEAD_LENGTH) {
            throw new IllegalArgumentException(
                    "OTP AEAD key must be " + OTP_AEAD_LENGTH + " bytes long but was " + nonceAead.length + " bytes instead");
        }
        if (otp.length != OTP_LENGTH) {
            throw new IllegalArgumentException("OTP must be " + OTP_LENGTH + " bytes long but was " + otp.length + " bytes instead");
        }

        log.fine("Decrypting Yubico OTP AEAD " + Utils.getPrintableBytes(nonceAead) + " with OTP " + Utils.getPrintableBytes(otp) + " using OTP " +
                 "AEAD key with ID 0x" + Integer.toHexString(getId()));

        ByteBuffer bb = ByteBuffer.allocate(OBJECT_ID_SIZE + OTP_AEAD_LENGTH + OTP_LENGTH);
        bb.putShort(getId());
        bb.put(nonceAead);
        bb.put(otp);

        byte[] resp = session.sendSecureCmd(Command.DECRYPT_OTP, bb.array());
        if (resp.length != DECRYPT_OTP_RESPONSE_LENGTH) {
            throw new YHInvalidResponseException(
                    "Response to " + Command.DECRYPT_OTP.getName() + " command is expected to be " + DECRYPT_OTP_RESPONSE_LENGTH +
                    " bytes long but was " + resp.length + " bytes instead");
        }

        bb = ByteBuffer.wrap(resp);
        YubicoOtpData otpData = new YubicoOtpData(Short.reverseBytes(bb.getShort()), bb.get(), bb.get(), Short.reverseBytes(bb.getShort()));

        log.info("Decrypted Yubico OTP using key with ID 0x" + Integer.toHexString(getId()));
        return otpData;
    }

    /**
     * Re-encrypt a Yubico OTP AEAD from one OTP AEAD Key to another OTP AEAD Key
     *
     * @param session   An authenticated session to communicate with the device over
     * @param keyIdFrom Object ID of the OTP AEAD key that performed the first encryption
     * @param keyIdTo   Object ID of the OTP AEAD key that will perform the new encryption
     * @param nonceAead 36 bytes nonce concatenated with AEAD
     * @return New 36 bytes nonce concatenated with AEAD
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
    public static byte[] rewrapOtpAead(@NonNull final YHSession session, final short keyIdFrom, final short keyIdTo, @NonNull final byte[] nonceAead)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException {

        if (nonceAead.length != OTP_AEAD_LENGTH) {
            throw new IllegalArgumentException(
                    "OTP AEAD key must be " + OTP_AEAD_LENGTH + " bytes long but was " + nonceAead.length + " bytes instead");
        }

        log.fine("Re-wrapping Yubico OTP AEAD " + Utils.getPrintableBytes(nonceAead) + " that was produced using key 0x" +
                 Integer.toHexString(keyIdFrom) + ". Key 0x" + Integer.toHexString(keyIdTo) + " will be used for re-wrapping");

        ByteBuffer bb = ByteBuffer.allocate(OBJECT_ID_SIZE + OBJECT_ID_SIZE + OTP_AEAD_LENGTH);
        bb.putShort(keyIdFrom);
        bb.putShort(keyIdTo);
        bb.put(nonceAead);

        byte[] resp = session.sendSecureCmd(Command.REWRAP_OTP_AEAD, bb.array());
        if (resp.length != OTP_AEAD_LENGTH) {
            throw new YHInvalidResponseException(
                    "Response to " + Command.REWRAP_OTP_AEAD.getName() + " command is expected to be " + OTP_AEAD_LENGTH +
                    " bytes long but was " + resp.length + " bytes instead");
        }

        log.info("Re-wrapped Yubico OTP using key with ID 0x" + Integer.toHexString(keyIdTo));
        return resp;
    }


    private static void verifyParametersForNewKey(@NonNull final List<Integer> domains, @NonNull final Algorithm keyAlgorithm,
                                                  final byte[] nonceId, final byte[] key)
            throws UnsupportedAlgorithmException {
        if (domains.isEmpty()) {
            throw new IllegalArgumentException("Domains parameter cannot be null or empty");
        }
        if (!isOtpAeadKeyAlgorithm(keyAlgorithm)) {
            throw new UnsupportedAlgorithmException("Algorithm " + keyAlgorithm.toString() + " is not a supported OTP AEAD key algorithm");
        }

        if (nonceId != null && key != null) {
            if (nonceId.length != NEW_KEY_NONCE_ID_LENGTH) {
                throw new IllegalArgumentException("The nonce ID is expected to be " + NEW_KEY_NONCE_ID_LENGTH + " bytes long but was " + nonceId.length +
                                                   " bytes");
            }
            final int keylen = getOtpAeadKeyLength(keyAlgorithm);
            if (key.length != keylen) {
                throw new IllegalArgumentException("OTP AEAD key is expected to be " + keylen + " bytes long but was " + key.length + " bytes");
            }
        } else if((nonceId!=null && key==null) || (nonceId==null && key!=null)) { // Practically, this should never happen since both these
            // parameters are marked with @NonNull in the calling method
            throw new IllegalArgumentException("Either the nonceID or the key is null. To import a new OTP AEAD key, both the nonceID and the key " +
                                               "need to be specified.");
        }
    }

    private static int getOtpAeadKeyLength(@NonNull final Algorithm algorithm) throws UnsupportedAlgorithmException {
        if (algorithm.equals(Algorithm.AES128_YUBICO_OTP)) {
            return 16;
        }
        if (algorithm.equals(Algorithm.AES192_YUBICO_OTP)) {
            return 24;
        }
        if (algorithm.equals(Algorithm.AES256_YUBICO_OTP)) {
            return 32;
        }
        throw new UnsupportedAlgorithmException("Algorithm " + algorithm.toString() + " is not a supported OTP AEAD key algorithm");
    }
}
