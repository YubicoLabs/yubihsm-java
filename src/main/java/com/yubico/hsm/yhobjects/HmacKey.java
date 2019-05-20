package com.yubico.hsm.yhobjects;

import com.yubico.hsm.YHSession;
import com.yubico.hsm.exceptions.*;
import com.yubico.hsm.internal.util.CommandUtils;
import com.yubico.hsm.internal.util.Utils;
import com.yubico.hsm.yhconcepts.Algorithm;
import com.yubico.hsm.yhconcepts.Capability;
import com.yubico.hsm.yhconcepts.Command;
import com.yubico.hsm.yhconcepts.Type;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

@Slf4j
public class HmacKey extends YHObject {

    public static final Type TYPE = Type.TYPE_HMAC_KEY;
    public static final int MAX_KEY_LENGTH_SHA1_SHA256 = 64;
    public static final int MAX_KEY_LENGTH_SHA384_SHA512 = 128;

    private Algorithm keyAlgorithm;

    public HmacKey(final short id, final Algorithm keyAlgorithm) {
        if (!isHmacKeyAlgorithm(keyAlgorithm)) {
            throw new IllegalArgumentException(keyAlgorithm.toString() + " is not a supported HMAC key algorithm");
        }
        setId(id);
        setType(TYPE);
        this.keyAlgorithm = keyAlgorithm;
    }

    public Algorithm getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public void setKeyAlgorithm(Algorithm keyAlgorithm) {
        this.keyAlgorithm = keyAlgorithm;
    }

    public static boolean isHmacKeyAlgorithm(final Algorithm algorithm) {
        List<Algorithm> hmacAlgorithms = Arrays.asList(Algorithm.HMAC_SHA1, Algorithm.HMAC_SHA256, Algorithm.HMAC_SHA384, Algorithm.HMAC_SHA512);
        return hmacAlgorithms.contains(algorithm);
    }

    /**
     * Generates an HMAC key on the YubiHSM
     *
     * @param session      An authenticated session to communicate with the device over
     * @param id           The desired ID for the new HMAC key. Set to 0 to have it generated
     * @param label        The label of the new HMAC key
     * @param domains      The domains through which the new HMAC key can be accessible
     * @param keyAlgorithm The algorithm used to generate the new HMAC key. Can be one of {{@link Algorithm.HMAC_SHA1}},
     *                     {{@link Algorithm.HMAC_SHA256}}, {{@link Algorithm.HMAC_SHA384}} or {{@link Algorithm.HMAC_SHA512}}
     * @param capabilities The actions that can be performed by the new HMAC key
     * @return ID of the HMAC key generated on the device
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
    public static short generateHmacKey(@NonNull final YHSession session, final short id, final String label, @NonNull final List<Integer> domains,
                                        @NonNull final Algorithm keyAlgorithm, final List<Capability> capabilities)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException, UnsupportedAlgorithmException {
        verifyParametersForNewKey(domains, keyAlgorithm, null);

        ByteBuffer bb =
                ByteBuffer.allocate(OBJECT_ID_SIZE + OBJECT_LABEL_SIZE + OBJECT_DOMAINS_SIZE + OBJECT_CAPABILITIES_SIZE + OBJECT_ALGORITHM_SIZE);
        bb.putShort(id);
        bb.put(Arrays.copyOf(Utils.getLabel(label).getBytes(), OBJECT_LABEL_SIZE));
        bb.putShort(Utils.getShortFromList(domains));
        bb.putLong(Utils.getLongFromCapabilities(capabilities));
        bb.put(keyAlgorithm.getId());

        byte[] resp = session.sendSecureCmd(Command.GENERATE_HMAC_KEY, bb.array());
        CommandUtils.verifyResponseLength(Command.GENERATE_HMAC_KEY, resp.length, OBJECT_ID_SIZE);

        bb = ByteBuffer.wrap(resp);
        short newid = bb.getShort();

        log.info("Generated HMAC key with ID 0x" + Integer.toHexString(newid) + " using " + keyAlgorithm.getName() + " algorithm");
        return newid;
    }

    /**
     * Imports an HMAC key into the YubiHSM
     *
     * @param session      An authenticated session to communicate with the device over
     * @param id           The desired ID for the new HMAC key. Set to 0 to have it generated
     * @param label        The label of the new HMAC key
     * @param domains      The domains through which the new HMAC key can be accessible
     * @param keyAlgorithm The algorithm used to generate the new HMAC key. Can be one of {{@link Algorithm.HMAC_SHA1}},
     *                     {{@link Algorithm.HMAC_SHA256}}, {{@link Algorithm.HMAC_SHA384}} or {{@link Algorithm.HMAC_SHA512}}
     * @param capabilities The actions that can be performed by the new HMAC key
     * @param hmacKey      The HMAC key. A maximum of 64 bytes for {{@link Algorithm.HMAC_SHA1}} and {{@link Algorithm.HMAC_SHA256}} and 128 bytes for {
     *                     {@link Algorithm.HMAC_SHA384}} and {{@link Algorithm.HMAC_SHA512}}
     * @return ID of the HMAC key generated on the device
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
    public static short importHmacKey(@NonNull final YHSession session, final short id, final String label, @NonNull final List<Integer> domains,
                                      @NonNull final Algorithm keyAlgorithm, final List<Capability> capabilities, @NonNull final byte[] hmacKey)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException, UnsupportedAlgorithmException {
        verifyParametersForNewKey(domains, keyAlgorithm, hmacKey);

        ByteBuffer bb =
                ByteBuffer.allocate(
                        OBJECT_ID_SIZE + OBJECT_LABEL_SIZE + OBJECT_DOMAINS_SIZE + OBJECT_CAPABILITIES_SIZE + OBJECT_ALGORITHM_SIZE + hmacKey.length);
        bb.putShort(id);
        bb.put(Arrays.copyOf(Utils.getLabel(label).getBytes(), OBJECT_LABEL_SIZE));
        bb.putShort(Utils.getShortFromList(domains));
        bb.putLong(Utils.getLongFromCapabilities(capabilities));
        bb.put(keyAlgorithm.getId());
        bb.put(hmacKey);

        byte[] resp = session.sendSecureCmd(Command.PUT_HMAC_KEY, bb.array());
        CommandUtils.verifyResponseLength(Command.PUT_HMAC_KEY, resp.length, OBJECT_ID_SIZE);

        bb = ByteBuffer.wrap(resp);
        short newid = bb.getShort();

        log.info("Imported HMAC key with ID 0x" + Integer.toHexString(newid) + " and " + keyAlgorithm.getName() + " algorithm");
        return newid;
    }

    /**
     * Performs an HMAC signature operation
     *
     * @param session An authenticated session to communicate with the device over
     * @param data    The data to sign
     * @return The HMAC. 20, 32, 48 or 64 bytes, depending on the HMAC key algorithm
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
    public byte[] signHmac(@NonNull final YHSession session, @NonNull final byte[] data)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException, UnsupportedAlgorithmException {
        Utils.checkEmptyByteArray(data, "The data to sign must be at least 1 byte long");

        log.info("Performing HMAC signing using HMAC key 0x" + Integer.toHexString(getId()));
        log.debug("HMAC data: " + Utils.getPrintableBytes(data));

        ByteBuffer bb = ByteBuffer.allocate(OBJECT_ID_SIZE + data.length);
        bb.putShort(getId());
        bb.put(data);

        byte[] hmac = session.sendSecureCmd(Command.SIGN_HMAC, bb.array());
        int expectedSigLength = getSignatureLength(getKeyAlgorithm());
        CommandUtils.verifyResponseLength(Command.SIGN_HMAC, hmac.length, expectedSigLength);
        log.debug("HMAC from YubiHSM: " + Utils.getPrintableBytes(hmac));
        return hmac;
    }

    /**
     * Verifies an HMAC
     *
     * @param session An authenticated session to communicate with the device over
     * @param data    The signed data
     * @param sig     The HMAC. 20, 32, 48 or 64 bytes long depending on the HMAC key algorithm
     * @return True if verification succeeds. False otherwise
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
    public boolean verifyHmac(@NonNull final YHSession session, @NonNull final byte[] data, @NonNull final byte[] sig)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException, UnsupportedAlgorithmException {
        Utils.checkEmptyByteArray(data, "The signed data must be at least 1 byte long");
        int expectedSigLength = getSignatureLength(getKeyAlgorithm());
        if (sig.length != expectedSigLength) {
            throw new IllegalArgumentException(
                    "Wrong HMAC length. Expected " + expectedSigLength + " bytes long HMAC but was " + sig.length + " bytes");
        }

        log.info("Verifying HMAC signature using HMAC key 0x" + Integer.toHexString(getId()));
        log.debug("[HMAC]" + Utils.getPrintableBytes(sig) + " - [HMAC data]" + Utils.getPrintableBytes(data));

        ByteBuffer bb = ByteBuffer.allocate(OBJECT_ID_SIZE + sig.length + data.length);
        bb.putShort(getId());
        bb.put(sig);
        bb.put(data);
        byte[] resp = session.sendSecureCmd(Command.VERIFY_HMAC, bb.array());
        CommandUtils.verifyResponseLength(Command.VERIFY_HMAC, resp.length, 1);

        boolean ret = false;
        if (resp[0] == (byte) 0x01) {
            log.info("HMAC verification successful");
            ret = true;
        } else {
            log.info("HMAC verification failed");
        }
        return ret;
    }

    private int getSignatureLength(@NonNull final Algorithm keyAlgorithm) throws UnsupportedAlgorithmException {
        if (keyAlgorithm.equals(Algorithm.HMAC_SHA1)) {
            return HASH_LENGTH_FOR_SHA1;
        }
        if (keyAlgorithm.equals(Algorithm.HMAC_SHA256)) {
            return HASH_LENGTH_FOR_SHA256;
        }
        if (keyAlgorithm.equals(Algorithm.HMAC_SHA384)) {
            return HASH_LENGTH_FOR_SHA384;
        }
        if (keyAlgorithm.equals(Algorithm.HMAC_SHA512)) {
            return HASH_LENGTH_FOR_SHA512;
        }
        throw new UnsupportedAlgorithmException(keyAlgorithm.getName() + " is not a supported HMAC key algorithm");
    }

    private static void verifyParametersForNewKey(@NonNull final List<Integer> domains, final Algorithm keyAlgorithm, final byte[] key)
            throws UnsupportedAlgorithmException {
        if (domains.isEmpty()) {
            throw new IllegalArgumentException("Domains parameter cannot be null or empty");
        }
        if (!isHmacKeyAlgorithm(keyAlgorithm)) {
            throw new UnsupportedAlgorithmException(keyAlgorithm.toString() + " is not a supported Wrap key algorithm");
        }

        if (key != null) {
            if ((keyAlgorithm.equals(Algorithm.HMAC_SHA1) || keyAlgorithm.equals(Algorithm.HMAC_SHA256)) &&
                (key.length > MAX_KEY_LENGTH_SHA1_SHA256)) {
                throw new IllegalArgumentException(
                        "HMAC key too long. Expected maximum of " + MAX_KEY_LENGTH_SHA1_SHA256 + " bytes but was " + key.length);
            } else if ((keyAlgorithm.equals(Algorithm.HMAC_SHA384) || keyAlgorithm.equals(Algorithm.HMAC_SHA512)) &&
                       (key.length > MAX_KEY_LENGTH_SHA384_SHA512)) {
                throw new IllegalArgumentException(
                        "HMAC key too long. Expected maximum of " + MAX_KEY_LENGTH_SHA384_SHA512 + " bytes but was " + key.length);
            }
            Utils.checkEmptyByteArray(key, "The HMAC key cannot be empty");
        }
    }

}
