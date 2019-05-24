/*
 * Copyright 2019 Yubico AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.yubico.hsm;

import com.yubico.hsm.exceptions.YHAuthenticationException;
import com.yubico.hsm.exceptions.YHConnectionException;
import com.yubico.hsm.exceptions.YHDeviceException;
import com.yubico.hsm.exceptions.YHInvalidResponseException;
import com.yubico.hsm.internal.util.CommandUtils;
import com.yubico.hsm.internal.util.Utils;
import com.yubico.hsm.yhconcepts.Command;
import com.yubico.hsm.yhconcepts.YHError;
import com.yubico.hsm.yhobjects.AuthenticationKey;
import com.yubico.hsm.yhobjects.YHObject;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * Class to handle communication with the device over an authenticated session
 */
@Slf4j
public class YHSession {

    public enum SessionStatus {
        NOT_INITIALIZED,
        CREATED,
        AUTHENTICATED,
        CLOSED
    }

    private static final byte KEY_ENC = 0x04;
    private static final byte KEY_MAC = 0x06;
    private static final byte KEY_RMAC = 0x07;
    private static final byte CARD_CRYPTOGRAM = 0x00;
    private static final byte HOST_CRYPTOGRAM = 0x01;

    private static final int PADDING_BLOCK_SIZE = 16;
    private static final int CHALLENGE_SIZE = 16;
    private static final int HALF_CHALLENGE_SIZE = 8;
    private static final int SESSION_KEY_SIZE = 16;
    private static final int MESSAGE_MAC_SIZE = 8;
    private static final int SESSION_COUNTER_SIZE = 16;
    private static final byte MIN_SESSION_ID = 0;
    private static final byte MAX_SESSION_ID = 15;
    private static final int SESSION_ID_SIZE = 1;

    private YubiHsm yubihsm;
    @NonNull private AuthenticationKey authenticationKey;
    private byte sessionID;
    private SessionStatus status;
    private byte[] sessionEncKey;
    private byte[] sessionMacKey;
    private byte[] sessionRMacKey;
    private byte[] sessionChain;
    private long lowCounter;
    private long highCounter;

    public YHSession(@NonNull final YubiHsm hsm, final short authKeyId, char[] password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        yubihsm = hsm;
        authenticationKey = new AuthenticationKey(authKeyId, password);
        init();
    }

    public YHSession(@NonNull final YubiHsm hsm, final short authKeyId, final byte[] encryptionKey, final byte[] macKey) {
        yubihsm = hsm;
        authenticationKey = new AuthenticationKey(authKeyId, encryptionKey, macKey);
        init();
    }


    private void init() {
        sessionID = (byte) -1;
        status = SessionStatus.NOT_INITIALIZED;
        sessionEncKey = null;
        sessionMacKey = null;
        sessionRMacKey = null;
        lowCounter = 0;
        highCounter = 0;
        sessionChain = null;
    }

    public byte getSessionID() {
        return sessionID;
    }

    public SessionStatus getStatus() {
        return status;
    }

    public short getAuthenticationKeyID() {
        return authenticationKey.getId();
    }

    /**
     * Creates and authenticates a session with the device
     *
     * @throws NoSuchAlgorithmException   If a random 8 bytes fail to generate
     * @throws YHDeviceException          If the device returns an error
     * @throws YHInvalidResponseException If the device returns a response that cannot be parsed
     * @throws YHConnectionException      If connection with the device fails
     * @throws YHAuthenticationException  If authenticating the session fails
     */
    public void authenticateSession()
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, YHAuthenticationException {

        if (status == SessionStatus.AUTHENTICATED) {
            log.debug("Session " + getSessionID() + " already authenticated. Doing nothing");
            return;
        }

        if (authenticationKey == null) {
            throw new YHAuthenticationException("Authentication key is needed to open a session to the device");
        }

        // Create session
        byte[] hostChallenge = SecureRandom.getInstanceStrong().generateSeed(HALF_CHALLENGE_SIZE);
        Object[] deviceResponse = createSessionAndGetResponse(hostChallenge);
        byte[] deviceChallenge = (byte[]) deviceResponse[0];
        byte[] deviceCryptogram = (byte[]) deviceResponse[1];

        // Assemble 16 byte challenge consisting of the 8 random bytes sent to the device followed by the 8 bytes received from the device
        byte[] challenge = getSessionAuthenticationChallenge(hostChallenge, deviceChallenge);
        log.debug("Authenticating session context: " + Utils.getPrintableBytes(challenge));

        deriveSessionKeys(challenge);
        verifyDeviceCryptogram(deviceCryptogram, challenge);

        // Derive a host cryptogram
        byte[] hostCryptogram = deriveKey(sessionMacKey, HOST_CRYPTOGRAM, challenge, HALF_CHALLENGE_SIZE);
        log.debug("Host cryptogram: " + Utils.getPrintableBytes(hostCryptogram));

        // Authenticate the session
        byte[] authenticateSessionMessage = getAuthenticateSessionMessage(hostCryptogram);
        log.debug("Authenticate Session data: " + Utils.getPrintableBytes(authenticateSessionMessage));
        byte[] authenticateSessionResponse = yubihsm.getBackend().transceive(authenticateSessionMessage);

        // Parse the response
        authenticateSessionResponse = CommandUtils.getResponseData(Command.AUTHENTICATE_SESSION, authenticateSessionResponse);
        log.debug("Authenticate Session response data: " + Utils.getPrintableBytes(authenticateSessionResponse));
        CommandUtils.verifyResponseLength(Command.AUTHENTICATE_SESSION, authenticateSessionResponse.length, 0);

        status = SessionStatus.AUTHENTICATED;
        lowCounter = 1;
    }

    /**
     * Sends an encrypted message over this authenticated session to the device and returns the device's response.
     *
     * @param message The plain text message to send to the device (typically consists of a complete command message )
     * @return The message response in plain text (aka decrypted)
     * @throws YHAuthenticationException          If the session authentication fails
     * @throws NoSuchPaddingException             If the encryption/decryption fails
     * @throws NoSuchAlgorithmException           If the encryption/decryption fails
     * @throws InvalidAlgorithmParameterException If the encryption/decryption fails
     * @throws InvalidKeyException                If the encryption/decryption fails
     * @throws BadPaddingException                If the encryption/decryption fails
     * @throws IllegalBlockSizeException          If the encryption/decryption fails
     * @throws YHConnectionException              If the connection to the device fails
     * @throws YHInvalidResponseException         If the response from the device cannot be parsed
     * @throws YHDeviceException                  If the device returns an error
     */
    public byte[] secureTransceive(@NonNull final byte[] message)
            throws YHAuthenticationException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
                   InvalidKeyException, BadPaddingException, IllegalBlockSizeException, YHConnectionException, YHInvalidResponseException,
                   YHDeviceException {

        if (status == SessionStatus.CLOSED) {
            throw new YHAuthenticationException("Session is not valid");
        }

        if (status != SessionStatus.AUTHENTICATED || !areSessionKeysInitialized()) {
            authenticateSession();
        }

        // Setup the secret key for this message
        SecretKey key = new SecretKeySpec(sessionEncKey, "AES");
        byte[] iv = getIv(key);

        // Add padding
        log.debug("Sending message: " + Utils.getPrintableBytes(message));
        byte[] paddedMsg = Utils.addPadding(message, PADDING_BLOCK_SIZE);
        log.debug("Plain text message: " + Utils.getPrintableBytes(paddedMsg));

        // Encrypt message
        byte[] encryptedMsg = getCipherMessage(paddedMsg, key, iv, Cipher.ENCRYPT_MODE);
        log.debug("Encrypted message: " + Utils.getPrintableBytes(encryptedMsg));

        // Assemble session message command without the MAC
        byte[] sessionMsgNoMac = getSessionMessageNoMac(encryptedMsg);

        // Assemble session message command with the MAC
        byte[] nextSessionChain = getMac(sessionMacKey, sessionChain, sessionMsgNoMac);
        byte[] sessionMessageWithMac = getSessionMessageWithMac(sessionMsgNoMac, nextSessionChain);

        // Send session message command
        byte[] sessionMsgResp = yubihsm.getBackend().transceive(sessionMessageWithMac);

        // Verify response mac
        verifyResponseMac(sessionMsgResp, nextSessionChain);
        log.debug("Response MAC successfully verified");

        // Extract command response message (encrypted)
        byte[] encryptedResp = getSessionMessageResponse(sessionMsgResp);
        log.debug("Encrypted response: " + Utils.getPrintableBytes(encryptedMsg));

        // Decrypt command response message
        byte[] decryptedResp = getCipherMessage(encryptedResp, key, iv, Cipher.DECRYPT_MODE);
        log.debug("Plain text response: " + Utils.getPrintableBytes(decryptedResp));

        // Remove padding from command response message
        byte[] unpaddedResp = Utils.removePadding(decryptedResp, PADDING_BLOCK_SIZE);
        log.debug("Unpadded plain text response: " + Utils.getPrintableBytes(unpaddedResp));

        incrementSessionCounter();
        sessionChain = nextSessionChain;

        // Return unpadded plain text command response message
        return unpaddedResp;
    }

    /**
     * Sends a command to the device and gets a response over an authenticated session
     *
     * @param cmd  The command to send
     * @param data The input to the command
     * @return The output of the command
     * @throws NoSuchAlgorithmException           If message encryption or decryption fails
     * @throws YHDeviceException                  If the device return an error
     * @throws YHInvalidResponseException         If the device returns a response that cannot be parsed
     * @throws YHConnectionException              If the connections to the device fails
     * @throws InvalidKeyException                If message encryption or decryption fails
     * @throws YHAuthenticationException          If the session or message authentication fails
     * @throws NoSuchPaddingException             If message encryption or decryption fails
     * @throws InvalidAlgorithmParameterException If message encryption or decryption fails
     * @throws BadPaddingException                If message encryption or decryption fails
     * @throws IllegalBlockSizeException          If message encryption or decryption fails
     */
    public byte[] sendSecureCmd(@NonNull final Command cmd, final byte[] data)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException {

        byte[] resp = secureTransceive(CommandUtils.getFullCommandMessage(cmd, data == null ? new byte[0] : data));
        return CommandUtils.getResponseData(cmd, resp);
    }


    /**
     * Closes this session with the device
     *
     * @throws YHAuthenticationException          If the message or session authentication fails
     * @throws NoSuchPaddingException             If the encryption/decryption fails
     * @throws NoSuchAlgorithmException           If the encryption/decryption fails
     * @throws InvalidAlgorithmParameterException If the encryption/decryption fails
     * @throws InvalidKeyException                If the encryption/decryption fails
     * @throws BadPaddingException                If the encryption/decryption fails
     * @throws IllegalBlockSizeException          If the encryption/decryption fails
     * @throws YHConnectionException              If the connection to the device fails
     * @throws YHInvalidResponseException         If the device returns a response that cannot be parsed
     * @throws YHDeviceException                  If the device return an error
     */
    public void closeSession()
            throws YHAuthenticationException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
                   InvalidKeyException, BadPaddingException, IllegalBlockSizeException, YHConnectionException, YHInvalidResponseException,
                   YHDeviceException {
        if (status != SessionStatus.CREATED && status != SessionStatus.AUTHENTICATED) {
            log.info("Session is not open. Doing nothing");
            return;
        }

        try {
            byte[] resp = sendSecureCmd(Command.CLOSE_SESSION, null);
            CommandUtils.verifyResponseLength(Command.CLOSE_SESSION, resp.length, 0);
        } catch (YHDeviceException e) {
            if (e.getYhError().equals(YHError.INVALID_SESSION)) {
                log.info("Session " + sessionID + " is not valid");
            } else {
                throw e;
            }
        } finally {
            destroySessionKeys();
            authenticationKey.destroyKeys();
            authenticationKey = null;
        }
        status = SessionStatus.CLOSED;
    }


    /// Help methods

    private void destroySessionKeys() {
        if (sessionEncKey != null) {
            Arrays.fill(sessionEncKey, (byte) 0x00);
        }
        if (sessionMacKey != null) {
            Arrays.fill(sessionMacKey, (byte) 0x00);
        }
        if (sessionRMacKey != null) {
            Arrays.fill(sessionRMacKey, (byte) 0x00);
        }
        log.info("Destroyed the session encryption key, MAC key and RMAC key");
    }

    private boolean areSessionKeysInitialized() {
        return sessionEncKey != null && sessionEncKey.length > 0 &&
               sessionMacKey != null && sessionMacKey.length > 0 &&
               sessionRMacKey != null && sessionRMacKey.length > 0;
    }

    private byte[] getSessionMessageNoMac(@NonNull byte[] encMessage) {
        int sessionMsgLength = SESSION_ID_SIZE + encMessage.length + MESSAGE_MAC_SIZE;
        int macMessageLength = CommandUtils.COMMAND_ID_SIZE + CommandUtils.COMMAND_INPUT_LENGTH_SIZE + SESSION_ID_SIZE + encMessage.length;

        ByteBuffer bb = ByteBuffer.allocate(macMessageLength);
        bb.put(Command.SESSION_MESSAGE.getId()).putShort((short) sessionMsgLength);
        bb.put(getSessionID());
        bb.put(encMessage);
        return bb.array();
    }

    private byte[] getSessionMessageWithMac(@NonNull byte[] sessionMsgNoMac, @NonNull byte[] sessionChain) {
        if (sessionChain.length < MESSAGE_MAC_SIZE) {
            throw new IllegalArgumentException("Session chain is too small to contain a " + MESSAGE_MAC_SIZE + " bytes MAC");
        }
        byte[] mac = Arrays.copyOfRange(sessionChain, 0, MESSAGE_MAC_SIZE);

        ByteBuffer bb = ByteBuffer.allocate(sessionMsgNoMac.length + MESSAGE_MAC_SIZE);
        bb.put(sessionMsgNoMac);
        bb.put(mac);
        return bb.array();
    }

    /**
     * Sends CreateSession command to the device and returns a response
     *
     * @param hostChallenge 8 random bytes generated by the host
     * @return Two byte arrays, the first one is the device challenge and the other is the device cryptogram
     * @throws YHInvalidResponseException If the response from the device cannot be parsed
     * @throws YHConnectionException      If the connection to the device fails
     * @throws YHDeviceException          If the device returns an error code
     * @throws YHAuthenticationException  If the session ID returned by the device is invalid (aka not in the range 0-15)
     */
    private Object[] createSessionAndGetResponse(@NonNull final byte[] hostChallenge)
            throws YHInvalidResponseException, YHConnectionException, YHDeviceException, YHAuthenticationException {
        ByteBuffer bb = ByteBuffer.allocate(YHObject.OBJECT_ID_SIZE + hostChallenge.length);
        bb.putShort(authenticationKey.getId());
        bb.put(hostChallenge);
        byte[] msg = bb.array();

        log.debug("Create Session data: " + Utils.getPrintableBytes(msg));
        byte[] resp = yubihsm.sendCmd(Command.CREATE_SESSION, msg);
        log.debug("Create Session response data: " + Utils.getPrintableBytes(resp));
        CommandUtils.verifyResponseLength(Command.CREATE_SESSION, resp.length, 1 + CHALLENGE_SIZE);

        // Set the session ID if successful
        setSessionID(resp[0]);
        status = SessionStatus.CREATED;
        log.debug("Created session with SessionID: " + sessionID);

        Object[] ret = new Object[2];
        ret[0] = Arrays.copyOfRange(resp, 1, 1 + HALF_CHALLENGE_SIZE); // Device challenge
        ret[1] = Arrays.copyOfRange(resp, 1 + HALF_CHALLENGE_SIZE, resp.length); // Device cryptogram
        return ret;
    }

    /**
     * Sets the session ID after successfully creating a session with the device
     *
     * @param b The session ID
     * @throws YHAuthenticationException If the specified session ID is not in the range 0-15
     */
    private void setSessionID(final byte b) throws YHAuthenticationException {
        if (b >= MIN_SESSION_ID && b <= MAX_SESSION_ID) { // Session ID is between 0 to 15
            sessionID = b;
        } else {
            throw new YHAuthenticationException("Failed to obtain a valid session ID from the device");
        }
    }

    /**
     * Assembles the 16 bytes challenge used for authenticating the session with the device.
     *
     * @param hostChallenge   8 random bytes generated by the host
     * @param deviceChallenge 8 bytes received from the device
     * @return 16 bytes: 8 bytes `hostChallenge` + 8 bytes `deviceChallenge`
     * @throws YHAuthenticationException If either hostChallenge of deviceChallenge are not 8 bytes long
     */
    private byte[] getSessionAuthenticationChallenge(@NonNull final byte[] hostChallenge, @NonNull final byte[] deviceChallenge)
            throws YHAuthenticationException {
        if (hostChallenge.length != HALF_CHALLENGE_SIZE || deviceChallenge.length != HALF_CHALLENGE_SIZE) {
            throw new YHAuthenticationException("Either the host challenge or the device challenge is not " + HALF_CHALLENGE_SIZE + " bytes long. " +
                                                "Host challenge: " + Utils.getPrintableBytes(hostChallenge) + ". Device challenge: " +
                                                Utils.getPrintableBytes(deviceChallenge));
        }
        ByteBuffer ret = ByteBuffer.allocate(CHALLENGE_SIZE);
        ret.put(hostChallenge);
        ret.put(deviceChallenge);
        return ret.array();
    }

    /**
     * Derives the short term session encryption key, session MAC key and session response MAC key
     *
     * @param challenge 16 bytes challenge consisting of 8 bytes generated by the host + 8 bytes received from the device
     */
    private void deriveSessionKeys(final byte[] challenge) {
        sessionEncKey = deriveKey(authenticationKey.getEncryptionKey(), KEY_ENC, challenge, SESSION_KEY_SIZE);
        sessionMacKey = deriveKey(authenticationKey.getMacKey(), KEY_MAC, challenge, SESSION_KEY_SIZE);
        sessionRMacKey = deriveKey(authenticationKey.getMacKey(), KEY_RMAC, challenge, SESSION_KEY_SIZE);
    }

    /**
     * Verifies the cryptogram received from the device by comparing it with a cryptogram generated using `challenge`
     *
     * @param deviceCryptogram 8 bytes cryptogram received from the device
     * @param challenge        16 bytes challenge consisting of 8 bytes generated by the host + 8 bytes received from the device
     * @throws YHAuthenticationException If the device cryptogram does not match the generated cryptogram
     */
    private void verifyDeviceCryptogram(@NonNull final byte[] deviceCryptogram, final byte[] challenge)
            throws YHAuthenticationException {
        log.debug("Card cryptogram: " + Utils.getPrintableBytes(deviceCryptogram));
        byte[] generatedCryptogram = deriveKey(sessionMacKey, CARD_CRYPTOGRAM, challenge, HALF_CHALLENGE_SIZE);
        if (!Arrays.equals(generatedCryptogram, deviceCryptogram)) {
            throw new YHAuthenticationException(YHError.AUTHENTICATION_FAILED);
        }
        log.debug("Card cryptogram successfully verified");
    }

    private byte[] getAuthenticateSessionMessage(@NonNull final byte[] hostCryptogram) {
        // Count data lengths
        // The part of the message to mac: authentication session command + command input data length + session ID + host cryptogram
        int macMsgLength = CommandUtils.COMMAND_ID_SIZE + CommandUtils.COMMAND_INPUT_LENGTH_SIZE + SESSION_ID_SIZE + hostCryptogram.length;

        // Construct the message that will be MAC:ed
        ByteBuffer bb = ByteBuffer.allocate(macMsgLength);
        bb.put(Command.AUTHENTICATE_SESSION.getId());
        bb.putShort((short) (SESSION_ID_SIZE + hostCryptogram.length + MESSAGE_MAC_SIZE));
        bb.put(sessionID);
        bb.put(hostCryptogram);
        byte[] msg = bb.array();

        // Calculate MAC of the message content
        sessionChain = getMac(sessionMacKey, new byte[CHALLENGE_SIZE], msg);
        byte[] msgMac = Arrays.copyOfRange(sessionChain, 0, MESSAGE_MAC_SIZE);

        // Add the MAC to the message content
        bb = ByteBuffer.allocate(macMsgLength + MESSAGE_MAC_SIZE);
        bb.put(msg);
        bb.put(msgMac);
        return bb.array();
    }

    /**
     * Calculate the MAC value of an input
     *
     * @param key   Key used to calculate the MAC
     * @param chain 16 bytes
     * @param input Data to calculate its MAC
     * @return 16 bytes MAC
     */
    private byte[] getMac(@NonNull final byte[] key, byte[] chain, @NonNull byte[] input) {
        log.debug("Mac input: " + Utils.getPrintableBytes(chain) + " " + Utils.getPrintableBytes(input));
        CipherParameters params = new KeyParameter(key);
        BlockCipher cipher = new AESEngine();
        CMac mac = new CMac(cipher);
        mac.init(params);
        if (chain != null && chain.length > 0) {
            mac.update(chain, 0, chain.length);
        }
        mac.update(input, 0, input.length);
        byte[] out = new byte[MESSAGE_MAC_SIZE * 2];
        mac.doFinal(out, 0);
        log.debug("Full MAC: " + Utils.getPrintableBytes(out));
        return out;
    }

    /**
     * Derives a short lived value from a long term key
     *
     * @param longTermKey A long term key to use to derive a short lived value
     * @param type        Type of the derived key
     * @param challenge   16 bytes challenge consisting of 8 bytes generated by the host + 8 bytes received from the device
     * @param length      Length of the value to generate
     * @return The first bytes of the derived value. The length of these bytes depend on `length`
     */
    private byte[] deriveKey(final byte[] longTermKey, final byte type, @NonNull final byte[] challenge, final int length) {

        if (length != SESSION_KEY_SIZE && length != (SESSION_KEY_SIZE / 2)) {
            throw new InvalidParameterException("Length of the derived key must be either " + SESSION_KEY_SIZE + " or " + (SESSION_KEY_SIZE / 2) +
                                                " bytes long");
        }

        int macMsgLength = 11 + 1 + 1 + 2 + 1 + challenge.length; // 11 0 bytes + 1 byte type + 1 0 byte + 2 bytes length + 1 1 byte + challenge
        ByteBuffer input = ByteBuffer.allocate(macMsgLength);
        input.put(new byte[11]);
        input.put(type);
        input.put((byte) 0);
        input.putShort((short) (length * 8));
        input.put((byte) 1);
        input.put(challenge);
        byte[] mac = getMac(longTermKey, null, input.array());
        return Arrays.copyOfRange(mac, 0, length);
    }

    private byte[] getIv(@NonNull final SecretKey key)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] ivCounter = getSessionCounter();
        log.debug("IV counter: " + Utils.getPrintableBytes(ivCounter));

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] iv = cipher.doFinal(ivCounter);
        log.debug("IV: " + Utils.getPrintableBytes(iv));
        return iv;
    }

    private byte[] getCipherMessage(@NonNull final byte[] message, @NonNull final SecretKey encKey, @NonNull final byte[] iv, final int mode)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException,
                   IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/CBC/NOPADDING");
        cipher.init(mode, encKey, new IvParameterSpec(iv));
        return cipher.doFinal(message);
    }

    /**
     * Verifies the response from the device by comparing the response MAC with a MAC generated using `challenge`
     *
     * @param response  Contains the response MAC as its last 8 bytes
     * @param challenge
     * @throws YHAuthenticationException If response authentication fails
     */
    private void verifyResponseMac(@NonNull final byte[] response, final byte[] challenge) throws YHAuthenticationException {
        if (response.length < MESSAGE_MAC_SIZE) {
            throw new IllegalArgumentException("Response is too short to contain a " + MESSAGE_MAC_SIZE + " bytes MAC");
        }
        byte[] respMac = Arrays.copyOfRange(response, response.length - MESSAGE_MAC_SIZE, response.length);
        byte[] respMacMsg = Arrays.copyOfRange(response, 0, response.length - MESSAGE_MAC_SIZE);
        byte[] fullResponseMac = getMac(sessionRMacKey, challenge, respMacMsg);
        byte[] rmac = Arrays.copyOfRange(fullResponseMac, 0, MESSAGE_MAC_SIZE);
        if (!Arrays.equals(rmac, respMac)) {
            throw new YHAuthenticationException("Incorrect MAC");
        }
    }

    /**
     * Extracts the encrypted command response from the device's response to SessionMessage
     *
     * @param rawResponse The device response to SessionMessage
     * @return The device's encrypted response to the command inside SessionMessage
     * @throws YHInvalidResponseException If the session ID returned by the device does not match this session ID
     * @throws YHDeviceException          If the device had returned an error code
     */
    private byte[] getSessionMessageResponse(final byte[] rawResponse)
            throws YHInvalidResponseException, YHDeviceException {
        byte[] resp = CommandUtils.getResponseData(Command.SESSION_MESSAGE, rawResponse);
        if (resp[0] != sessionID) {
            throw new YHInvalidResponseException("Incorrect session ID");
        }

        // extract the response to the command
        // Response: 1 byte session ID + response to the command + 8 bytes MAC
        return Arrays.copyOfRange(resp, 1, resp.length - MESSAGE_MAC_SIZE);
    }

    /**
     * Adds 1 to the session counter
     */
    private void incrementSessionCounter() {
        if (lowCounter == 0xFFFFFFFFFFFFFFFFL) {
            highCounter++;
        }
        lowCounter++;
    }

    private byte[] getSessionCounter() {
        ByteBuffer bb = ByteBuffer.allocate(SESSION_COUNTER_SIZE);
        bb.putLong(highCounter);
        bb.putLong(lowCounter);
        return bb.array();
    }

}
