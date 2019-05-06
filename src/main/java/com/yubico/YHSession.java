package com.yubico;

import com.yubico.exceptions.*;
import com.yubico.internal.util.CommandUtils;
import com.yubico.internal.util.Utils;
import com.yubico.objects.yhconcepts.Command;
import com.yubico.objects.yhobjects.AuthenticationKey;
import lombok.NonNull;
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
import java.util.logging.Logger;

/**
 * Class to handle communication with the device over an authenticated session
 */
public class YHSession {
    Logger log = Logger.getLogger(YHSession.class.getName());

    public enum SessionStatus {
        NOT_INITIALIZED,
        CREATED,
        AUTHENTICATED,
        CLOSED
    }

    private final byte KEY_ENC = 0x04;
    private final byte KEY_MAC = 0x06;
    private final byte KEY_RMAC = 0x07;
    private final byte CARD_CRYPTOGRAM = 0x00;
    private final byte HOST_CRYPTOGRAM = 0x01;
    private final int BLOCK_SIZE = 16;
    private final int HALF_BLOCK_SIZE = 8;

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

    public YHSession(final YubiHsm hsm, final short authKeyId, char[] password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        yubihsm = hsm;
        authenticationKey = new AuthenticationKey(authKeyId, password);
        init();
    }

    public YHSession(final YubiHsm hsm, final short authKeyId, final byte[] encryptionKey, final byte[] macKey) {
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
    public void createAuthenticatedSession()
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException,
                   YHAuthenticationException {

        if (status == SessionStatus.AUTHENTICATED) {
            log.fine("Session " + getSessionID() + " already authenticated. Doing nothing");
            return;
        }

        if (authenticationKey == null) {
            throw new YHAuthenticationException("Authentication key is needed to open a session to the device");
        }

        byte[] challenge = SecureRandom.getInstanceStrong().generateSeed(8);
        byte[] responseData = getCreateSessionResponse(challenge);


        // Assemble 16 byte challenge consisting of the 8 random bytes sent to the device followed by the 8 bytes received from the device
        challenge = getSessionAuthenticationChallenge(challenge, Arrays.copyOfRange(responseData, 1, 1 + 8));
        log.finer("Authenticating session context: " + Utils.getPrintableBytes(challenge));

        deriveSessionKeys(challenge);
        verifyCardCryptogram(Arrays.copyOfRange(responseData, 9, 9 + 8), challenge);

        // Send AuthenticateSession command
        byte[] inputData = getSessionAuthenticateMessageToMac(challenge);
        sessionChain = getMac(sessionMacKey, new byte[16], inputData, BLOCK_SIZE);
        inputData = getAuthenticateSessionInputData(inputData, sessionChain);
        log.finer("Authenticate Session data: " + Utils.getPrintableBytes(inputData));
        responseData = yubihsm.getBackend().transceive(inputData);

        // Parse the response
        responseData = CommandUtils.getResponseData(Command.AUTHENTICATE_SESSION, responseData);
        log.finer("Authenticate Session response data: " + Utils.getPrintableBytes(responseData));
        if (responseData.length > 0) {
            log.severe("Received a non empty response from device");
            throw new YHInvalidResponseException(YHError.AUTHENTICATION_FAILED);
        }

        status = SessionStatus.AUTHENTICATED;
        lowCounter = 1;
    }

    /**
     * Sends an encrypted message over this authenticated session to the device and returns the device's response.
     *
     * @param message The message to send
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
        if (status != SessionStatus.AUTHENTICATED) {
            if (status == SessionStatus.NOT_INITIALIZED || status == SessionStatus.CREATED) {
                createAuthenticatedSession();
            } else {
                throw new YHAuthenticationException("Session needs to be authenticated to send secure messages to the device");
            }
        }

        // Add necessary padding to the message
        log.finer("Sending message: " + Utils.getPrintableBytes(message));
        byte[] msg = Utils.addPadding(message, BLOCK_SIZE);
        log.finer("Plain text message: " + Utils.getPrintableBytes(msg));

        // Encrypt the message
        SecretKey key = new SecretKeySpec(sessionEncKey, "AES");
        byte[] iv = getIv(key);
        msg = getEncryptedMessage(msg, key, iv, Cipher.ENCRYPT_MODE);
        log.finer("Encrypted message: " + Utils.getPrintableBytes(msg));

        // Calculate message MAC
        msg = getMessageToMac(msg);
        byte[] nextSessionChain = getMac(sessionMacKey, sessionChain, msg, BLOCK_SIZE);

        // Add the message MAC to the message and send it
        ByteBuffer bb = ByteBuffer.allocate(msg.length + 8);
        bb.put(msg);
        bb.put(nextSessionChain, 0, 8);
        msg = bb.array();
        byte[] rawResponse = yubihsm.getBackend().transceive(msg);

        // Verify response and get the encrypted message response. The encrypted response is the output of the command in the sent message (aka.
        // stripped off the session ID and the trailing MAC bytes)
        verifyResponseMac(rawResponse, nextSessionChain);
        log.fine("Response MAC successfully verified");
        byte[] resp = getCommandResponse(rawResponse);
        log.finer("Encrypted response: " + Utils.getPrintableBytes(resp));

        // Decrypt the message response and remove the padding from the plain text response
        resp = getEncryptedMessage(resp, key, iv, Cipher.DECRYPT_MODE);
        log.finer("Plain text response: " + Utils.getPrintableBytes(resp));
        resp = Utils.removePadding(resp, BLOCK_SIZE);
        log.finer("Unpadded plain text response: " + Utils.getPrintableBytes(resp));

        incrementCounter();
        sessionChain = nextSessionChain;

        return resp;
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
            byte[] closeSessionMsg = {Command.CLOSE_SESSION.getCommandId(), (byte) 0, (byte) 0};
            byte[] response = secureTransceive(closeSessionMsg);
            byte[] responseData = CommandUtils.getResponseData(Command.CLOSE_SESSION, response);
            if (responseData.length == 0) {
                sessionID = (byte) 0;
                status = SessionStatus.CLOSED;
            } else {
                final String err = "Received unexpected response from YubiHsm";
                log.fine(err + ": " + Utils.getPrintableBytes(response));
                throw new YHInvalidResponseException(err);
            }

        } catch (YHDeviceException e) {
            if (e.getYhError().equals(YHError.INVALID_SESSION)) {
                log.info("Session " + sessionID + " no longer valid");
            } else {
                throw e;
            }
        } finally {
            authenticationKey.destroyKeys();
            authenticationKey = null;
        }
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

        if (status != YHSession.SessionStatus.AUTHENTICATED) {
            createAuthenticatedSession();
        }

        byte[] resp = secureTransceive(CommandUtils.getTransceiveMessage(cmd, data == null ? new byte[0] : data));
        return CommandUtils.getResponseData(cmd, resp);
    }


    /// Help methods

    /**
     * Sends CreateSession command to the device and returns a response
     *
     * @param challenge 8 random bytes generated by the host
     * @return The device response for CreateSession command
     * @throws YHInvalidResponseException If the response from the device cannot be parsed
     * @throws YHConnectionException      If the connection to the device fails
     * @throws YHDeviceException          If the device returns an error code
     * @throws YHAuthenticationException  If the session ID returned by the device is invalid (aka not in the range 0-15)
     */
    private byte[] getCreateSessionResponse(final byte[] challenge)
            throws YHInvalidResponseException, YHConnectionException, YHDeviceException, YHAuthenticationException {
        byte[] inputData = getCreateSessionInputData(challenge);
        log.finer("Create Session data: " + Utils.getPrintableBytes(inputData));
        byte[] responseData = yubihsm.sendCmd(Command.CREATE_SESSION, inputData);
        log.finer("Create Session response data: " + responseData);

        // Set the session ID if successful
        setSessionID(responseData[0]);
        log.fine("Created session with SessionID: " + sessionID);
        return responseData;
    }

    /**
     * Assembles the input data of the CreateSession command.
     *
     * @param hostChallenge 8 random bytes representing the host's part of the challenge that will be used for authenticating the session
     * @return 10 bytes input to the CreateSession command: 2 byte Authentication Key ID + 8 bytes `hostChallenge`
     */
    private byte[] getCreateSessionInputData(@NonNull final byte[] hostChallenge) {
        ByteBuffer bb = ByteBuffer.allocate(10);
        bb.putShort(authenticationKey.getId());
        bb.put(hostChallenge);
        return bb.array();
    }

    /**
     * Sets the session ID after successfully creating a session with the device
     *
     * @param b The session ID
     * @throws YHAuthenticationException If the specified session ID is not in the range 0-15
     */
    private void setSessionID(final byte b) throws YHAuthenticationException {
        if (b >= ((byte) 0) && b < ((byte) 16)) { // Session ID is between 0 to 15
            sessionID = b;
            status = SessionStatus.CREATED;
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
        if (hostChallenge.length != 8 || deviceChallenge.length != 8) {
            throw new YHAuthenticationException("Either the host challenge or the device challenge is not 8 bytes long");
        }
        ByteBuffer ret = ByteBuffer.allocate(16);
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
        sessionEncKey = deriveKey(authenticationKey.getEncryptionKey(), KEY_ENC, challenge, BLOCK_SIZE * 8);
        sessionMacKey = deriveKey(authenticationKey.getMacKey(), KEY_MAC, challenge, BLOCK_SIZE * 8);
        sessionRMacKey = deriveKey(authenticationKey.getMacKey(), KEY_RMAC, challenge, BLOCK_SIZE * 8);
    }

    /**
     * Verifies the cryptogram received from the device by comparing it with a cryptogram generated using challenge
     *
     * @param cardCryptogram 8 bytes cryptogram received from the device
     * @param challenge      16 bytes challenge consisting of 8 bytes generated by the host + 8 bytes received from the device
     * @throws YHAuthenticationException If the device cryptogram does not match the generated cryptogram
     */
    private void verifyCardCryptogram(@NonNull final byte[] cardCryptogram, final byte[] challenge)
            throws YHAuthenticationException {
        log.finer("Card cryptogram: " + Utils.getPrintableBytes(cardCryptogram));
        byte[] generatedCryptogram = deriveKey(sessionMacKey, CARD_CRYPTOGRAM, challenge, HALF_BLOCK_SIZE * 8);
        if (!Arrays.equals(generatedCryptogram, cardCryptogram)) {
            throw new YHAuthenticationException(YHError.AUTHENTICATION_FAILED);
        }
        log.fine("Card cryptogram successfully verified");
    }

    /**
     * Assembles a message that will be used to calculate its MAC value and sent as a part of the AuthenticateSession command
     *
     * @param challenge 16 bytes challenge consisting of 8 bytes generated by the host + 8 bytes received from the device
     * @return 12 bytes array: 1 byte AuthenticateSession command + 2 bytes length of the input data of the AuthenticateSession command + 1 byte
     * session ID + 8 bytes cryptogram generated by the host
     */
    private byte[] getSessionAuthenticateMessageToMac(final byte[] challenge) {
        // Derive a host cryptogram
        byte[] hostCryptogram = deriveKey(sessionMacKey, HOST_CRYPTOGRAM, challenge, HALF_BLOCK_SIZE * 8);
        log.finer("Host cryptogram: " + Utils.getPrintableBytes(hostCryptogram));

        // Get the message MAC
        ByteBuffer msg = ByteBuffer.allocate(12);
        msg.put(Command.AUTHENTICATE_SESSION.getCommandId());
        msg.putShort((short) (17)); // 1 byte sessionID + 8 byte host cryptogram + 8 bytes MAC
        msg.put(sessionID);
        msg.put(hostCryptogram);
        return msg.array();
    }

    /**
     * Assembles the input data of the AuthenticateSession command
     *
     * @param message 12 bytes message (output of getSessionAuthenticateMessageToMac() )
     * @param fullMac 16 bytes MAC value of message
     * @return 20 bytes: 12 bytes `message` + first 8 bytes of `fullMac`
     */
    private byte[] getAuthenticateSessionInputData(@NonNull final byte[] message, @NonNull final byte[] fullMac) {
        ByteBuffer data = ByteBuffer.allocate(20);
        data.put(message);
        data.put(Arrays.copyOfRange(fullMac, 0, 8));
        return data.array();
    }

    /**
     * Calculate the MAC value of an input
     *
     * @param key       Key used to calculate the MAC
     * @param chain     16 bytes
     * @param input     Data to calculate its MAC
     * @param macLength Length of the MAC value
     * @return The MAC value of input
     */
    private byte[] getMac(final byte[] key, byte[] chain, @NonNull byte[] input, final int macLength) {
        log.finer("Mac input: " + Utils.getPrintableBytes(chain) + " " + Utils.getPrintableBytes(input));
        CipherParameters params = new KeyParameter(key);
        BlockCipher cipher = new AESEngine();
        CMac mac = new CMac(cipher);
        mac.init(params);
        if (chain != null && chain.length > 0) {
            mac.update(chain, 0, chain.length);
        }
        mac.update(input, 0, input.length);
        byte[] out = new byte[macLength];
        mac.doFinal(out, 0);
        log.finer("Full MAC: " + Utils.getPrintableBytes(out));
        return out;
    }

    /**
     * Derives a short lived value from a long term key
     *
     * @param key       A long term key to use to derive a short lived value
     * @param type      Type of the derived key
     * @param challenge 16 bytes challenge consisting of 8 bytes generated by the host + 8 bytes received from the device
     * @param length    Length of the value to generate
     * @return The first bytes of the derived value. The length of these bytes depend on `length`
     */
    private byte[] deriveKey(final byte[] key, final byte type, @NonNull final byte[] challenge, final int length) {

        if (length != BLOCK_SIZE * 8 && length != HALF_BLOCK_SIZE * 8) {
            throw new InvalidParameterException("Length of the derived key must be either " + BLOCK_SIZE + " or " + HALF_BLOCK_SIZE + " bytes long");
        }

        ByteBuffer input = ByteBuffer.allocate(BLOCK_SIZE * 2);
        input.put(new byte[11]);
        input.put(type);
        input.put((byte) 0);
        input.putShort((short) length);
        input.put((byte) 1);
        input.put(challenge);
        byte[] mac = getMac(key, null, input.array(), length);
        return Arrays.copyOfRange(mac, 0, length / 8); //getFirstBytes(mac, length / 8);
    }

    private byte[] getIv(@NonNull final SecretKey key)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        ByteBuffer bb = ByteBuffer.allocate(16);
        bb.putLong(highCounter);
        bb.putLong(lowCounter);
        byte[] ivCounter = bb.array();
        log.finer("IV counter: " + Utils.getPrintableBytes(ivCounter));

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] iv = cipher.doFinal(ivCounter);
        log.finer("IV: " + Utils.getPrintableBytes(iv));
        return iv;
    }

    private byte[] getEncryptedMessage(@NonNull final byte[] message, @NonNull final SecretKey encKey, @NonNull final byte[] iv, final int mode)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException,
                   IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/CBC/NOPADDING");
        cipher.init(mode, encKey, new IvParameterSpec(iv));
        return cipher.doFinal(message);
    }

    /**
     * Assembles the part of the message whose MAC will be calculated to be sent to the device over the authenticated session
     *
     * @param encMessage The encrypted message to sent to the device
     * @return Byte array whose MAC value will be calculated: 1 byte SessionMessage command + 2 bytes length of the input to the SessionMessage
     * command + 1 byte sessionID + `encMessage`
     */
    private byte[] getMessageToMac(@NonNull final byte[] encMessage) {
        int lengthToMac = 1 + encMessage.length + 8; // sessionID + length of encrypted message + mac
        ByteBuffer bb = ByteBuffer.allocate(3 + 1 + encMessage.length);
        bb.put(Command.SESSION_MESSAGE.getCommandId()).putShort((short) lengthToMac);
        bb.put(getSessionID());
        bb.put(encMessage);
        return bb.array();
    }

    /**
     * Verifies the MAC in the response to the SessionMessage command
     *
     * @param rawResponse
     * @param challenge
     * @throws YHAuthenticationException If verification fails
     */
    private void verifyResponseMac(@NonNull final byte[] rawResponse, final byte[] challenge) throws YHAuthenticationException {
        byte[] macInResponse = Arrays.copyOfRange(rawResponse, rawResponse.length - 8, rawResponse.length);
        byte[] rmacToCalculate = Arrays.copyOfRange(rawResponse, 0, rawResponse.length - 8);
        byte[] fullResponseMac = getMac(sessionRMacKey, challenge, rmacToCalculate, BLOCK_SIZE);
        byte[] rmac = Arrays.copyOfRange(fullResponseMac, 0, 8);
        if (!Arrays.equals(rmac, macInResponse)) {
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
    private byte[] getCommandResponse(final byte[] rawResponse)
            throws YHInvalidResponseException, YHDeviceException {
        byte[] resp = CommandUtils.getResponseData(Command.SESSION_MESSAGE, rawResponse);
        if (resp[0] != sessionID) {
            throw new YHInvalidResponseException("Incorrect session ID");
        }

        // extract the response to the command
        // Response: 1 byte session ID + response to the command + 8 bytes MAC
        return Arrays.copyOfRange(resp, 1, resp.length - 8);
    }

    /**
     * Adds 1 to the session counter
     */
    private void incrementCounter() {
        if (lowCounter == 0xFFFFFFFFFFFFFFFFL) {
            highCounter++;
        }
        lowCounter++;
    }

}
