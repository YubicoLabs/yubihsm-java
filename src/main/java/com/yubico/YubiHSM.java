package com.yubico;

import com.yubico.backend.Backend;
import com.yubico.exceptions.*;
import com.yubico.objects.Command;
import com.yubico.objects.DeviceInfo;
import com.yubico.util.CommandUtils;
import com.yubico.util.Utils;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

/**
 * This class handles commands and command packages for communication with the device. It also implements basic YubiHSM commands
 */
public class YubiHSM {

    private Logger logger = Logger.getLogger(YubiHSM.class.getName());

    /**
     * The backend used to connect to the device
     */
    private Backend backend;

    public YubiHSM(Backend backend) {
        this.backend = backend;
    }

    /**
     * @return Backend used to connect to the device
     */
    public Backend getBackend() {
        return backend;
    }

    /**
     * Close the connection to the device
     */
    public void close() {
        backend.close();
    }

    /**
     * Sends a command to the device and returns a response.
     * <p>
     * The command code and the length of the input are added at the beginning of the input data before sending the package. In case of success, the
     * response from the device is stripped off the response code and the length of the output before returning the data to the calling method
     *
     * @param cmd  The YubiHSM command to send
     * @param data The input to the command as specified by the YubiHSM
     * @return The output of the command
     * @throws YubiHsmInvalidResponseException If the device response cannot be parsed
     * @throws YubiHsmConnectionException      If the connection to the device fails
     * @throws YubiHsmDeviceException          If the device returns an error
     */
    public byte[] sendCmd(final Command cmd, final byte[] data)
            throws YubiHsmInvalidResponseException, YubiHsmConnectionException, YubiHsmDeviceException {

        final byte[] msg = CommandUtils.getTransceiveMessage(cmd, data);
        byte[] response = backend.transceive(msg);
        return CommandUtils.getResponseData(cmd, response);
    }


    /**
     * Sends a command to the device and gets a response over an authenticated session
     *
     * @param session The session to send the command over
     * @param cmd     The command to send
     * @param data    The input to the command as specified by the YubiHSM
     * @return The output of the command
     * @throws InvalidSession                     If no `session` is null
     * @throws NoSuchAlgorithmException           If message encryption or decryption fails
     * @throws YubiHsmDeviceException             If the device return an error
     * @throws YubiHsmInvalidResponseException    If the device returns a response that cannot be parsed
     * @throws YubiHsmConnectionException         If the connections to the device fails
     * @throws InvalidKeyException                If message encryption or decryption fails
     * @throws YubiHsmAuthenticationException     If the session or message authentication fails
     * @throws NoSuchPaddingException             If message encryption or decryption fails
     * @throws InvalidAlgorithmParameterException If message encryption or decryption fails
     * @throws BadPaddingException                If message encryption or decryption fails
     * @throws IllegalBlockSizeException          If message encryption or decryption fails
     */
    public byte[] sendSecureCmd(YubiHSMSession session, final Command cmd, final byte[] data) throws InvalidSession, NoSuchAlgorithmException,
                                                                                                     YubiHsmDeviceException,
                                                                                                     YubiHsmInvalidResponseException,
                                                                                                     YubiHsmConnectionException,
                                                                                                     InvalidKeyException,
                                                                                                     YubiHsmAuthenticationException,
                                                                                                     NoSuchPaddingException,
                                                                                                     InvalidAlgorithmParameterException,
                                                                                                     BadPaddingException, IllegalBlockSizeException {
        if (session == null) {
            throw new InvalidSession("Secure messages have to be send to the device over an authenticated session");
        }

        if (session.getStatus() != YubiHSMSession.SessionStatus.AUTHENTICATED) {
            session.createAuthenticatedSession();
        }

        byte[] resp = session.secureTransceive(CommandUtils.getTransceiveMessage(cmd, data));
        return CommandUtils.getResponseData(cmd, resp);
    }

    /**
     * Sends the Echo command with `data` as the input
     *
     * @param data The input to the Echo command
     * @return The device response to the Echo command
     * @throws YubiHsmDeviceException          If the device return an error
     * @throws YubiHsmInvalidResponseException If the device returns a response that cannot be parsed
     * @throws YubiHsmConnectionException      If the connection to the device fails
     */
    public byte[] echo(final byte[] data) throws YubiHsmDeviceException, YubiHsmInvalidResponseException, YubiHsmConnectionException {
        return sendCmd(Command.ECHO, data);
    }

    /**
     * Sends the Echo command with `data` as the input over an authenticated session
     *
     * @param session The session to send the command over
     * @param data    The input to the Echo command
     * @return The device response to the Echo command
     * @throws YubiHsmConnectionException         If the connection to the device fails
     * @throws InvalidSession                     If `session` is null
     * @throws NoSuchAlgorithmException           If the message encryption/decryption fails
     * @throws InvalidKeyException                If the message encryption/decryption fails
     * @throws YubiHsmDeviceException             If the device returns an error
     * @throws NoSuchPaddingException             If the message encryption/decryption fails
     * @throws BadPaddingException                If the message encryption/decryption fails
     * @throws YubiHsmAuthenticationException     If the session or message authentication fails
     * @throws InvalidAlgorithmParameterException If the message encryption/decryption fails
     * @throws YubiHsmInvalidResponseException    If the device returns a response that cannot be parsed
     * @throws IllegalBlockSizeException          If the message encryption/decryption fails
     */
    public byte[] secureEcho(final YubiHSMSession session, final byte[] data)
            throws YubiHsmConnectionException, InvalidSession, NoSuchAlgorithmException, InvalidKeyException, YubiHsmDeviceException,
                   NoSuchPaddingException, BadPaddingException, YubiHsmAuthenticationException, InvalidAlgorithmParameterException,
                   YubiHsmInvalidResponseException, IllegalBlockSizeException {
        return sendSecureCmd(session, Command.ECHO, data);
    }

    /**
     * Gets the device info from the device using the DeviceInfo command
     *
     * @return The device info
     * @throws YubiHsmConnectionException      If the connection to the device fails
     * @throws YubiHsmInvalidResponseException If the device returns a response that cannot be parsed
     * @throws YubiHsmDeviceException          If the device returns an error
     */
    public DeviceInfo getDeviceInfo() throws YubiHsmConnectionException, YubiHsmInvalidResponseException, YubiHsmDeviceException {
        byte[] data = sendCmd(Command.DEVICE_INFO, new byte[0]);
        DeviceInfo info = new DeviceInfo(data);
        logger.fine("Got device info: " + info.toString());
        return info;

    }

    /**
     * Reset the device
     *
     * @param session The session to send the command over
     * @throws YubiHsmConnectionException         If the connection to the device fails
     * @throws InvalidSession                     If `session` is null
     * @throws NoSuchAlgorithmException           If the message encryption/decryption fails
     * @throws InvalidKeyException                If the message encryption/decryption fails
     * @throws YubiHsmDeviceException             If the device returns an error
     * @throws NoSuchPaddingException             If the message encryption/decryption fails
     * @throws BadPaddingException                If the message encryption/decryption fails
     * @throws YubiHsmAuthenticationException     If the session or message authentication fails
     * @throws InvalidAlgorithmParameterException If the message encryption/decryption fails
     * @throws YubiHsmInvalidResponseException    If the device returns a response that cannot be parsed
     * @throws IllegalBlockSizeException          If the message encryption/decryption fails
     */
    public void resetDevice(final YubiHSMSession session)
            throws YubiHsmConnectionException, InvalidSession, NoSuchAlgorithmException, InvalidKeyException, YubiHsmDeviceException,
                   NoSuchPaddingException, BadPaddingException, YubiHsmAuthenticationException, InvalidAlgorithmParameterException,
                   YubiHsmInvalidResponseException, IllegalBlockSizeException {
        byte[] resp = sendSecureCmd(session, Command.RESET_DEVICE, new byte[0]);
        if (resp.length != 0) {
            throw new YubiHsmInvalidResponseException("Expecting empty response. Found: " + Utils.getPrintableBytes(resp));
        }
    }

    /**
     * Get pseudo-random data of a specific length from the device
     *
     * @param session The session to send the command over
     * @param length  The number of pseudo random bytes to return
     * @return `length` pseudo random bytes
     * @throws YubiHsmConnectionException         If the connection to the device fails
     * @throws InvalidSession                     If `session` is null
     * @throws NoSuchAlgorithmException           If the message encryption/decryption fails
     * @throws InvalidKeyException                If the message encryption/decryption fails
     * @throws YubiHsmDeviceException             If the device returns an error
     * @throws NoSuchPaddingException             If the message encryption/decryption fails
     * @throws BadPaddingException                If the message encryption/decryption fails
     * @throws YubiHsmAuthenticationException     If the session or message authentication fails
     * @throws InvalidAlgorithmParameterException If the message encryption/decryption fails
     * @throws YubiHsmInvalidResponseException    If the device returns a response that cannot be parsed
     * @throws IllegalBlockSizeException          If the message encryption/decryption fails
     */
    public byte[] getRandom(final YubiHSMSession session, final int length)
            throws YubiHsmConnectionException, InvalidSession, NoSuchAlgorithmException, InvalidKeyException, YubiHsmDeviceException,
                   NoSuchPaddingException, BadPaddingException, YubiHsmAuthenticationException, InvalidAlgorithmParameterException,
                   YubiHsmInvalidResponseException, IllegalBlockSizeException {
        ByteBuffer data = ByteBuffer.allocate(2);
        data.putShort((short) length);
        return sendSecureCmd(session, Command.GET_PSEUDO_RANDOM, data.array());
    }

}
