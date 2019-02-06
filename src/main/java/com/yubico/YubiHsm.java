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
public class YubiHsm {

    private Logger logger = Logger.getLogger(YubiHsm.class.getName());

    /**
     * The backend used to connect to the device
     */
    private Backend backend;

    public YubiHsm(Backend backend) {
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
     * @param data The input to the command
     * @return The output of the command
     * @throws YHInvalidResponseException If the device response cannot be parsed
     * @throws YHConnectionException      If the connection to the device fails
     * @throws YHDeviceException          If the device returns an error
     */
    public byte[] sendCmd(final Command cmd, final byte[] data)
            throws YHInvalidResponseException, YHConnectionException, YHDeviceException {

        final byte[] msg = CommandUtils.getTransceiveMessage(cmd, data);
        byte[] response = backend.transceive(msg);
        return CommandUtils.getResponseData(cmd, response);
    }


    /**
     * Sends a command to the device and gets a response over an authenticated session
     *
     * @param session The session to send the command over
     * @param cmd     The command to send
     * @param data    The input to the command
     * @return The output of the command
     * @throws InvalidSession                     If no `session` is null
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
    public byte[] sendSecureCmd(YHSession session, final Command cmd, final byte[] data) throws InvalidSession, NoSuchAlgorithmException,
                                                                                                YHDeviceException,
                                                                                                YHInvalidResponseException,
                                                                                                YHConnectionException,
                                                                                                InvalidKeyException,
                                                                                                YHAuthenticationException,
                                                                                                NoSuchPaddingException,
                                                                                                InvalidAlgorithmParameterException,
                                                                                                BadPaddingException, IllegalBlockSizeException {
        if (session == null) {
            throw new InvalidSession("Secure messages have to be send to the device over an authenticated session");
        }

        if (session.getStatus() != YHSession.SessionStatus.AUTHENTICATED) {
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
     * @throws YHDeviceException          If the device return an error
     * @throws YHInvalidResponseException If the device returns a response that cannot be parsed
     * @throws YHConnectionException      If the connection to the device fails
     */
    public byte[] echo(final byte[] data) throws YHDeviceException, YHInvalidResponseException, YHConnectionException {
        return sendCmd(Command.ECHO, data);
    }

    /**
     * Sends the Echo command with `data` as the input over an authenticated session
     *
     * @param session The session to send the command over
     * @param data    The input to the Echo command
     * @return The device response to the Echo command
     * @throws YHConnectionException              If the connection to the device fails
     * @throws InvalidSession                     If `session` is null
     * @throws NoSuchAlgorithmException           If the message encryption/decryption fails
     * @throws InvalidKeyException                If the message encryption/decryption fails
     * @throws YHDeviceException                  If the device returns an error
     * @throws NoSuchPaddingException             If the message encryption/decryption fails
     * @throws BadPaddingException                If the message encryption/decryption fails
     * @throws YHAuthenticationException          If the session or message authentication fails
     * @throws InvalidAlgorithmParameterException If the message encryption/decryption fails
     * @throws YHInvalidResponseException         If the device returns a response that cannot be parsed
     * @throws IllegalBlockSizeException          If the message encryption/decryption fails
     */
    public byte[] secureEcho(final YHSession session, final byte[] data)
            throws YHConnectionException, InvalidSession, NoSuchAlgorithmException, InvalidKeyException, YHDeviceException,
                   NoSuchPaddingException, BadPaddingException, YHAuthenticationException, InvalidAlgorithmParameterException,
                   YHInvalidResponseException, IllegalBlockSizeException {
        return sendSecureCmd(session, Command.ECHO, data);
    }

    /**
     * Gets the device info from the device using the DeviceInfo command
     *
     * @return The device info
     * @throws YHConnectionException      If the connection to the device fails
     * @throws YHInvalidResponseException If the device returns a response that cannot be parsed
     * @throws YHDeviceException          If the device returns an error
     */
    public DeviceInfo getDeviceInfo() throws YHConnectionException, YHInvalidResponseException, YHDeviceException {
        byte[] data = sendCmd(Command.DEVICE_INFO, new byte[0]);
        DeviceInfo info = new DeviceInfo(data);
        logger.fine("Got device info: " + info.toString());
        return info;

    }

    /**
     * Reset the device
     *
     * @param session The session to send the command over
     * @throws YHConnectionException              If the connection to the device fails
     * @throws InvalidSession                     If `session` is null
     * @throws NoSuchAlgorithmException           If the message encryption/decryption fails
     * @throws InvalidKeyException                If the message encryption/decryption fails
     * @throws YHDeviceException                  If the device returns an error
     * @throws NoSuchPaddingException             If the message encryption/decryption fails
     * @throws BadPaddingException                If the message encryption/decryption fails
     * @throws YHAuthenticationException          If the session or message authentication fails
     * @throws InvalidAlgorithmParameterException If the message encryption/decryption fails
     * @throws YHInvalidResponseException         If the device returns a response that cannot be parsed
     * @throws IllegalBlockSizeException          If the message encryption/decryption fails
     */
    public void resetDevice(final YHSession session)
            throws YHConnectionException, InvalidSession, NoSuchAlgorithmException, InvalidKeyException, YHDeviceException,
                   NoSuchPaddingException, BadPaddingException, YHAuthenticationException, InvalidAlgorithmParameterException,
                   YHInvalidResponseException, IllegalBlockSizeException {
        byte[] resp = sendSecureCmd(session, Command.RESET_DEVICE, new byte[0]);
        if (resp.length != 0) {
            throw new YHInvalidResponseException("Expecting empty response. Found: " + Utils.getPrintableBytes(resp));
        }
    }

    /**
     * Get pseudo-random data of a specific length from the device
     *
     * @param session The session to send the command over
     * @param length  The number of pseudo random bytes to return
     * @return `length` pseudo random bytes
     * @throws YHConnectionException              If the connection to the device fails
     * @throws InvalidSession                     If `session` is null
     * @throws NoSuchAlgorithmException           If the message encryption/decryption fails
     * @throws InvalidKeyException                If the message encryption/decryption fails
     * @throws YHDeviceException                  If the device returns an error
     * @throws NoSuchPaddingException             If the message encryption/decryption fails
     * @throws BadPaddingException                If the message encryption/decryption fails
     * @throws YHAuthenticationException          If the session or message authentication fails
     * @throws InvalidAlgorithmParameterException If the message encryption/decryption fails
     * @throws YHInvalidResponseException         If the device returns a response that cannot be parsed
     * @throws IllegalBlockSizeException          If the message encryption/decryption fails
     */
    public byte[] getRandom(final YHSession session, final int length)
            throws YHConnectionException, InvalidSession, NoSuchAlgorithmException, InvalidKeyException, YHDeviceException,
                   NoSuchPaddingException, BadPaddingException, YHAuthenticationException, InvalidAlgorithmParameterException,
                   YHInvalidResponseException, IllegalBlockSizeException {
        ByteBuffer data = ByteBuffer.allocate(2);
        data.putShort((short) length);
        return sendSecureCmd(session, Command.GET_PSEUDO_RANDOM, data.array());
    }

}
