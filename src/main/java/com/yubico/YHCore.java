package com.yubico;

import com.yubico.exceptions.YHAuthenticationException;
import com.yubico.exceptions.YHConnectionException;
import com.yubico.exceptions.YHDeviceException;
import com.yubico.exceptions.YHInvalidResponseException;
import com.yubico.internal.util.Utils;
import com.yubico.objects.yhconcepts.Command;
import lombok.NonNull;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

public class YHCore {
    private static Logger log = Logger.getLogger(YHCore.class.getName());

    /**
     * Sends the Echo command with `data` as the input over an authenticated session
     *
     * @param session An authenticated session to communicate with the device over
     * @param data    The data that should be echoed back by the device
     * @return The device response to the Echo command. Should be the same as `data`
     * @throws YHConnectionException              If the connection to the device fails
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
    public static byte[] secureEcho(@NonNull final YHSession session, final byte[] data)
            throws YHConnectionException, NoSuchAlgorithmException, InvalidKeyException, YHDeviceException,
                   NoSuchPaddingException, BadPaddingException, YHAuthenticationException, InvalidAlgorithmParameterException,
                   YHInvalidResponseException, IllegalBlockSizeException {
        return session.sendSecureCmd(Command.ECHO, data);
    }

    /**
     * Reset the device
     *
     * @param session An authenticated session to communicate with the device over
     * @throws YHConnectionException              If the connection to the device fails
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
    public static void resetDevice(@NonNull final YHSession session)
            throws YHConnectionException, NoSuchAlgorithmException, InvalidKeyException, YHDeviceException,
                   NoSuchPaddingException, BadPaddingException, YHAuthenticationException, InvalidAlgorithmParameterException,
                   YHInvalidResponseException, IllegalBlockSizeException {
        log.info("Resetting the YubiHSM");
        byte[] resp = session.sendSecureCmd(Command.RESET_DEVICE, new byte[0]);
        if (resp.length != 0) {
            throw new YHInvalidResponseException("Expecting empty response. Found: " + Utils.getPrintableBytes(resp));
        }
    }

    /**
     * Get pseudo-random data of a specific length from the device
     *
     * @param session An authenticated session to communicate with the device over
     * @param length  The number of pseudo random bytes to return
     * @return `length` pseudo random bytes
     * @throws YHConnectionException              If the connection to the device fails
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
    public static byte[] getRandom(@NonNull final YHSession session, final int length)
            throws YHConnectionException, NoSuchAlgorithmException, InvalidKeyException, YHDeviceException,
                   NoSuchPaddingException, BadPaddingException, YHAuthenticationException, InvalidAlgorithmParameterException,
                   YHInvalidResponseException, IllegalBlockSizeException {
        log.info("Getting " + length + " random bytes from the device");
        ByteBuffer data = ByteBuffer.allocate(2);
        data.putShort((short) length);
        return session.sendSecureCmd(Command.GET_PSEUDO_RANDOM, data.array());
    }
}
