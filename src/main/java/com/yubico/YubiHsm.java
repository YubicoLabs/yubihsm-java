package com.yubico;

import com.yubico.backend.Backend;
import com.yubico.exceptions.*;
import com.yubico.internal.util.CommandUtils;
import com.yubico.internal.util.Utils;
import com.yubico.objects.DeviceInfo;
import com.yubico.objects.yhconcepts.Capability;
import com.yubico.objects.yhconcepts.Command;
import com.yubico.objects.yhconcepts.ObjectType;
import com.yubico.objects.yhobjects.YHObject;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/**
 * This class handles commands and command packages for communication with the device. It also implements basic YubiHSM commands
 */
public class YubiHsm {

    private Logger logger = Logger.getLogger(YubiHsm.class.getName());

    public enum LIST_FILTERS {
        ID,
        TYPE,
        DOMAINS,
        CAPABILITIES,
        ALGORITHM,
        LABEL
    }

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
     * @throws InvalidSessionException            If `session` is null
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
            throws YHConnectionException, InvalidSessionException, NoSuchAlgorithmException, InvalidKeyException, YHDeviceException,
                   NoSuchPaddingException, BadPaddingException, YHAuthenticationException, InvalidAlgorithmParameterException,
                   YHInvalidResponseException, IllegalBlockSizeException {
        if (session == null) {
            throw new InvalidSessionException();
        }
        return session.sendSecureCmd(Command.ECHO, data);
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
     * @throws InvalidSessionException            If `session` is null
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
            throws YHConnectionException, InvalidSessionException, NoSuchAlgorithmException, InvalidKeyException, YHDeviceException,
                   NoSuchPaddingException, BadPaddingException, YHAuthenticationException, InvalidAlgorithmParameterException,
                   YHInvalidResponseException, IllegalBlockSizeException {
        if (session == null) {
            throw new InvalidSessionException();
        }
        byte[] resp = session.sendSecureCmd(Command.RESET_DEVICE, new byte[0]);
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
     * @throws InvalidSessionException            If `session` is null
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
            throws YHConnectionException, InvalidSessionException, NoSuchAlgorithmException, InvalidKeyException, YHDeviceException,
                   NoSuchPaddingException, BadPaddingException, YHAuthenticationException, InvalidAlgorithmParameterException,
                   YHInvalidResponseException, IllegalBlockSizeException {
        if (session == null) {
            throw new InvalidSessionException();
        }
        ByteBuffer data = ByteBuffer.allocate(2);
        data.putShort((short) length);
        return session.sendSecureCmd(Command.GET_PSEUDO_RANDOM, data.array());
    }

    public List<YHObject> getObjectList(final YHSession session, final Map<LIST_FILTERS, Object> filters)
            throws IOException, InvalidSessionException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   NoSuchPaddingException, IllegalBlockSizeException {
        if (session == null) {
            throw new InvalidSessionException();
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        if (filters != null) {
            try {
                ByteBuffer bb;
                for (LIST_FILTERS f : filters.keySet()) {
                    switch (f) {
                        case ID:
                            bb = ByteBuffer.allocate(3);
                            bb.put((byte) 0x01).putShort((short) filters.get(f));
                            baos.write(bb.array());
                            break;
                        case TYPE:
                            bb = ByteBuffer.allocate(2);
                            bb.put((byte) 0x02);
                            Object type = filters.get(f);
                            if (type instanceof Byte) {
                                bb.put((byte) type);
                            } else if (type instanceof ObjectType) {
                                bb.put(((ObjectType) type).getTypeId());
                            }
                            baos.write(bb.array());
                            break;
                        case DOMAINS:
                            bb = ByteBuffer.allocate(3);
                            bb.put((byte) 0x03);
                            Object domains = filters.get(f);
                            if (domains instanceof Short) {
                                bb.putShort((short) domains);
                            } else if (domains instanceof List) {
                                bb.putShort(Utils.getShortFromList((List) domains));
                            }
                            baos.write(bb.array());
                            break;
                        case CAPABILITIES:
                            bb = ByteBuffer.allocate(9);
                            bb.put((byte) 0x04);
                            Object capabilities = filters.get(f);
                            if (capabilities instanceof Long) {
                                bb.putLong(((long) capabilities));
                            } else if (capabilities instanceof List) {
                                bb.putLong(Capability.getCapabilities((List) capabilities));
                            }
                            baos.write(bb.array());
                            break;
                        case ALGORITHM:
                            bb = ByteBuffer.allocate(2);
                            bb.put((byte) 0x05).put((byte) filters.get(f));
                            baos.write(bb.array());
                            break;
                        case LABEL:
                            final String label = (String) filters.get(f);
                            bb = ByteBuffer.allocate(41);
                            bb.put((byte) 0x06).put(label.getBytes());
                            baos.write(bb.array());
                            break;
                        default:
                            // do nothing
                            break;

                    }
                }
            } catch (IOException e) {
                logger.severe("Failed to construct input message to the " + Command.LIST_OBJECTS.getName() + " command");
                throw e;
            }
        }

        byte[] cmdMessage = baos.toByteArray();
        byte[] response = session.sendSecureCmd(Command.LIST_OBJECTS, cmdMessage);
        if (response.length % 4 != 0) {
            logger.finer(Command.LIST_OBJECTS.getName() + " response: " + Utils.getPrintableBytes(response));
            throw new YHInvalidResponseException("Expecting length of response to " + Command.LIST_OBJECTS.getName() + " command to be a multiple " +
                                                 "of 4 but have recieved " + response.length + " bytes instead");
        }
        ByteBuffer bb = ByteBuffer.wrap(response);
        List<YHObject> ret = new ArrayList<>();
        while (bb.hasRemaining()) {
            ret.add(new YHObject(bb.getShort(), ObjectType.getObjectType(bb.get()), bb.get()));
        }
        logger.fine("Response to " + Command.LIST_OBJECTS.getName() + " command contained " + ret.size() + " objects");
        return ret;
    }

    public void deleteObject(final YHSession session, final short objectID, final ObjectType objectType) throws InvalidSessionException,
                                                                                                                NoSuchAlgorithmException,
                                                                                                                YHDeviceException,
                                                                                                                YHInvalidResponseException,
                                                                                                                YHConnectionException,
                                                                                                                InvalidKeyException,
                                                                                                                YHAuthenticationException,
                                                                                                                NoSuchPaddingException,
                                                                                                                InvalidAlgorithmParameterException,
                                                                                                                BadPaddingException,
                                                                                                                IllegalBlockSizeException {
        if (session == null) {
            throw new InvalidSessionException();
        }
        Utils.checkNullValue(objectType, "Object type is necessary to identify the object to delete");

        ByteBuffer bb = ByteBuffer.allocate(3);
        bb.putShort(objectID);
        bb.put(objectType.getTypeId());
        session.sendSecureCmd(Command.DELETE_OBJECT, bb.array());
    }

}
