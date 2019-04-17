package com.yubico;

import com.yubico.exceptions.*;
import com.yubico.internal.util.Utils;
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

public class YHCore {

    private static Logger logger = Logger.getLogger(YHCore.class.getName());

    public enum ListFilter {
        ID          ((byte) 0x01, 3), // 1 identifier byte + 2
        TYPE        ((byte) 0x02, 2), // 1 identifier byte + 1
        DOMAINS     ((byte) 0x03, 3), // 1 identifier byte + 2
        CAPABILITIES((byte) 0x04, 9), // 1 identifier byte + 8
        ALGORITHM   ((byte) 0x05, 2), // 1 identifier byte + 1
        LABEL       ((byte) 0x06, 41); // 1 identifier byte + 40

        private final byte identifier;
        private final int length;

        ListFilter(byte id, int l) {
            this.identifier = id;
            this.length = l;
        }

        public byte getIdentifier() {
            return this.identifier;
        }

        public int getLength() {
            return this.length;
        }
    }

    /**
     * Sends the Echo command with `data` as the input over an authenticated session
     *
     * @param session An authenticated session to communicate with the device over
     * @param data    The data that should be echoed back by the device
     * @return The device response to the Echo command. Should be the same as `data`
     * @throws YHConnectionException              If the connection to the device fails
     * @throws InvalidSessionException            If no session is specified
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
    public static byte[] secureEcho(final YHSession session, final byte[] data)
            throws YHConnectionException, InvalidSessionException, NoSuchAlgorithmException, InvalidKeyException, YHDeviceException,
                   NoSuchPaddingException, BadPaddingException, YHAuthenticationException, InvalidAlgorithmParameterException,
                   YHInvalidResponseException, IllegalBlockSizeException {
        if (session == null) {
            throw new InvalidSessionException();
        }
        return session.sendSecureCmd(Command.ECHO, data);
    }

    /**
     * Reset the device
     *
     * @param session An authenticated session to communicate with the device over
     * @throws YHConnectionException              If the connection to the device fails
     * @throws InvalidSessionException            If no session is specified
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
    public static void resetDevice(final YHSession session)
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
     * @param session An authenticated session to communicate with the device over
     * @param length  The number of pseudo random bytes to return
     * @return `length` pseudo random bytes
     * @throws YHConnectionException              If the connection to the device fails
     * @throws InvalidSessionException            If no session is specified
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
    public static byte[] getRandom(final YHSession session, final int length)
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

    /**
     * Return a list of objects on the device. The return value can be filtered by object ID, type, domains, capabilities, algorithm and/or label
     *
     * @param session An authenticated session to communicate with the device over
     * @param filters The filter applied to the result
     * @return A list of objects on the device
     * @throws YHConnectionException              If the connection to the device fails
     * @throws InvalidSessionException            If no session is specified
     * @throws NoSuchAlgorithmException           If the message encryption/decryption fails
     * @throws InvalidKeyException                If the message encryption/decryption fails
     * @throws YHDeviceException                  If the device returns an error
     * @throws NoSuchPaddingException             If the message encryption/decryption fails
     * @throws BadPaddingException                If the message encryption/decryption fails
     * @throws YHAuthenticationException          If the session or message authentication fails
     * @throws InvalidAlgorithmParameterException If the message encryption/decryption fails
     * @throws YHInvalidResponseException         If the device returns a response that cannot be parsed
     * @throws IllegalBlockSizeException          If the message encryption/decryption fails
     * @throws IOException                        If failed to parse the filter
     */
    public static List<YHObject> getObjectList(final YHSession session, final Map<ListFilter, Object> filters)
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
                for (ListFilter f : filters.keySet()) {
                    switch (f) {
                        case ID:
                            bb = ByteBuffer.allocate(ListFilter.ID.length);
                            bb.put(ListFilter.ID.identifier).putShort((short) filters.get(f));
                            baos.write(bb.array());
                            break;
                        case TYPE:
                            bb = ByteBuffer.allocate(ListFilter.TYPE.length);
                            bb.put(ListFilter.TYPE.identifier);
                            Object type = filters.get(f);
                            if (type instanceof Byte) {
                                bb.put((byte) type);
                            } else if (type instanceof ObjectType) {
                                bb.put(((ObjectType) type).getTypeId());
                            }
                            baos.write(bb.array());
                            break;
                        case DOMAINS:
                            bb = ByteBuffer.allocate(ListFilter.DOMAINS.length);
                            bb.put(ListFilter.DOMAINS.identifier);
                            Object domains = filters.get(f);
                            if (domains instanceof Short) {
                                bb.putShort((short) domains);
                            } else if (domains instanceof List) {
                                bb.putShort(Utils.getShortFromList((List) domains));
                            }
                            baos.write(bb.array());
                            break;
                        case CAPABILITIES:
                            bb = ByteBuffer.allocate(ListFilter.CAPABILITIES.length);
                            bb.put(ListFilter.CAPABILITIES.identifier);
                            Object capabilities = filters.get(f);
                            if (capabilities instanceof Long) {
                                bb.putLong(((long) capabilities));
                            } else if (capabilities instanceof List) {
                                bb.putLong(Capability.getCapabilities((List) capabilities));
                            }
                            baos.write(bb.array());
                            break;
                        case ALGORITHM:
                            bb = ByteBuffer.allocate(ListFilter.ALGORITHM.length);
                            bb.put(ListFilter.ALGORITHM.identifier).put((byte) filters.get(f));
                            baos.write(bb.array());
                            break;
                        case LABEL:
                            final String label = (String) filters.get(f);
                            bb = ByteBuffer.allocate(ListFilter.LABEL.length);
                            bb.put(ListFilter.LABEL.identifier).put(label.getBytes());
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

    /**
     * Deletes a specific object from the device
     *
     * @param session    An authenticated session to communicate with the device over
     * @param objectID   The ID of the subject to delete
     * @param objectType The type of the object to delete
     * @throws InvalidSessionException            If no session is specified
     * @throws NoSuchAlgorithmException           If the message encryption/decryption fails
     * @throws YHDeviceException                  If the device returns an error
     * @throws YHInvalidResponseException         If the device returns a response that cannot be parsed
     * @throws YHConnectionException              If the connection to the device fails
     * @throws InvalidKeyException                If the message encryption/decryption fails
     * @throws YHAuthenticationException          If the session or message authentication fails
     * @throws NoSuchPaddingException             If the message encryption/decryption fails
     * @throws InvalidAlgorithmParameterException If the message encryption/decryption fails
     * @throws BadPaddingException                If the message encryption/decryption fails
     * @throws IllegalBlockSizeException          If the message encryption/decryption fails
     */
    public static void deleteObject(final YHSession session, final short objectID, final ObjectType objectType)
            throws InvalidSessionException, NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException,
                   InvalidKeyException, YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException {
        if (session == null) {
            throw new InvalidSessionException();
        }
        Utils.checkNullValue(objectType, "Object type is necessary to identify the object to delete");

        logger.finer("Deleting " + objectType.getName() + " " + String.format("0x%02X", objectID));

        ByteBuffer bb = ByteBuffer.allocate(3);
        bb.putShort(objectID);
        bb.put(objectType.getTypeId());
        session.sendSecureCmd(Command.DELETE_OBJECT, bb.array());
    }

    /**
     * Retrieves details of a specific object in the device
     *
     * @param session    An authenticated session to communicate with the device over
     * @param objectID   The ID of the subject to delete
     * @param objectType The type of the object to delete
     * @throws InvalidSessionException            If no session is specified
     * @throws NoSuchAlgorithmException           If the message encryption/decryption fails
     * @throws YHDeviceException                  If the device returns an error
     * @throws YHInvalidResponseException         If the device returns a response that cannot be parsed
     * @throws YHConnectionException              If the connection to the device fails
     * @throws InvalidKeyException                If the message encryption/decryption fails
     * @throws YHAuthenticationException          If the session or message authentication fails
     * @throws NoSuchPaddingException             If the message encryption/decryption fails
     * @throws InvalidAlgorithmParameterException If the message encryption/decryption fails
     * @throws BadPaddingException                If the message encryption/decryption fails
     * @throws IllegalBlockSizeException          If the message encryption/decryption fails
     * @throws IllegalBlockSizeException
     */
    public static YHObject getObjectInfo(final YHSession session, final short objectID, final ObjectType objectType)
            throws InvalidSessionException, NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException,
                   InvalidKeyException, YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException {
        if (session == null) {
            throw new InvalidSessionException();
        }
        Utils.checkNullValue(objectType, "Object type is necessary to identify the object");

        logger.finer("Getting object info for " + objectType.getName() + " " + String.format("0x%02X", objectID));

        ByteBuffer bb = ByteBuffer.allocate(3);
        bb.putShort(objectID);
        bb.put(objectType.getTypeId());
        byte[] response = session.sendSecureCmd(Command.GET_OBJECT_INFO, bb.array());
        YHObject info = new YHObject(response);

        logger.finer("Response to " + Command.GET_OBJECT_INFO.getName() + " returned:");
        logger.finer(info.toString());

        return info;
    }

}
