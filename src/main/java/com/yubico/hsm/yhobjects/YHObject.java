package com.yubico.hsm.yhobjects;

import com.yubico.hsm.YHSession;
import com.yubico.hsm.exceptions.YHAuthenticationException;
import com.yubico.hsm.exceptions.YHConnectionException;
import com.yubico.hsm.exceptions.YHDeviceException;
import com.yubico.hsm.exceptions.YHInvalidResponseException;
import com.yubico.hsm.internal.util.CommandUtils;
import com.yubico.hsm.internal.util.Utils;
import com.yubico.hsm.yhconcepts.*;
import com.yubico.hsm.yhdata.YHObjectInfo;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

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
import java.util.Objects;

@Slf4j
public class YHObject {

    public static final int OBJECT_ID_SIZE = 2;
    public static final int OBJECT_TYPE_SIZE = 1;
    public static final int OBJECT_LABEL_SIZE = 40;
    public static final int OBJECT_DOMAINS_SIZE = 2;
    public static final int OBJECT_ALGORITHM_SIZE = 1;
    public static final int OBJECT_CAPABILITIES_SIZE = 8;
    public static final int OBJECT_DELEGATED_CAPABILITIES_SIZE = 8;
    public static final int OBJECT_SEQUENCE_SIZE = 1;

    protected final int HASH_LENGTH_FOR_SHA1 = 20;
    protected final int HASH_LENGTH_FOR_SHA256 = 32;
    protected final int HASH_LENGTH_FOR_SHA384 = 48;
    protected final int HASH_LENGTH_FOR_SHA512 = 64;

    protected static final int KEY_LENGTH_FOR_AES128 = 16;
    protected static final int KEY_LENGTH_FOR_AES192 = 24;
    protected static final int KEY_LENGTH_FOR_AES256 = 32;


    private short id;
    private Type type;

    protected YHObject() {}

    public YHObject(final short id, @NonNull final Type type) {
        this.id = id;
        this.type = type;
    }

    public short getId() {
        return id;
    }

    protected void setId(short id) {
        this.id = id;
    }

    public Type getType() {
        return type;
    }

    protected void setType(@NonNull Type type) {
        this.type = type;
    }

    @Override
    public String toString() {
        return String.format("0x%02x:%s", id, type.getName());
    }

    /**
     * Compares two YHObject objects
     *
     * @param other
     * @return True if the objects' IDs and types are equal. False otherwise
     */
    @Override
    public boolean equals(final Object other) {
        if(this == other) {
            return true;
        }
        if (!(other instanceof YHObject)) {
            return false;
        }
        YHObject otherObject = (YHObject) other;
        return getId() == otherObject.getId() && getType().equals(otherObject.getType());
    }

    @Override
    public int hashCode() {
        Object[] fields = {id, type};
        return Objects.hash(fields);
    }

    /**
     * Return a list of objects on the device. The return value can be filtered by object ID, type, domains, capabilities, algorithm and/or label
     *
     * @param session An authenticated session to communicate with the device over
     * @param filters The filter applied to the result
     * @return A list of objects on the device
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
     * @throws IOException                        If failed to parse the filter
     */
    public static List<YHObjectInfo> getObjectList(@NonNull final YHSession session, final Map<ListObjectsFilter, Object> filters)
            throws IOException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   NoSuchPaddingException, IllegalBlockSizeException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        if (filters != null) {
            try {
                ByteBuffer bb;
                for (ListObjectsFilter f : filters.keySet()) {
                    switch (f) {
                        case ID:
                            bb = ByteBuffer.allocate(ListObjectsFilter.ID.getLength());
                            bb.put(ListObjectsFilter.ID.getId()).putShort((short) filters.get(f));
                            baos.write(bb.array());
                            break;
                        case TYPE:
                            bb = ByteBuffer.allocate(ListObjectsFilter.TYPE.getLength());
                            bb.put(ListObjectsFilter.TYPE.getId());
                            Object type = filters.get(f);
                            if (type instanceof Byte) {
                                bb.put((byte) type);
                            } else if (type instanceof Type) {
                                bb.put(((Type) type).getId());
                            }
                            baos.write(bb.array());
                            break;
                        case DOMAINS:
                            bb = ByteBuffer.allocate(ListObjectsFilter.DOMAINS.getLength());
                            bb.put(ListObjectsFilter.DOMAINS.getId());
                            Object domains = filters.get(f);
                            if (domains instanceof Short) {
                                bb.putShort((short) domains);
                            } else if (domains instanceof List) {
                                bb.putShort(Utils.getShortFromList((List<Integer>) domains));
                            }
                            baos.write(bb.array());
                            break;
                        case CAPABILITIES:
                            bb = ByteBuffer.allocate(ListObjectsFilter.CAPABILITIES.getLength());
                            bb.put(ListObjectsFilter.CAPABILITIES.getId());
                            Object capabilities = filters.get(f);
                            if (capabilities instanceof Long) {
                                bb.putLong(((long) capabilities));
                            } else if (capabilities instanceof List) {
                                bb.putLong(Utils.getLongFromCapabilities((List<Capability>) capabilities));
                            }
                            baos.write(bb.array());
                            break;
                        case ALGORITHM:
                            bb = ByteBuffer.allocate(ListObjectsFilter.ALGORITHM.getLength());
                            bb.put(ListObjectsFilter.ALGORITHM.getId()).put((byte) filters.get(f));
                            baos.write(bb.array());
                            break;
                        case LABEL:
                            final String label = (String) filters.get(f);
                            bb = ByteBuffer.allocate(ListObjectsFilter.LABEL.getLength());
                            bb.put(ListObjectsFilter.LABEL.getId()).put(label.getBytes());
                            baos.write(bb.array());
                            break;
                        default:
                            // do nothing
                            break;

                    }
                }
            } catch (IOException e) {
                log.error("Failed to construct input message to the " + Command.LIST_OBJECTS.getName() + " command");
                throw e;
            }
        }

        byte[] cmdMessage = baos.toByteArray();
        byte[] response = session.sendSecureCmd(Command.LIST_OBJECTS, cmdMessage);
        int itemSize = OBJECT_ID_SIZE + OBJECT_TYPE_SIZE + OBJECT_SEQUENCE_SIZE;
        if (response.length % itemSize != 0) {
            log.debug(Command.LIST_OBJECTS.getName() + " response: " + Utils.getPrintableBytes(response));
            throw new YHInvalidResponseException("Expecting length of response to " + Command.LIST_OBJECTS.getName() + " command to be a multiple " +
                                                 "of " + itemSize + " but have received " + response.length + " bytes instead");
        }
        ByteBuffer bb = ByteBuffer.wrap(response);
        List<YHObjectInfo> ret = new ArrayList<YHObjectInfo>();
        while (bb.hasRemaining()) {
            ret.add(new YHObjectInfo(bb.getShort(), Type.forId(bb.get()), bb.get()));
        }
        log.debug("Response to " + Command.LIST_OBJECTS.getName() + " command contained " + ret.size() + " objects");
        return ret;
    }

    /**
     * Deletes a this object from the device
     *
     * @param session An authenticated session to communicate with the device over
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
    public void delete(YHSession session)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException,
                   InvalidKeyException, YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException {
        delete(session, getId(), getType());
    }

    /**
     * Deletes a specific object from the device
     *
     * @param session  An authenticated session to communicate with the device over
     * @param objectID The ID of the subject to delete
     * @param type     The type of the object to delete
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
    public static void delete(@NonNull final YHSession session, final short objectID, @NonNull final Type type)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException,
                   InvalidKeyException, YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException {

        log.debug("Deleting " + type.getName() + " " + String.format("0x%02x", objectID));

        ByteBuffer bb = ByteBuffer.allocate(OBJECT_ID_SIZE + OBJECT_TYPE_SIZE);
        bb.putShort(objectID);
        bb.put(type.getId());
        try {
            byte[] resp = session.sendSecureCmd(Command.DELETE_OBJECT, bb.array());
            CommandUtils.verifyResponseLength(Command.DELETE_OBJECT, resp.length, 0);
        } catch (YHDeviceException e) {
            if (!YHError.OBJECT_NOT_FOUND.equals(e.getYhError())) {
                throw e;
            } else {
                log.info(type.getName() + " with ID " + String.format("0x%02x", objectID) + " does not exist. Doing nothing");
            }
        }
    }

    /**
     * Retrieves details of a this object from the device
     *
     * @param session An authenticated session to communicate with the device over
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
    public YHObjectInfo getObjectInfo(final YHSession session)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException,
                   InvalidKeyException, YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException {
        return getObjectInfo(session, getId(), getType());
    }

    /**
     * Retrieves details of a specific object in the device
     *
     * @param session  An authenticated session to communicate with the device over
     * @param objectID The ID of the object to delete
     * @param type     The type of the object to delete
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
    public static YHObjectInfo getObjectInfo(@NonNull final YHSession session, final short objectID, @NonNull final Type type)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException,
                   InvalidKeyException, YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException {

        log.debug("Getting object info for " + type.getName() + " " + String.format("0x%02X", objectID));

        ByteBuffer bb = ByteBuffer.allocate(OBJECT_ID_SIZE + OBJECT_TYPE_SIZE);
        bb.putShort(objectID);
        bb.put(type.getId());
        byte[] response = session.sendSecureCmd(Command.GET_OBJECT_INFO, bb.array());
        YHObjectInfo info = new YHObjectInfo(response);

        log.info("Returned metadata for " + type.getName() + " with ID 0x" + Integer.toHexString(objectID));

        return info;
    }

    /**
     * Checks whether this object exists in the YubiHSM or not
     *
     * @param session An authenticated session to communicate with the device over
     * @return True if there exist and object in the YubiHSM with the same ID and Type as this object. False otherwise
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
    public boolean exists(final YHSession session)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException,
                   InvalidKeyException, YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException {
        return exists(session, getId(), getType());
    }

    /**
     * Checks whether an object exists in the YubiHSM or not
     *
     * @param session  An authenticated session to communicate with the device over
     * @param objectID The ID of the subject to check
     * @param type     The type of the object to check
     * @return True if there exist and object in the YubiHSM with the same ID and Type. False otherwise
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
    public static boolean exists(@NonNull final YHSession session, final short objectID, @NonNull final Type type)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException,
                   InvalidKeyException, YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException {
        try {
            YHObject.getObjectInfo(session, objectID, type);
        } catch (YHDeviceException e) {
            if (YHError.OBJECT_NOT_FOUND.equals(e.getYhError())) {
                return false;
            } else {
                throw e;
            }
        }
        return true;
    }
}
