package com.yubico.objects.yhobjects;

import com.yubico.YHSession;
import com.yubico.exceptions.*;
import com.yubico.internal.util.Utils;
import com.yubico.objects.yhconcepts.Capability;
import com.yubico.objects.yhconcepts.Command;
import com.yubico.objects.yhconcepts.ObjectType;
import com.yubico.objects.yhconcepts.YHConcept;
import lombok.NonNull;

import javax.annotation.Nonnull;
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

public class YHObject {
    private static Logger log = Logger.getLogger(YHObject.class.getName());

    public static final int OBJECT_ID_SIZE = 2;
    public static final int OBJECT_TYPE_SIZE = 1;
    public static final int OBJECT_LABEL_SIZE = 40;
    public static final int OBJECT_DOMAINS_SIZE = 2;
    public static final int OBJECT_ALGORITHM_SIZE = 1;
    public static final int OBJECT_CAPABILITIES_SIZE = 8;
    public static final int OBJECT_DELEGATED_CAPABILITIES_SIZE = 8;


    private short id;
    private ObjectType type;

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

    protected YHObject() {}

    public YHObject(final short id, @NonNull final ObjectType type) {
        this.id = id;
        this.type = type;
    }

    public short getId() {
        return id;
    }

    protected void setId(short id) {
        this.id = id;
    }

    public ObjectType getType() {
        return type;
    }

    protected void setType(@NonNull ObjectType type) {
        this.type = type;
    }

    /**
     * Compares two YHObject objects
     *
     * @param other
     * @return True if the objects' IDs and types are equal. False otherwise
     */
    public boolean equals(@NonNull final YHObject other) {
        return (getId() == other.getId()) && YHConcept.equals(getType(), other.getType());
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
    public static List<YHObjectInfo> getObjectList(@NonNull final YHSession session, final Map<ListFilter, Object> filters)
            throws IOException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   NoSuchPaddingException, IllegalBlockSizeException {
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
                log.severe("Failed to construct input message to the " + Command.LIST_OBJECTS.getName() + " command");
                throw e;
            }
        }

        byte[] cmdMessage = baos.toByteArray();
        byte[] response = session.sendSecureCmd(Command.LIST_OBJECTS, cmdMessage);
        if (response.length % 4 != 0) {
            log.finer(Command.LIST_OBJECTS.getName() + " response: " + Utils.getPrintableBytes(response));
            throw new YHInvalidResponseException("Expecting length of response to " + Command.LIST_OBJECTS.getName() + " command to be a multiple " +
                                                 "of 4 but have received " + response.length + " bytes instead");
        }
        ByteBuffer bb = ByteBuffer.wrap(response);
        List<YHObjectInfo> ret = new ArrayList<>();
        while (bb.hasRemaining()) {
            ret.add(new YHObjectInfo(bb.getShort(), ObjectType.getObjectType(bb.get()), bb.get()));
        }
        log.fine("Response to " + Command.LIST_OBJECTS.getName() + " command contained " + ret.size() + " objects");
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
     * @param session    An authenticated session to communicate with the device over
     * @param objectID   The ID of the subject to delete
     * @param objectType The type of the object to delete
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
    public static void delete(@NonNull final YHSession session, final short objectID, @NonNull final ObjectType objectType)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException,
                   InvalidKeyException, YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException {

        log.finer("Deleting " + objectType.getName() + " " + String.format("0x%02X", objectID));

        ByteBuffer bb = ByteBuffer.allocate(3);
        bb.putShort(objectID);
        bb.put(objectType.getTypeId());
        session.sendSecureCmd(Command.DELETE_OBJECT, bb.array());
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
     * @param session    An authenticated session to communicate with the device over
     * @param objectID   The ID of the object to delete
     * @param objectType The type of the object to delete
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
    public static YHObjectInfo getObjectInfo(@NonNull final YHSession session, final short objectID, @NonNull final ObjectType objectType)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException,
                   InvalidKeyException, YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException {

        log.finer("Getting object info for " + objectType.getName() + " " + String.format("0x%02X", objectID));

        ByteBuffer bb = ByteBuffer.allocate(3);
        bb.putShort(objectID);
        bb.put(objectType.getTypeId());
        byte[] response = session.sendSecureCmd(Command.GET_OBJECT_INFO, bb.array());
        YHObjectInfo info = new YHObjectInfo(response);

        log.info("Returned metadata for " + objectType.getName() + " with ID 0x" + Integer.toHexString(objectID));

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
     * @param session    An authenticated session to communicate with the device over
     * @param objectID   The ID of the subject to check
     * @param objectType The type of the object to check
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
    public static boolean exists(@Nonnull final YHSession session, final short objectID, @NonNull final ObjectType objectType)
            throws NoSuchAlgorithmException, YHDeviceException, YHInvalidResponseException, YHConnectionException,
                   InvalidKeyException, YHAuthenticationException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
                   IllegalBlockSizeException {
        try {
            YHObject.getObjectInfo(session, objectID, objectType);
        } catch (YHDeviceException e) {
            if(YHError.OBJECT_NOT_FOUND.equals(e.getYhError())) {
                return false;
            } else {
                throw e;
            }
        }
        return true;
    }
}
