package com.yubico.hsm.internal.util;

import com.yubico.hsm.yhconcepts.Capability;
import com.yubico.hsm.yhconcepts.Command;
import com.yubico.hsm.yhconcepts.DeviceOptionValue;
import com.yubico.hsm.yhobjects.YHObject;
import lombok.NonNull;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidParameterException;
import java.util.*;
import java.util.logging.Logger;

public class Utils {
    static Logger log = Logger.getLogger(Utils.class.getName());

    /**
     * Returns a String representation of a byte array. Each individual byte is represented in hexadecimal format and every 8 bytes are grouped
     * together
     *
     * @param ba The byte array to convert
     * @return `ba` as a String
     */
    public static String getPrintableBytes(final byte[] ba) {
        StringBuilder sb = new StringBuilder("");
        if (ba != null) {
            for (int i = 0; i < ba.length; i++) {
                if (i % 8 == 0) {
                    sb.append(" ");
                }
                sb.append(String.format("%02x", ba[i]));
            }
        }
        return sb.toString();
    }

    /**
     * Adds the necessary number of bytes so that `ba`'s length will be a multiple of the specified block size. The first of these extra bytes will
     * be 0x80 and the rest are 0x00
     *
     * @param ba        The unpadded byte array
     * @param blockSize The number that the resulting array length should be a multiple of
     * @return `ba` with padding
     */
    public static byte[] addPadding(final @NonNull byte[] ba, final int blockSize) {
        int padLength = blockSize - (ba.length % blockSize);
        byte[] ret = Arrays.copyOf(ba, ba.length + padLength);
        ret[ba.length] = (byte) 0x80;
        return ret;
    }

    /**
     * Removes the padding that was added to make `ba`'s length a multiple of the specified block size
     *
     * @param ba        The padded array
     * @param blockSize The number that the resulting array length should be a multiple of
     * @return `ba` without the padding
     */
    public static byte[] removePadding(@NonNull final byte[] ba, final int blockSize) {
        if (ba.length % blockSize != 0) {
            log.fine("Byte array was not padded. Doing nothing");
            return ba;
        }
        int index = ba.length - 1;
        while (ba[index] == 0) {
            index--;
        }
        if (ba[index] != (byte) 0x80) {
            // input has no padding
            return ba;
        }

        return Arrays.copyOf(ba, index);
    }

    /**
     * Converts a list of integers into a short value (2 bytes). Each integer sets the corresponding bit in the returned short value into '1'. This
     * is mostly used to represent an object's domains, which is a 16-bit value representing 16 domains.
     *
     * @param values A list of integers from 1 to 16
     * @return A short value representing the list of integers
     */
    public static short getShortFromList(final List<Integer> values) {
        int ret = 0;
        if (values != null) {
            for (int i : values) {
                int v = 1 << (i - 1);
                ret = ret | v;
            }
        }
        return (short) ret;
    }

    /**
     * Converts a short value (2 bytes) into a list of integers. Each bit in `value` set to '1' is converted into an integer representing its index
     * in the `value`. This is mostly used to represent an object's domains, which is a 16-bit value representing 16 domains
     *
     * @param value
     * @return The list of integers from 1 to 16
     */
    public static List<Integer> getListFromShort(final short value) {
        List<Integer> ret = new ArrayList();
        for (int i = 0; i < 16; i++) {
            int v = 1 << i;
            if ((value & v) == v) {
                ret.add(i + 1);
            }
        }
        return ret;
    }

    /**
     * Converts a list of capabilities into a long object
     *
     * @param capabilities A list of capabilities
     * @return `capabilities` as a 64 bit long object
     */
    public static long getLongFromCapabilities(final List<Capability> capabilities) {
        long ret = 0L;
        if (capabilities != null) {
            for (Capability c : capabilities) {
                ret = ret | c.getId();
            }
        }
        return ret;
    }

    /**
     * Converts a 64 bit long object into a list of capabilities
     *
     * @param capabilities Capabilities as a long object
     * @return `capabilities` as a List of Capability
     */
    public static List<Capability> getCapabilitiesFromLong(final long capabilities) {
        List<Capability> ret = new ArrayList();
        long c = 1L;
        while (c <= capabilities) {
            if ((capabilities & c) == c) {
                ret.add(Capability.forId(c));
            }
            c = c << 1;
        }
        return ret;

    }

    /**
     * Throws an IllegalArgumentException with a specific error message if `ba` is null or empty
     *
     * @param ba           The byte array to check
     * @param errorMessage The error message to include in the InvalidParameterException
     */
    public static void checkEmptyByteArray(@NonNull final byte[] ba, final String errorMessage) {
        if (ba.length == 0) {
            throw new IllegalArgumentException(errorMessage);
        }
    }

    /**
     * Throws an IllegalArgumentException with a specific error message if `l` is null or empty
     *
     * @param l            The list to check
     * @param errorMessage The error message to include in the InvalidParameterException
     */
    public static void checkEmptyList(@NonNull final List l, final String errorMessage) {
        if (l.isEmpty()) {
            throw new IllegalArgumentException(errorMessage);
        }
    }

    /**
     * Returns a usable non-null label value and verifies its length.
     *
     * @param label
     * @return The label. An empty string if the input label is null
     * @throws InvalidParameterException If the label is more than the maximum length allowed
     */
    public static String getLabel(String label) {
        if (label == null) {
            return "";
        }
        if (label.length() > YHObject.OBJECT_LABEL_SIZE) {
            throw new IllegalArgumentException("Label is too long");
        }
        return label;
    }

    /**
     * Converts a map containing Command-OptionValue pairs into byte array
     *
     * @param commandOptionValueMap
     * @return Byte array where each pair in the map is represented as 2 bytes: commandID byte and OptionValue value byte, in that order
     */
    public static byte[] geOptionTlvValue(@NonNull Map<Command, DeviceOptionValue> commandOptionValueMap) {
        ByteBuffer bb = ByteBuffer.allocate(commandOptionValueMap.size() * 2);
        for (Command c : commandOptionValueMap.keySet()) {
            if (c != null) {
                bb.put(c.getId()).put(commandOptionValueMap.get(c).getValue());
            }
        }
        return bb.array();
    }

    /**
     * Converts a byte array into a map containing Command-OptionValue pairs.
     * <p>
     * The byte array is expected to contain an even number of bytes, where each bytes represent a commandID byte and an OptionValue value byte, in
     * that order
     *
     * @param commandOptionValue
     * @return A map containing Command-OptionValue pairs
     */
    public static Map<Command, DeviceOptionValue> geOptionTlvValue(@NonNull byte[] commandOptionValue) {
        Map<Command, DeviceOptionValue> ret = new HashMap<Command, DeviceOptionValue>();
        for (int i = 0; i < commandOptionValue.length; i += 2) {
            Command command = Command.forId(commandOptionValue[i]);
            if (command != null) {
                ret.put(command, DeviceOptionValue.forValue(commandOptionValue[i + 1]));
            }
        }
        return ret;
    }

    /**
     * Returns the bytes of a BigInteger.
     * <p>
     * The toByteArray() method in BigInteger class returns the two's complement representation of the BigInteger object + one sign byte. Since we
     * do not care about negative values, this method will remove the sign byte from resulting byte array if it is longer than the expected length.
     * If, however, toByteArray() returns a byte array shorter than what is expected, this method will add a 0 byte as the element in the least
     * significant byte
     *
     * @param bi
     * @param length Expected length of the resulting byte array
     * @return The BigInteger object represented as a byte array without the sign byte
     */
    public static byte[] getUnsignedByteArrayFromBigInteger(BigInteger bi, int length) {
        byte[] ba = bi.toByteArray();
        if (ba.length > length) {
            if (ba[0] == 0) {
                ba = Arrays.copyOfRange(ba, 1, ba.length);
            }
        } else if (ba.length < length) {
            ByteBuffer bb = ByteBuffer.allocate(ba.length + 1);
            bb.put((byte) 0x00);
            bb.put(ba);
            ba = bb.array();
        }
        return ba;
    }

}
