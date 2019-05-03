package com.yubico.internal.util;

import com.yubico.objects.yhobjects.YHObject;
import lombok.NonNull;

import java.security.InvalidParameterException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
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
                sb.append(String.format("%02X", ba[i]).toLowerCase());
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

}
