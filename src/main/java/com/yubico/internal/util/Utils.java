package com.yubico.internal.util;

import java.security.InvalidParameterException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

public class Utils {

    static Logger logger = Logger.getLogger(Utils.class.getName());

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
     * Adds the necessary number of bytes so that `ba`'s length will be a multiple of 16. The first of these extra bytes will be 0x80 and the rest
     * are 0x00
     *
     * @param ba
     * @return An array whose length is a multiple of 16
     */
    public static byte[] addPadding(final byte[] ba, final int blockSize) {
        int padLength = blockSize - (ba.length % blockSize);
        byte[] ret = Arrays.copyOf(ba, ba.length + padLength);
        ret[ba.length] = (byte) 0x80;
        return ret;
    }

    /**
     * Removes 0 to 15 bytes whose value is 0x00 and 1 byte whose value is 0x80 from the end of the input byte array
     *
     * @param ba
     * @return `ba` without the trailing 0x80 0x00 ... 0x00 bytes
     */
    public static byte[] removePadding(final byte[] ba, final int blockSize) {
        if (ba.length % blockSize != 0) {
            logger.fine("Byte array was not padded. Doing nothing");
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
     * Converts a list of integers into a short value. Mostly used to represent an object's domains
     *
     * @param values A list of integers
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
     * Converts a short value into a list of integers. Mostly used to represent an object's domains
     *
     * @param value A short value
     * @return The short value as a list of integers
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
     * Throws an InvalidParameterException with the specified error message if `value` is null
     *
     * @param value        The value to check whether it is null
     * @param errorMessage The error message to include in the InvalidParameterException
     */
    public static void checkNullValue(final Object value, final String errorMessage) {
        if (value == null) {
            throw new InvalidParameterException(errorMessage);
        }
    }
}
