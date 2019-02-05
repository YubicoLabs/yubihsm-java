package com.yubico.util;

import java.nio.ByteBuffer;
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
     * Compares 2 bytes arrays byte for byte
     *
     * @param a
     * @param b
     * @return True if the content of the two byte arrays is equal. False otherwise
     */
    public static boolean isByteArrayEqual(final byte[] a, final byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Extracts a part of the input byte array
     *
     * @param ba     The full input array
     * @param offset Start index of the part to extract
     * @param length The number of bytes to extract
     * @return `length` bytes starting from index `offset` in a new byte array
     */
    public static byte[] getSubArray(final byte[] ba, final int offset, final int length) {
        ByteBuffer ret = ByteBuffer.allocate(length);
        ret.put(ba, offset, length);
        return ret.array();
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
        ByteBuffer res = ByteBuffer.allocate(ba.length + padLength);
        res.put(ba).put((byte) 0x80).put(new byte[padLength-1]);
        return res.array();
    }

    /**
     * Removes 0 to 15 bytes whose value is 0x00 and 1 byte whose value is 0x80 from the end of the input byte array
     *
     * @param ba
     * @return `ba` without the trailing 0x80 0x00 ... 0x00 bytes
     */
    public static byte[] removePadding(final byte[] ba) {
        if (ba.length % 16 != 0) {
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

        ByteBuffer unpadded = ByteBuffer.allocate(index);
        unpadded.put(ba, 0, index);
        return unpadded.array();
    }
}
