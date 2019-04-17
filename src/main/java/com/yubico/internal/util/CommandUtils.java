package com.yubico.internal.util;

import com.yubico.exceptions.YHDeviceException;
import com.yubico.exceptions.YHError;
import com.yubico.exceptions.YHInvalidResponseException;
import com.yubico.objects.yhconcepts.Command;

import java.nio.ByteBuffer;
import java.util.logging.Logger;

public class CommandUtils {

    private static Logger logger = Logger.getLogger(CommandUtils.class.getName());


    /**
     * Add the command code and the length of the data in front of the data
     *
     * @param cmd  The command to be padded
     * @param data The input to the command
     * @return A byte array in the form: [command code (1 byte), length of data (2 bytes), data]
     */
    public static byte[] getTransceiveMessage(final Command cmd, final byte[] data) {
        int dl = 0;
        if (data != null) {
            dl = data.length;
        }
        ByteBuffer ret = ByteBuffer.allocate(dl + 3);
        ret.put(cmd.getCommandId());
        ret.putShort((short) dl);
        if (dl > 0) {
            ret.put(data);
        }
        return ret.array();
    }

    /**
     * Removes the leading response code and the length of the response and returns only the response data.
     *
     * @param cmd      The command to which the response belongs
     * @param response The raw response received from the YubiHSM device (including leading meta data)
     * @return The stripped command response data (with leading metadata removed)
     * @throws YHDeviceException          If the response contains an error code
     * @throws YHInvalidResponseException If the response cannot be parsed
     */
    public static byte[] getResponseData(final Command cmd, final byte[] response)
            throws YHDeviceException, YHInvalidResponseException {
        byte respCode = response[0];
        if (respCode == cmd.getCommandResponse()) {
            logger.fine("Received response from device for " + cmd.getName());
        } else if (isErrorResponse(response)) {
            final YHError error = YHError.getError(response[3]);
            logger.severe("Device returned error code: " + error.toString());
            throw new YHDeviceException(error);
        } else {
            final String err = "Unrecognized response: " + Utils.getPrintableBytes(response);
            logger.severe(err);
            throw new YHInvalidResponseException(err);
        }

        int expectedDataLength = (response[2] & 0xFF) | ((response[1] & 0xFF) << 8);
        int dataLength = response.length - 3;
        if (dataLength != expectedDataLength) {
            final String err = "Unexpected length of response from device. Expected " + expectedDataLength + ", found " + dataLength;
            logger.severe(err);
            throw new YHInvalidResponseException(err);
        }

        if (dataLength > 0) {
            ByteBuffer res = ByteBuffer.allocate(dataLength);
            res.put(response, 3, dataLength);
            return res.array();
        }
        return new byte[0];
    }

    /**
     * Returns whether data is actually an error message as defined by the YubiHSM.
     * <p>
     * The data contains an error if it is 4 bytes long and the first 3 bytes are: 0x7f 0x00 0x01
     *
     * @param data The data to check
     * @return True if data contains an error code. False otherwise
     */
    public static boolean isErrorResponse(final byte[] data) {
        if (data.length != 4) {
            return false;
        }

        byte[] errResp = {Command.ERROR.getCommandId(), (byte) 0, (byte) 1};
        for (int i = 0; i < errResp.length; i++) {
            if (data[i] != errResp[i]) {
                return false;
            }
        }

        return true;
    }

}
