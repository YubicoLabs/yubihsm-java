/*
 * Copyright 2019 Yubico AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.yubico.hsm.internal.util;

import com.yubico.hsm.exceptions.YHDeviceException;
import com.yubico.hsm.exceptions.YHInvalidResponseException;
import com.yubico.hsm.yhconcepts.Command;
import com.yubico.hsm.yhconcepts.YHError;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.nio.ByteBuffer;
import java.util.Arrays;

@Slf4j
public class CommandUtils {

    public static final int COMMAND_ID_SIZE = 1;
    public static final int COMMAND_INPUT_LENGTH_SIZE = 2;

    private static final int RESPONSE_CODE_INDEX = 0;
    private static final int RESPONSE_LENGTH_INDEX = 1;
    private static final int RESPONSE_DATA_INDEX = 3;
    private static final int ERROR_RESPONSE_LENGTH = 4;
    private static final byte[] ERROR_RESPONSE_START = {Command.ERROR.getId(), (byte) 0, (byte) 1};

    /**
     * Add the command code and the length of the data in front of the data
     *
     * @param cmd  The command to be padded
     * @param data The input to the command
     * @return A byte array in the form: [command code (1 byte), length of data (2 bytes), data]
     */
    public static byte[] getFullCommandMessage(@NonNull final Command cmd, final byte[] data) {
        final int dl = data != null ? data.length : 0;
        ByteBuffer ret = ByteBuffer.allocate(COMMAND_ID_SIZE + COMMAND_INPUT_LENGTH_SIZE + dl);
        ret.put(cmd.getId());
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
    public static byte[] getResponseData(@NonNull final Command cmd, @NonNull final byte[] response)
            throws YHDeviceException, YHInvalidResponseException {
        byte respCode = getResponseCode(response);
        if (respCode == cmd.getCommandResponse()) {
            log.debug("Received response from device for " + cmd.getName());
        } else {
            final YHError error = getResponseErrorCode(response);
            if (error != null) {
                log.error("Device returned error code: " + error.toString());
                throw new YHDeviceException(error);
            } else {
                final String err = "Unrecognized response: " + Utils.getPrintableBytes(response);
                log.error(err);
                throw new YHInvalidResponseException(err);
            }
        }

        int expectedDataLength = getCommandResponseLength(response);
        int actualDataLength = response.length - COMMAND_ID_SIZE - COMMAND_INPUT_LENGTH_SIZE;
        if (actualDataLength != expectedDataLength) {
            final String err =
                    "Unexpected length of response from device. According to device response, the command response should be " +
                    expectedDataLength + " bytes long, but the actual received data was " + actualDataLength;
            log.error(err);
            throw new YHInvalidResponseException(err);
        }

        byte[] ret = new byte[0];
        if (actualDataLength > 0) {
            ret = Arrays.copyOfRange(response, RESPONSE_DATA_INDEX, response.length);
        }
        return ret;
    }

    /**
     * Returns whether data is actually an error message as defined by the YubiHSM.
     *
     * @param deviceResponse
     * @return True if the first 3 bytes of the device response are: 0x7f 0x00 0x01 (The fourth byte is the error code). False otherwise
     */
    public static boolean isErrorResponse(final byte[] deviceResponse) {
        if (deviceResponse == null || deviceResponse.length != ERROR_RESPONSE_LENGTH) {
            return false;
        }
        for (int i = 0; i < ERROR_RESPONSE_START.length; i++) {
            if (deviceResponse[i] != ERROR_RESPONSE_START[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * @param deviceResponse
     * @return The error code contained in `deviceResponse` if there is one. Null otherwise
     */
    public static YHError getResponseErrorCode(final byte[] deviceResponse) {
        YHError ret = null;
        if (isErrorResponse(deviceResponse)) {
            ret = YHError.forId(deviceResponse[RESPONSE_DATA_INDEX]);
        }
        return ret;
    }

    /**
     * @param deviceResponse
     * @return The first byte of `deviceResponse` (where the response code is expected to be)
     */
    public static byte getResponseCode(@NonNull final byte[] deviceResponse) {
        if (deviceResponse.length == 0) {
            throw new IllegalArgumentException("Device response did not contain any data");
        }
        return deviceResponse[RESPONSE_CODE_INDEX];
    }

    /**
     * Returns the length of the data contained in `deviceResponse`
     *
     * @param deviceResponse
     * @return The length of the data is stated in the second and third byte of `deviceResponse`
     */
    public static int getCommandResponseLength(@NonNull final byte[] deviceResponse) {
        int shortSize = Short.SIZE / 8; // the size of a short object in bytes
        if (deviceResponse.length < RESPONSE_LENGTH_INDEX + shortSize) {
            throw new IllegalArgumentException("Device response is too short to contain the length data at index " + RESPONSE_LENGTH_INDEX);
        }
        return (deviceResponse[RESPONSE_LENGTH_INDEX + 1] & 0xFF) | ((deviceResponse[RESPONSE_LENGTH_INDEX] & 0xFF) << 8);
    }

    /**
     * @param cmd
     * @param responseLength
     * @param expectedLength
     * @throws YHInvalidResponseException If the the response length does not match the expected length
     */
    public static void verifyResponseLength(@NonNull final Command cmd, final int responseLength, final int expectedLength)
            throws YHInvalidResponseException {
        if (responseLength != expectedLength) {
            throw new YHInvalidResponseException(
                    "Response to " + cmd.getName() + " command expected to contains " + expectedLength + " bytes, but was " +
                    responseLength + " bytes instead");
        }
    }
}
