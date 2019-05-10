package com.yubico.hsm;

import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.exceptions.YHConnectionException;
import com.yubico.hsm.exceptions.YHDeviceException;
import com.yubico.hsm.exceptions.YHInvalidResponseException;
import com.yubico.hsm.internal.util.CommandUtils;
import com.yubico.hsm.yhconcepts.Command;
import com.yubico.hsm.yhdata.DeviceInfo;

import java.util.logging.Logger;

/**
 * This class handles commands and command packages for communication with the device. It also implements basic YubiHSM commands
 */
public class YubiHsm {
    private Logger log = Logger.getLogger(YubiHsm.class.getName());

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
     * @param data The data that should be echoed by the device
     * @return The device response to the Echo command. Should be the same as `data`
     * @throws YHDeviceException          If the device return an error
     * @throws YHInvalidResponseException If the device returns a response that cannot be parsed
     * @throws YHConnectionException      If the connection to the device fails
     */
    public byte[] echo(final byte[] data) throws YHDeviceException, YHInvalidResponseException, YHConnectionException {
        return sendCmd(Command.ECHO, data);
    }

    /**
     * Retrieves the device info from the YubiHSM device
     *
     * @return The device info
     * @throws YHConnectionException      If the connection to the device fails
     * @throws YHInvalidResponseException If the device returns a response that cannot be parsed
     * @throws YHDeviceException          If the device returns an error
     */
    public DeviceInfo getDeviceInfo() throws YHConnectionException, YHInvalidResponseException, YHDeviceException {
        byte[] data = sendCmd(Command.DEVICE_INFO, new byte[0]);
        DeviceInfo info = new DeviceInfo(data);
        log.fine("Got device info: " + info.toString());
        return info;

    }

}
