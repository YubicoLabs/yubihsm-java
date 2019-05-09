package com.yubico.hsm.backend;

import com.yubico.hsm.exceptions.YHConnectionException;

public interface Backend {

    /**
     * Sends a raw message to the device and returns a response
     *
     * @param message The data to send to the device (including the command)
     * @return The device response
     * @throws YHConnectionException If connection with the device fails
     */
    byte[] transceive(byte[] message) throws YHConnectionException;

    /**
     * Closes the connection with the device
     */
    void close();
}
