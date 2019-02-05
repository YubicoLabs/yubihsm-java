package com.yubico.backend;

import com.yubico.exceptions.YubiHsmConnectionException;

public interface Backend {

    /**
     * Sends a raw message to the device and returns a response
     *
     * @param message The data to send to the device
     * @return The device response
     * @throws YubiHsmConnectionException If connection with the device fails
     */
    public byte[] transceive(byte[] message) throws YubiHsmConnectionException;

    /**
     * Closes the connection with the device
     */
    public void close();
}
