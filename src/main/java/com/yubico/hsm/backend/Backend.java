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
