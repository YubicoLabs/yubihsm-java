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
package com.yubico.hsm.yhdata;

import com.yubico.hsm.yhconcepts.Algorithm;
import lombok.NonNull;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * Class representing various information about the YubiHSM device
 */
public class DeviceInfo {

    private final String version;
    private final int serialnumber;
    private final int logSize;
    private final int logUsed;
    private final List<Algorithm> supportedAlgorithms;

    /**
     * @param version      The firmware version of the device
     * @param serialnumber The device serialnumber
     * @param logSize      The number of log entries that can be stored on the device
     * @param logUsed      The number of unread log entries that are on the device
     * @param algorithms   A list of algorithms supported by the device
     */
    public DeviceInfo(final String version, final int serialnumber, final int logSize, final int logUsed, final List<Algorithm> algorithms) {
        this.version = version;
        this.serialnumber = serialnumber;
        this.logSize = logSize;
        this.logUsed = logUsed;
        this.supportedAlgorithms = algorithms;
    }

    /**
     * Creates a DeviceInfo object by parsing a byte array
     *
     * @param info The device data as a byte array in the form of {1 byte major version number + 1 byte minor version number + 1 byte build version
     *             number + 4 bytes serial number + 1 bytes log size + 1 byte log unread log entries + 1 byte for each supported algorithms}
     */
    public DeviceInfo(@NonNull final byte[] info) {
        ByteBuffer bb = ByteBuffer.wrap(info);
        version = bb.get() + "." + bb.get() + "." + bb.get();
        serialnumber = bb.getInt();
        logSize = bb.get();
        logUsed = bb.get();

        supportedAlgorithms = new ArrayList<Algorithm>();
        while (bb.hasRemaining()) {
            supportedAlgorithms.add(Algorithm.forId(bb.get()));
        }
    }

    public String getVersion() {
        return version;
    }

    public int getSerialnumber() {
        return serialnumber;
    }

    public int getLogSize() {
        return logSize;
    }

    public int getLogUsed() {
        return logUsed;
    }

    public List<Algorithm> getSupportedAlgorithms() {
        return supportedAlgorithms;
    }

    @Override
    public String toString() {
        if (version == null && serialnumber == 0) {
            return "";
        }

        StringBuilder builder = new StringBuilder("");
        builder.append("   Device version: " + version + "\n");
        builder.append("   Device serial number: " + serialnumber + "\n");
        builder.append("   Log size: " + logSize + "\n");
        builder.append("   Unread logs: " + logUsed + "\n");
        builder.append("   Supported algorithms: \n");
        builder.append("        ");
        int i = 0;
        for (Algorithm algo : supportedAlgorithms) {
            i++;
            builder.append(algo.getName()).append(", ");
            if (i == 10) {
                builder.append("\n        ");
                i = 0;
            }

        }
        builder.append("\n");
        return builder.toString();
    }


}
