package com.yubico.objects;

import com.yubico.objects.yhconcepts.Algorithm;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * Class representing various information about the YubiHSM
 */
public class DeviceInfo {

    private final String version;
    private final int serialnumber;
    private final int logSize;
    private final int logUsed;
    private final List<Algorithm> supportedAlgorithms;

    public DeviceInfo() {
        version = null;
        serialnumber = 0;
        logSize = 0;
        logUsed = 0;
        supportedAlgorithms = null;
    }

    /**
     * @param version      The device version
     * @param serialnumber The device serialnumber
     * @param logSize      The number of log entries that can be stored on the device
     * @param logUsed      The number of log entries that are on the device
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
     * @param info
     */
    public DeviceInfo(final byte[] info) {
        ByteBuffer bb = ByteBuffer.wrap(info);
        version = bb.get() + "." + bb.get() + "." + bb.get();
        serialnumber = bb.getInt();
        logSize = bb.get();
        logUsed = bb.get();

        supportedAlgorithms = new ArrayList<Algorithm>();
        while (bb.hasRemaining()) {
            supportedAlgorithms.add(Algorithm.getAlgorithm(bb.get()));
        }
    }

    /**
     * @return The device version number in the form of major.minor.build
     */
    public String getVersion() {
        return version;
    }

    /**
     * @return The device serial number
     */
    public int getSerialnumber() {
        return serialnumber;
    }

    /**
     * @return The number of log entries that can be stored on the device
     */
    public int getLogSize() {
        return logSize;
    }

    /**
     * @return The number of log entries that are on the device
     */
    public int getLogUsed() {
        return logUsed;
    }

    /**
     * @return A list of algorithms supported by the device
     */
    public List<Algorithm> getSupportedAlgorithms() {
        return supportedAlgorithms;
    }

    /**
     * @return A String representation of the device information
     */
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
