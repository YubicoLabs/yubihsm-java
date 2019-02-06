package com.yubico.objects;

import java.nio.ByteBuffer;
import java.util.HashSet;
import java.util.Set;

/**
 * Class holding various information about the YubiHSM
 */
public class DeviceInfo {

    /**
     * The device version number in the form of major.minor.build
     */
    private String version;
    /**
     * The device serial number
     */
    private int serialnumber;
    /**
     * The device log store size expressed in number of log entries
     */
    private int logSize;
    /**
     * The number of log lines used
     */
    private int logUsed;
    /**
     * The list of algorithms supported by the device
     */
    private Set<Algorithm> supportedAlgorithms;

    public DeviceInfo() {
        init();
    }

    public DeviceInfo(final String version, final int serialnumber, final int logSize, final int logUsed, final Set<Algorithm> algorithms) {
        this.version = version;
        this.serialnumber = serialnumber;
        this.logSize = logSize;
        this.logUsed = logUsed;
        this.supportedAlgorithms = algorithms;
    }

    public DeviceInfo(final byte[] info) {
        if (info != null && info.length > 0) {
            ByteBuffer bb = ByteBuffer.wrap(info);
            version = bb.get() + "." + bb.get() + "." + bb.get();
            serialnumber = bb.getInt();
            logSize = bb.get();
            logUsed = bb.get();

            supportedAlgorithms = new HashSet<Algorithm>();
            while (bb.hasRemaining()) {
                supportedAlgorithms.add(Algorithm.getAlgorithm(bb.get()));
            }
        } else {
            init();
        }
    }

    private void init() {
        version = null;
        serialnumber = 0;
        logSize = 0;
        logUsed = 0;
        supportedAlgorithms = null;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public int getSerialnumber() {
        return serialnumber;
    }

    public void setSerialnumber(int serialnumber) {
        this.serialnumber = serialnumber;
    }

    public int getLogSize() {
        return logSize;
    }

    public void setLogSize(int logSize) {
        this.logSize = logSize;
    }

    public int getLogUsed() {
        return logUsed;
    }

    public void setLogUsed(int logUsed) {
        this.logUsed = logUsed;
    }

    public Set<Algorithm> getSupportedAlgorithms() {
        return supportedAlgorithms;
    }

    public void setSupportedAlgorithms(Set<Algorithm> supportedAlgorithms) {
        this.supportedAlgorithms = supportedAlgorithms;
    }

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
