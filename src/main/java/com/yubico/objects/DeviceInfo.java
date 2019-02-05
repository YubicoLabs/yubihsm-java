package com.yubico.objects;

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
            version = info[0] + "." + info[1] + "." + info[2];
            serialnumber = (info[6] & 0xFF) | ((info[5] & 0xFF) << 8) |
                           ((info[4] & 0xFF) << 16) | ((info[3] & 0xFF) << 24);
            logSize = info[7];
            logUsed = info[8];

            supportedAlgorithms = new HashSet<Algorithm>();
            for (int i = 9; i < info.length; i++) {
                supportedAlgorithms.add(Algorithm.getAlgorithm(info[i]));
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
