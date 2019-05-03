package com.yubico.objects;

/**
 * Class representing the Decrypted Yubico OTP data
 */
public class YubicoOtpData {

    private short sessionCounter;
    private byte usageCounter;
    private byte timestampHigh;
    private short timestampLow;

    public YubicoOtpData(final short sessionCtr, final byte usageCtr, final byte tmstmpHi, final short tmstmpLow) {
        sessionCounter = sessionCtr;
        usageCounter = usageCtr;
        timestampHigh = tmstmpHi;
        timestampLow = tmstmpLow;
    }

    public short getSessionCounter() {
        return sessionCounter;
    }

    public byte getUsageCounter() {
        return usageCounter;
    }

    public byte getTimestampHigh() {
        return timestampHigh;
    }

    public short getTimestampLow() {
        return timestampLow;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Session counter: ").append(sessionCounter).append("\n");
        sb.append("Usage counter: ").append(usageCounter).append("\n");
        sb.append("Timestamp high: ").append(timestampHigh).append("\n");
        sb.append("Timestamp low: ").append(timestampLow).append("\n");
        return sb.toString();
    }

    public boolean equals(Object other) {
        if (other == null || !(other instanceof YubicoOtpData)) {
            return false;
        }

        YubicoOtpData otherOtpData = (YubicoOtpData) other;
        return getSessionCounter() == otherOtpData.getSessionCounter() && getUsageCounter() == otherOtpData.getUsageCounter() &&
               getTimestampHigh() == otherOtpData.getTimestampHigh() && getTimestampLow() == otherOtpData.getTimestampLow();
    }

}
