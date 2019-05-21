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

import java.util.Objects;

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

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Session counter: ").append(sessionCounter).append("\n");
        sb.append("Usage counter: ").append(usageCounter).append("\n");
        sb.append("Timestamp high: ").append(timestampHigh).append("\n");
        sb.append("Timestamp low: ").append(timestampLow).append("\n");
        return sb.toString();
    }

    @Override
    public boolean equals(final Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof YubicoOtpData)) {
            return false;
        }
        YubicoOtpData otherOtpData = (YubicoOtpData) other;
        return getSessionCounter() == otherOtpData.getSessionCounter() && getUsageCounter() == otherOtpData.getUsageCounter() &&
               getTimestampHigh() == otherOtpData.getTimestampHigh() && getTimestampLow() == otherOtpData.getTimestampLow();
    }

    @Override
    public int hashCode() {
        Object[] fields = {sessionCounter, usageCounter, timestampHigh, timestampLow};
        return Objects.hash(fields);
    }
}
