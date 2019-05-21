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

import com.yubico.hsm.internal.util.Utils;
import lombok.NonNull;

import java.util.Arrays;

public class WrapData {

    public static final int NONCE_LENGTH = 13;
    public static final int MAC_LENGTH = 16;

    /** 13 bytes nonce */
    private byte[] nonce;
    private byte[] wrappedData;
    /** 16 bytes MAC value */
    private byte[] mac;

    public WrapData(@NonNull final byte[] nonce, @NonNull final byte[] wrappedData, @NonNull final byte[] mac) {
        if (nonce.length != NONCE_LENGTH) {
            throw new IllegalArgumentException("Nonce must be " + NONCE_LENGTH + " bytes long");
        }
        if (mac.length != MAC_LENGTH) {
            throw new IllegalArgumentException("Mac must be " + MAC_LENGTH + " bytes long");
        }
        this.nonce = nonce;
        this.wrappedData = wrappedData;
        this.mac = mac;
    }

    public WrapData(@NonNull final byte[] nonce, @NonNull final byte[] wrappedData) {
        if (nonce.length != NONCE_LENGTH) {
            throw new IllegalArgumentException("Nonce must be " + NONCE_LENGTH + " bytes long");
        }
        this.nonce = nonce;
        this.wrappedData = wrappedData;
        this.mac = null;
    }

    public WrapData(@NonNull final byte[] rawWrappedData, final boolean includeMac) {
        final int minLen = NONCE_LENGTH + (includeMac ? MAC_LENGTH : 0);

        if (rawWrappedData.length < minLen) {
            throw new IllegalArgumentException(
                    "The raw wrapped data is too short. Expected to be at least " + minLen + " bytes, but was " + rawWrappedData.length + " bytes");
        }
        nonce = Arrays.copyOfRange(rawWrappedData, 0, NONCE_LENGTH);
        if (includeMac) {
            wrappedData = Arrays.copyOfRange(rawWrappedData, NONCE_LENGTH, rawWrappedData.length - MAC_LENGTH);
            mac = Arrays.copyOfRange(rawWrappedData, rawWrappedData.length - MAC_LENGTH, rawWrappedData.length);
        } else {
            wrappedData = Arrays.copyOfRange(rawWrappedData, NONCE_LENGTH, rawWrappedData.length);
            mac = null;
        }
    }

    public byte[] getNonce() {
        return nonce;
    }

    public byte[] getWrappedData() {
        return wrappedData;
    }

    public byte[] getMac() {
        return mac;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(Utils.getPrintableBytes(nonce)).append(" - ");
        sb.append(Utils.getPrintableBytes(wrappedData)).append(" - ");
        sb.append(mac == null ? "0" : Utils.getPrintableBytes(mac));
        return sb.toString();
    }
}
