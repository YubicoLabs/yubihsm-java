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
package com.yubico.hsm.yhconcepts;

import java.util.LinkedHashMap;
import java.util.Map;

public enum DeviceOptionValue {
    OFF((byte) 0x00, "OFF", "Disabled"),
    ON ((byte) 0x01, "ON", "Enabled"),
    FIX((byte) 0x02, "FIX", "Enabled, not possible to turn off");

    private final byte value;
    private final String name;
    private final String description;

    DeviceOptionValue(byte value, String name, String description) {
        this.value = value;
        this.name = name;
        this.description = description;
    }

    public byte getValue() {
        return value;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    private static final Map<Byte, DeviceOptionValue> BY_VALUE_MAP = new LinkedHashMap<Byte, DeviceOptionValue>();

    static {
        for (DeviceOptionValue v : DeviceOptionValue.values()) {
            BY_VALUE_MAP.put(v.getValue(), v);
        }
    }

    public static DeviceOptionValue forValue(byte v) {
        return BY_VALUE_MAP.get(v);
    }

    @Override
    public String toString() {
        return String.format("0x%02x:%s:%s", value, name, description);
    }
}
