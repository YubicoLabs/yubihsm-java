package com.yubico.hsm.yhconcepts;

import java.util.LinkedHashMap;
import java.util.Map;

public enum DeviceOptionValue {
    OFF((byte) 0x00, "OFF", "Disabled"),
    ON((byte) 0x01, "ON", "Enabled"),
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
}
