package com.yubico.hsm.yhconcepts;

import java.util.LinkedHashMap;
import java.util.Map;

public enum DeviceOption {
    FORCE_AUDIT  ((byte) 0x01, "Force audit"),
    COMMAND_AUDIT((byte) 0x03, "Command audit");

    private final byte tag;
    private final String description;

    DeviceOption(byte tag, String description) {
        this.tag = tag;
        this.description = description;
    }

    public byte getTag() {
        return tag;
    }

    public String getDescription() {
        return description;
    }

    private static final Map<Byte, DeviceOption> BY_VALUE_MAP = new LinkedHashMap<Byte, DeviceOption>();

    static {
        for (DeviceOption option : DeviceOption.values()) {
            BY_VALUE_MAP.put(option.getTag(), option);
        }
    }

    public static DeviceOption forTag(byte id) {
        return BY_VALUE_MAP.get(id);
    }

    @Override
    public String toString() {
        return String.format("0x%02x:%s", tag, description);
    }
}

