package com.yubico.hsm.yhconcepts;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Class representing the origin of objects stored on the device, aka. where an object has been created originally
 */
public enum Origin {
    /** Object was originated on the YubiHSM */
    YH_ORIGIN_GENERATED       ((byte) 0x01, "generated"),
    /** Object was imported into the YubiHSM */
    YH_ORIGIN_IMPORTED        ((byte) 0x02, "imported"),
    /** Object was imported into the YubiHSM under wrap */
    YH_ORIGIN_IMPORTED_WRAPPED((byte) 0x10, "imported-under-wrap");

    private final byte id;
    private final String name;

    Origin(final byte id, final String name) {
        this.id = id;
        this.name = name;
    }

    public byte getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    private static final Map<Byte, Origin> BY_VALUE_MAP = new LinkedHashMap<Byte, Origin>();

    static {
        for (Origin origin : Origin.values()) {
            BY_VALUE_MAP.put(origin.getId(), origin);
        }
    }

    public static Origin forId(byte id) {
        return BY_VALUE_MAP.get(id);
    }

    @Override
    public String toString() {
        return String.format("0x%02x:%s", id, name);
    }
}
