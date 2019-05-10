package com.yubico.hsm.yhconcepts;

import java.util.LinkedHashMap;
import java.util.Map;

public enum ListObjectsFilter {
    ID((byte) 0x01, 3), // 1 identifier byte + 2 bytes OBJECT_ID_SIZE
    TYPE((byte) 0x02, 2), // 1 identifier byte + 1 byte OBJECT_TYPE_SIZE
    DOMAINS((byte) 0x03, 3), // 1 identifier byte + 2 bytes OBJECT_DOMAINS_SIZE
    CAPABILITIES((byte) 0x04, 9), // 1 identifier byte + 8 bytes OBJECT_CAPABILITIES_SIZE
    ALGORITHM((byte) 0x05, 2), // 1 identifier byte + 1 byts OBJECT_ALGORITHM_SIZE
    LABEL((byte) 0x06, 41); // 1 identifier byte + 40 bytes OBJECT_LABEL_SIZE

    private final byte id;
    private final int length;

    ListObjectsFilter(byte id, int length) {
        this.id = id;
        this.length = length;
    }

    public byte getId() {
        return id;
    }

    public int getLength() {
        return this.length;
    }

    private static final Map<Byte, ListObjectsFilter> BY_VALUE_MAP = new LinkedHashMap<Byte, ListObjectsFilter>();

    static {
        for (ListObjectsFilter filter : ListObjectsFilter.values()) {
            BY_VALUE_MAP.put(filter.getId(), filter);
        }
    }

    public static ListObjectsFilter forId(byte id) {
        return BY_VALUE_MAP.get(id);
    }
}
