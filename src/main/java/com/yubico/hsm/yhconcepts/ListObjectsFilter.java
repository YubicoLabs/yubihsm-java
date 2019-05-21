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

public enum ListObjectsFilter {
    ID          ((byte) 0x01, 3), // 1 identifier byte + 2 bytes OBJECT_ID_SIZE
    TYPE        ((byte) 0x02, 2), // 1 identifier byte + 1 byte OBJECT_TYPE_SIZE
    DOMAINS     ((byte) 0x03, 3), // 1 identifier byte + 2 bytes OBJECT_DOMAINS_SIZE
    CAPABILITIES((byte) 0x04, 9), // 1 identifier byte + 8 bytes OBJECT_CAPABILITIES_SIZE
    ALGORITHM   ((byte) 0x05, 2), // 1 identifier byte + 1 byts OBJECT_ALGORITHM_SIZE
    LABEL       ((byte) 0x06, 41); // 1 identifier byte + 40 bytes OBJECT_LABEL_SIZE

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

    @Override
    public String toString() {
        return String.format("0x%02x:%d", id, length);
    }
}
