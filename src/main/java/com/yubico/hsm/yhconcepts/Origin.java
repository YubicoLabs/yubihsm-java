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
