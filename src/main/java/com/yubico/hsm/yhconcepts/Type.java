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
 * Class representing the types of objects that can be stored on the device
 */
public enum Type {

    /** Object is an X509Certificate or raw data of any kind */
    TYPE_OPAQUE            ((byte) 0x01, "Opaque"),
    /** Object is an Authentication key used to establish an encrypted communication session with the YubiHSM */
    TYPE_AUTHENTICATION_KEY((byte) 0x2, "Authentication Key"),
    /** Object is an Asymmetric key of type RSA, EC or ED */
    TYPE_ASYMMETRIC_KEY    ((byte) 0x03, "Asymmetric Key"),
    /** Object is a Wrap key used to export and import sensitive data securely */
    TYPE_WRAP_KEY          ((byte) 0x04, "Wrap Key"),
    TYPE_HMAC_KEY          ((byte) 0x05, "HMAC Key"),
    TYPE_TEMPLATE          ((byte) 0x06, "Template"),
    TYPE_OTP_AEAD_KEY      ((byte) 0x07, "OTP AEAD Key");

    private final byte id;
    private final String name;

    Type(final byte id, final String name) {
        this.id = id;
        this.name = name;
    }

    public byte getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    private static final Map<Byte, Type> BY_VALUE_MAP = new LinkedHashMap<Byte, Type>();

    static {
        for (Type type : Type.values()) {
            BY_VALUE_MAP.put(type.getId(), type);
        }
    }

    public static Type forId(byte id) {
        return BY_VALUE_MAP.get(id);
    }

    @Override
    public String toString() {
        return String.format("0x%02x:%s", id, name);
    }
}
