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
import com.yubico.hsm.yhconcepts.Algorithm;
import com.yubico.hsm.yhconcepts.Capability;
import com.yubico.hsm.yhconcepts.Origin;
import com.yubico.hsm.yhconcepts.Type;
import com.yubico.hsm.yhobjects.YHObject;
import lombok.NonNull;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class YHObjectInfo {

    private short id = 0;
    private short objectSize = 0;
    private Type type = null;
    private byte sequence = 0;
    private List<Integer> domains = new ArrayList<Integer>();
    private Algorithm algorithm = null;
    private Origin origin = null;
    private String label = "";
    private List<Capability> capabilities = new ArrayList<Capability>();
    private List<Capability> delegatedCapabilities = new ArrayList<Capability>();


    /**
     * @param id       The object ID uniquely identifying the object together with the object type
     * @param type     The object type uniquely identifying the object together with the object ID
     * @param sequence The number of previous objects that had had the same ID and type
     */
    public YHObjectInfo(final short id, final Type type, final byte sequence) {
        this.id = id;
        this.type = type;
        this.sequence = sequence;
    }

    /**
     * @param objectId              The object ID uniquely identifying the object together with the object type
     * @param type                  The object type uniquely identifying the object together with the object ID
     * @param capabilities          What the object can be used to do
     * @param domains               The domains that the object can operate within
     * @param algorithm             The algorithm used to create this object when applicable
     * @param label                 The object label
     * @param delegatedCapabilities What capabilities can the object bestow on other objects when applicable
     */
    public YHObjectInfo(final short objectId, final Type type, final String label, final List<Integer> domains,
                        final Algorithm algorithm, final List<Capability> capabilities, final List<Capability> delegatedCapabilities) {
        this.id = objectId;
        this.type = type;
        this.label = Utils.getLabel(label);
        this.domains = domains;
        this.algorithm = algorithm;
        this.capabilities = capabilities;
        this.delegatedCapabilities = delegatedCapabilities;
    }

    /**
     * Creates an YHObject object by parsing a byte array
     *
     * @param data The object data as a byte array in the form of {8 bytes capabilities + 2 bytes object ID + 2 bytes object size + 2 bytes domains
     *             + 1 byte type + 1 byte algorithm + 1 byte sequence + 1 byte object origin + 40 bytes label + 8 bytes delegated capabilities}
     */
    public YHObjectInfo(@NonNull final byte[] data) {
        ByteBuffer bb = ByteBuffer.wrap(data);
        capabilities = Utils.getCapabilitiesFromLong(bb.getLong());
        id = bb.getShort();
        objectSize = bb.getShort();
        domains = Utils.getListFromShort(bb.getShort());
        type = Type.forId(bb.get());
        algorithm = Algorithm.forId(bb.get());
        sequence = bb.get();
        origin = Origin.forId(bb.get());
        byte[] l = new byte[YHObject.OBJECT_LABEL_SIZE];
        bb.get(l, 0, YHObject.OBJECT_LABEL_SIZE);
        label = new String(l);
        label = label.trim();
        delegatedCapabilities = Utils.getCapabilitiesFromLong(bb.getLong());
    }

    public short getId() {
        return id;
    }

    public short getObjectSize() {
        return objectSize;
    }

    public Type getType() {
        return type;
    }

    public byte getSequence() {
        return sequence;
    }

    public List<Integer> getDomains() {
        return domains;
    }

    public Algorithm getAlgorithm() {
        return algorithm;
    }

    public Origin getOrigin() {
        return origin;
    }

    public String getLabel() {
        if (label == null) {
            return "";
        }
        return label;
    }

    public List<Capability> getCapabilities() {
        return capabilities;
    }

    public List<Capability> getDelegatedCapabilities() {
        return delegatedCapabilities;
    }

    @Override
    public boolean equals(final Object other) {
        if(this == other) {
            return true;
        }
        if (!(other instanceof YHObjectInfo)) {
            return false;
        }
        YHObjectInfo otherInfo = (YHObjectInfo) other;
        return id == otherInfo.getId() && type.equals(otherInfo.getType());
    }

    @Override
    public int hashCode() {
        Object[] fields = {id, type};
        return Objects.hash(fields);
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("Object ID: " + id).append("\n");
        builder.append("Object Type: " + type.getName()).append("\n");
        builder.append("Sequence: " + sequence).append("\n");
        builder.append("Label: ").append(label).append("\n");
        builder.append("Size: " + objectSize + " bytes").append("\n");

        builder.append("Domains: ");
        if (domains != null && !domains.isEmpty()) {
            for (int d : domains) {
                builder.append(d).append(" ");
            }
        }
        builder.append("\n");

        builder.append("Algorithm: ");
        if (algorithm != null) {
            builder.append(algorithm.getName());
        }
        builder.append("\n");

        builder.append("Origin: ");
        if (origin != null) {
            builder.append(origin.getName());
        }
        builder.append("\n");

        builder.append("Capabilities: ");
        if (capabilities != null && !capabilities.isEmpty()) {
            for (Capability c : capabilities) {
                builder.append(c.getName()).append(" ");
            }
        }
        builder.append("\n");

        builder.append("Delegated capabilities: ");
        if (delegatedCapabilities != null && !delegatedCapabilities.isEmpty()) {
            for (Capability c : delegatedCapabilities) {
                builder.append(c.getName()).append(" ");
            }
        }
        builder.append("\n");

        return builder.toString();
    }

}
