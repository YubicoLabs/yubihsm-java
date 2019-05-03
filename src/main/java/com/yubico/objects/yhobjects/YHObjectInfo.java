package com.yubico.objects.yhobjects;

import com.yubico.internal.util.Utils;
import com.yubico.objects.yhconcepts.Algorithm;
import com.yubico.objects.yhconcepts.Capability;
import com.yubico.objects.yhconcepts.ObjectOrigin;
import com.yubico.objects.yhconcepts.ObjectType;
import lombok.NonNull;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class YHObjectInfo {

    private short id = 0;
    private short objectSize = 0;
    private ObjectType type = null;
    private byte sequence = 0;
    private List<Integer> domains = new ArrayList<Integer>();
    private Algorithm algorithm = null;
    private ObjectOrigin origin = null;
    private String label = "";
    private List<Capability> capabilities = new ArrayList<Capability>();
    private List<Capability> delegatedCapabilities = new ArrayList<Capability>();


    /**
     * @param id       The object ID uniquely identifying the object together with the object type
     * @param type     The object type uniquely identifying the object together with the object ID
     * @param sequence The number of previews objects that had had the same ID and type
     */
    public YHObjectInfo(final short id, final ObjectType type, final byte sequence) {
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
    public YHObjectInfo(final short objectId, final ObjectType type, final String label, final List<Integer> domains,
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
        capabilities = Capability.getCapabilities(bb.getLong());
        id = bb.getShort();
        objectSize = bb.getShort();
        domains = Utils.getListFromShort(bb.getShort());
        type = ObjectType.getObjectType(bb.get());
        algorithm = Algorithm.getAlgorithm(bb.get());
        sequence = bb.get();
        origin = ObjectOrigin.getObjectOrigin(bb.get());
        byte[] l = new byte[YHObject.OBJECT_LABEL_SIZE];
        bb.get(l, 0, YHObject.OBJECT_LABEL_SIZE);
        label = new String(l);
        label = label.trim();
        delegatedCapabilities = Capability.getCapabilities(bb.getLong());
    }

    public short getId() {
        return id;
    }

    public void setId(short id) {
        this.id = id;
    }

    public short getObjectSize() {
        return objectSize;
    }

    public void setObjectSize(short objectSize) {
        this.objectSize = objectSize;
    }

    public ObjectType getType() {
        return type;
    }

    public void setType(ObjectType type) {
        this.type = type;
    }

    public byte getSequence() {
        return sequence;
    }

    public void setSequence(byte sequence) {
        this.sequence = sequence;
    }

    public List<Integer> getDomains() {
        return domains;
    }

    public void setDomains(List<Integer> domains) {
        this.domains = domains;
    }

    public Algorithm getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(Algorithm algorithm) {
        this.algorithm = algorithm;
    }

    public ObjectOrigin getOrigin() {
        return origin;
    }

    public void setOrigin(ObjectOrigin origin) {
        this.origin = origin;
    }

    public String getLabel() {
        if (label == null) {
            return "";
        }
        return label;
    }

    public void setLabel(String label) {
        this.label = Utils.getLabel(label);
    }

    public List<Capability> getCapabilities() {
        return capabilities;
    }

    public void setCapabilities(List<Capability> capabilities) {
        this.capabilities = capabilities;
    }

    public List<Capability> getDelegatedCapabilities() {
        return delegatedCapabilities;
    }

    public void setDelegatedCapabilities(List<Capability> delegatedCapabilities) {
        this.delegatedCapabilities = delegatedCapabilities;
    }

    /**
     * @return A String representation of the object
     */
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
