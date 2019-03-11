package com.yubico.objects.yhobjects;

import com.yubico.internal.util.Utils;
import com.yubico.objects.yhconcepts.*;

import java.nio.ByteBuffer;
import java.util.List;

/**
 * Class representing objects stored on the device
 */
public class YHObject {

    /**
     * The maximum length of an object's label
     */
    public static final int LABEL_LENGTH = 40;

    private short id;
    private short objectSize;
    private ObjectType type;
    private byte sequence;
    private List<Integer> domains;
    private Algorithm algorithm;
    private ObjectOrigin origin;
    private String label;
    private List<Capability> capabilities;
    private List<Capability> delegatedCapabilities;

    protected YHObject(final short id) {
        this.id = id;
    }

    /**
     * @param id       The object ID uniquely identifying the object together with the object type
     * @param type     The object type uniquely identifying the object together with the object ID
     * @param sequence The number if previews objects that had had the same ID and type
     */
    public YHObject(final short id, final ObjectType type, final byte sequence) {
        this.id = id;
        this.type = type;
        this.sequence = sequence;

        this.capabilities = null;
        this.objectSize = -1;
        this.domains = null;
        this.algorithm = null;
        this.origin = null;
        this.label = "";
        this.delegatedCapabilities = null;
    }

    /**
     * @param objectId              The object ID uniquely identifying the object together with the object type
     * @param type                  The object type uniquely identifying the object together with the object ID
     * @param capabilities          What the object can be used to do
     * @param size                  The object size in bytes
     * @param domains               The domains that the object can operate within
     * @param algorithm             The algorithm used to create this object when applicable
     * @param sequence              The number of previous objects that had had the same ID and type
     * @param origin                Where the object has been created originally
     * @param label                 The object label
     * @param delegatedCapabilities What capabilities can the object bestow on other objects when applicable
     */
    public YHObject(final short objectId, final ObjectType type, final List<Capability> capabilities, final short size, final List<Integer> domains,
                    final Algorithm algorithm, final byte sequence, final ObjectOrigin origin, final String label,
                    final List<Capability> delegatedCapabilities) {
        this.capabilities = capabilities;
        this.id = objectId;
        this.objectSize = size;
        this.domains = domains;
        this.type = type;
        this.algorithm = algorithm;
        this.sequence = sequence;
        this.origin = origin;
        this.label = label;
        this.delegatedCapabilities = delegatedCapabilities;
    }

    /**
     * Constructor to create an YHObject object by parsing a byte array
     *
     * @param data The object data as a byte array in the form of {8 bytes capabilities + 2 bytes object ID + 2 bytes object size + 2 bytes domains
     *             + 1 byte type + 1 byte algorithm + 1 byte sequence + 1 byte object origin + 40 bytes label + 8 bytes delegated capabilities}
     */
    public YHObject(final byte[] data) {
        ByteBuffer bb = ByteBuffer.wrap(data);
        capabilities = Capability.getCapabilities(bb.getLong());
        id = bb.getShort();
        objectSize = bb.getShort();
        domains = Utils.getListFromShort(bb.getShort());
        type = ObjectType.getObjectType(bb.get());
        algorithm = Algorithm.getAlgorithm(bb.get());
        sequence = bb.get();
        origin = ObjectOrigin.getObjectOrigin(bb.get());
        byte[] l = new byte[LABEL_LENGTH];
        bb.get(l, 0, LABEL_LENGTH);
        label = new String(l);
        label = label.trim();
        delegatedCapabilities = Capability.getCapabilities(bb.getLong());
    }

    /**
     * @return The object ID
     */
    public short getId() {
        return id;
    }

    /**
     * @param id The object ID
     */
    public void setId(short id) {
        this.id = id;
    }

    /**
     * @return The object size
     */
    public short getObjectSize() {
        return objectSize;
    }

    /**
     * @param objectSize the object size
     */
    public void setObjectSize(short objectSize) {
        this.objectSize = objectSize;
    }

    /**
     * @return The object type
     */
    public ObjectType getType() {
        return type;
    }

    /**
     * @param type The object type
     */
    public void setType(ObjectType type) {
        this.type = type;
    }

    /**
     * @return The object sequence
     */
    public byte getSequence() {
        return sequence;
    }

    /**
     * @param sequence The object sequence
     */
    public void setSequence(byte sequence) {
        this.sequence = sequence;
    }

    /**
     * @return The object domains
     */
    public List<Integer> getDomains() {
        return domains;
    }

    /**
     * @param domains The objects domains
     */
    public void setDomains(List<Integer> domains) {
        this.domains = domains;
    }

    /**
     * @return The object algorithm
     */
    public Algorithm getAlgorithm() {
        return algorithm;
    }

    /**
     * @param algorithm The object algorithm
     */
    public void setAlgorithm(Algorithm algorithm) {
        this.algorithm = algorithm;
    }

    /**
     * @return The object origin
     */
    public ObjectOrigin getOrigin() {
        return origin;
    }

    /**
     * @param origin The object origin
     */
    public void setOrigin(ObjectOrigin origin) {
        this.origin = origin;
    }

    /**
     * @return The object label
     */
    public String getLabel() {
        return label;
    }

    /**
     * @param label The object label
     */
    public void setLabel(String label) {
        this.label = label;
    }

    /**
     * @return The object capabilities
     */
    public List<Capability> getCapabilities() {
        return capabilities;
    }

    /**
     * @param capabilities The object capabilities
     */
    public void setCapabilities(List<Capability> capabilities) {
        this.capabilities = capabilities;
    }

    /**
     * @return The object delegated capabilities
     */
    public List<Capability> getDelegatedCapabilities() {
        return delegatedCapabilities;
    }

    /**
     * @param delegatedCapabilities The object delegated capabilities
     */
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
        if (objectSize > 0) {
            builder.append("Size: " + objectSize + " bytes").append("\n");
        }
        if (domains != null && domains.size() < 0) {
            builder.append("Domains: ");
            for (int d : domains) {
                builder.append(d).append(" ");
            }
            builder.append("\n");
        }
        if (algorithm != null) {
            builder.append("Algorithm: " + algorithm.getName()).append("\n");
        }
        if (origin != null) {
            builder.append("Origin: ").append(origin.getName()).append("\n");
        }
        if (label != null && !label.isEmpty()) {
            builder.append("Label: ").append(label).append("\n");
        }
        if (capabilities != null && capabilities.size() > 0) {
            builder.append("Capabilities: ");
            for (Capability c : capabilities) {
                builder.append(c.getName()).append(" ");
            }
            builder.append("\n");
        }
        if (delegatedCapabilities != null && delegatedCapabilities.size() > 0) {
            builder.append("Delegated capabilities: ");
            for (Capability c : delegatedCapabilities) {
                builder.append(c.getName()).append(" ");
            }
            builder.append("\n");
        }
        return builder.toString();
    }

    /**
     * Compares two YHObject objects
     *
     * @param a
     * @param b
     * @return True if the objects' IDs and the objects' types are equal. False otherwise
     */
    public static boolean equals(final YHObject a, final YHObject b) {
        return (a.getId() == b.getId()) && YHConcept.equals(a.getType(), b.getType());
    }
}
