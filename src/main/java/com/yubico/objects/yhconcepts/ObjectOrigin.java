package com.yubico.objects.yhconcepts;

/**
 * Class representing the origin of objects stored on the device, aka. where the objects have been created originally
 */
public class ObjectOrigin extends YHConcept {

    /**
     * @param id   Origin ID
     * @param name Origin name
     */
    private ObjectOrigin(final byte id, final String name) {
        super(id, name);
    }

    /**
     * @return The ID of the origin
     */
    public byte getOriginId() {
        return (byte) getId();
    }

    /**
     * Returns a String representation of the origin
     *
     * @return The ID and name of the origin as a formatted String
     */
    public String toString() {
        return String.format("0x%02X: " + getName(), getOriginId());
    }

    /**
     * Return the ObjectOrigin object with the specified ID
     *
     * @param id The origin ID
     * @return The origin object whose ID is `id`. Null if the ID is unrecognized
     */
    public static ObjectOrigin getObjectOrigin(final byte id) {
        switch (id) {
            case 0x01: return YH_ORIGIN_GENERATED;
            case 0x02: return YH_ORIGIN_IMPORTED;
            case 0x10: return YH_ORIGIN_IMPORTED_WRAPPED;
            default: return null;
        }
    }

    /** Object was originated on the YubiHSM */
    public static final ObjectOrigin YH_ORIGIN_GENERATED = new ObjectOrigin((byte) 0x01, "generated");
    /** Object was imported into the YubiHSM */
    public static final ObjectOrigin YH_ORIGIN_IMPORTED = new ObjectOrigin((byte) 0x02, "imported");
    /** Object was imported into the YubiHSM under wrap */
    public static final ObjectOrigin YH_ORIGIN_IMPORTED_WRAPPED = new ObjectOrigin((byte) 0x10, "imported-under-wrap");
}
