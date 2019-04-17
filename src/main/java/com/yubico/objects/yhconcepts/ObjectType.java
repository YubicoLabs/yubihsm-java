package com.yubico.objects.yhconcepts;

/**
 * Class representing the types of objects that can be stored on the device
 */
public class ObjectType extends YHConcept {

    private ObjectType(final byte id, final String name) {
        super(id, name);
    }

    public byte getTypeId() {
        return (byte) getId();
    }

    /**
     * Returns a String representation of the type
     *
     * @return The ID and name of the type as a formatted String
     */
    public String toString() {
        return String.format("0x%02X: " + getName(), getTypeId());
    }

    /**
     * Return the ObjectType object with the specified ID
     *
     * @param id
     * @return The type object whose ID is `id`. Null if the ID is not recognized
     */
    public static ObjectType getObjectType(final byte id) {
        switch (id) {
            case 1: return TYPE_OPAQUE;
            case 2: return TYPE_AUTHENTICATION_KEY;
            case 3: return TYPE_ASYMMETRIC_KEY;
            case 4: return TYPE_WRAP_KEY;
            case 5: return TYPE_HMAC_KEY;
            case 6: return TYPE_TEMPLATE;
            case 7: return TYPE_OTP_AEAD_KEY;
            default: return null;
        }
    }

    /** Object is an X509Certificate or raw data of any kind */
    public static final ObjectType TYPE_OPAQUE = new ObjectType((byte) 0x01, "Opaque");
    /** Object is an Authentication key used to establish an encrypted communication session with the YubiHSM */
    public static final ObjectType TYPE_AUTHENTICATION_KEY = new ObjectType((byte) 0x2, "Authentication Key");
    /** Object is an Asymmetric key of type RSA, EC or ED */
    public static final ObjectType TYPE_ASYMMETRIC_KEY = new ObjectType((byte) 0x03, "Asymmetric Key");
    /** Object is a Wrap key used to export and import sensitive data securely */
    public static final ObjectType TYPE_WRAP_KEY = new ObjectType((byte) 0x04, "Wrap Key");
    public static final ObjectType TYPE_HMAC_KEY = new ObjectType((byte) 0x05, "HMAC Key");
    public static final ObjectType TYPE_TEMPLATE = new ObjectType((byte) 0x06, "Template");
    public static final ObjectType TYPE_OTP_AEAD_KEY = new ObjectType((byte) 0x07, "OTP AEAD Key");

}
