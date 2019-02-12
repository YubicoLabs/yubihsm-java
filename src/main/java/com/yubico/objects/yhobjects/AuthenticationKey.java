package com.yubico.objects.yhobjects;

import com.yubico.objects.yhconcepts.Algorithm;
import com.yubico.objects.yhconcepts.Capability;
import com.yubico.objects.yhconcepts.ObjectOrigin;
import com.yubico.objects.yhconcepts.ObjectType;

import java.util.List;

/**
 * Class representing an Authentication Key Object
 */
public class AuthenticationKey extends YHObject {

    public static final ObjectType TYPE = ObjectType.TYPE_AUTHENTICATION_KEY;

    /**
     * @param objectId
     * @param capabilities
     * @param size
     * @param domains
     * @param algorithm
     * @param sequence
     * @param origin
     * @param label
     * @param delegatedCapabilities
     */
    public AuthenticationKey(final short objectId, final long capabilities, final short size, final short domains, final byte algorithm,
                             final byte sequence, final byte origin, final String label, final long delegatedCapabilities) {
        super(objectId, TYPE.getTypeId(), capabilities, size, domains, algorithm, sequence, origin, label, delegatedCapabilities);
    }

    /**
     * @param objectId
     * @param capabilities
     * @param size
     * @param domains
     * @param algorithm
     * @param sequence
     * @param origin
     * @param label
     * @param delegatedCapabilities
     */
    public AuthenticationKey(final short objectId, final List<Capability> capabilities, final short size, final List<Integer> domains,
                             final Algorithm algorithm, final byte sequence, final ObjectOrigin origin, final String label,
                             final List<Capability> delegatedCapabilities) {
        super(objectId, TYPE, capabilities, size, domains, algorithm, sequence, origin, label, delegatedCapabilities);
    }

    /**
     * @param data
     */
    public AuthenticationKey(final byte[] data) {
        super(data);
    }
}



