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
     * @param objectId              The ID uniquely identifying the authentication key
     * @param capabilities          What operations are allowed over a session authenticated with this authentication key
     * @param size                  The size of the authentication key in bytes
     * @param domains               The domains that this authentication key kan operate within
     * @param algorithm             The algorithm used to generate this authentication key
     * @param sequence              The number of previous authentication keys that had had the same ID
     * @param origin                Where the authentication key has been generated originally
     * @param label                 They authentication key label
     * @param delegatedCapabilities What capabilities can be bestowed on other objects that were created over a session authenticated with this
     *                              authentication key
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