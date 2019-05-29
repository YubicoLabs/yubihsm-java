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
package yhobjectstest;

import com.yubico.hsm.YHCore;
import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.exceptions.YHDeviceException;
import com.yubico.hsm.internal.util.Utils;
import com.yubico.hsm.yhconcepts.*;
import com.yubico.hsm.yhdata.YHObjectInfo;
import com.yubico.hsm.yhobjects.*;
import lombok.extern.slf4j.Slf4j;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import static org.junit.Assert.*;

@Slf4j
public class YHObjectTest {

    private static YubiHsm yubihsm;
    private static YHSession session;

    @BeforeClass
    public static void init() throws Exception {
        if (session == null) {
            openSession(new HttpBackend());
        }
        YHCore.resetDevice(session);
        yubihsm.close();

        Thread.sleep(1000);
        openSession(new HttpBackend());
    }

    private static void openSession(Backend backend) throws Exception {
        yubihsm = new YubiHsm(backend);
        session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
        session.authenticateSession();
    }

    @AfterClass
    public static void destroy() throws Exception {
        if (session != null) {
            session.closeSession();
            yubihsm.close();
        }
    }

    @Test
    public void testListObjects() throws Exception {
        log.info("TEST START: testListObjects()");

        // Generate 2 Asymmetric keys, 1 HMAC key and 1 Wrapkey
        short asymid1 = AsymmetricKey.generateAsymmetricKey(session, (short) 0, "ec_sign_ssh", Arrays.asList(1), Algorithm.EC_P224,
                                                            Arrays.asList(Capability.SIGN_SSH_CERTIFICATE, Capability.EXPORT_WRAPPED));
        YHObjectInfo asym1 = new YHObjectInfo(asymid1, AsymmetricKey.TYPE, (byte) 0);

        short asymid2 = AsymmetricKey.generateAsymmetricKey(session, (short) 0, "ec_sign_ecdsa", Arrays.asList(2), Algorithm.EC_P224,
                                                            Arrays.asList(Capability.SIGN_ECDSA));
        YHObjectInfo asym2 = new YHObjectInfo(asymid1, AsymmetricKey.TYPE, (byte) 0);

        short hmacid = HmacKey.generateHmacKey(session, (short) 0, "hmac", Arrays.asList(3, 4), Algorithm.HMAC_SHA256,
                                               Arrays.asList(Capability.VERIFY_HMAC));
        YHObjectInfo hmackey = new YHObjectInfo(hmacid, HmacKey.TYPE, (byte) 0);

        short wrapid = WrapKey.generateWrapKey(session, (short) 0, "wrap", Arrays.asList(2, 4), Algorithm.AES192_CCM_WRAP,
                                               Arrays.asList(Capability.EXPORT_WRAPPED), null);
        YHObjectInfo wrapkey = new YHObjectInfo(wrapid, WrapKey.TYPE, (byte) 0);

        try {
            HashMap filters = new HashMap();
            List<YHObjectInfo> objects;

            // List AsymmetricKey objects
            filters.put(ListObjectsFilter.TYPE, AsymmetricKey.TYPE.getId());
            objects = YHObject.getObjectList(session, filters);
            assertEquals(2, objects.size());
            assertTrue(objects.contains(asym1));
            assertTrue(objects.contains(asym2));

            // List object with label "hmac"
            filters.clear();
            filters.put(ListObjectsFilter.LABEL, "hmac");
            objects = YHObject.getObjectList(session, filters);
            assertEquals(1, objects.size());
            assertEquals(hmackey, objects.get(0));

            // List object with domains 5 and type HMAC key
            filters.clear();
            filters.put(ListObjectsFilter.DOMAINS, Utils.getShortFromList(Arrays.asList(5)));
            filters.put(ListObjectsFilter.TYPE, HmacKey.TYPE);
            objects = YHObject.getObjectList(session, filters);
            assertTrue(objects.isEmpty());

            // List object with domain 2
            filters.clear();
            filters.put(ListObjectsFilter.DOMAINS, Utils.getShortFromList(Arrays.asList(2)));
            objects = YHObject.getObjectList(session, filters);
            assertEquals(3, objects.size()); // The third object is the default authentication key
            assertTrue(objects.contains(wrapkey));
            assertTrue(objects.contains(wrapkey));

            // List object with Capability.EXPORT_WRAPPED
            filters.clear();
            filters.put(ListObjectsFilter.CAPABILITIES, Utils.getLongFromCapabilities(Arrays.asList(Capability.EXPORT_WRAPPED)));
            objects = YHObject.getObjectList(session, filters);
            assertEquals(3, objects.size()); // The third object is the default authentication key
            assertTrue(objects.contains(wrapkey));
            assertTrue(objects.contains(asym1));

        } finally {
            YHObject.delete(session, asymid1, AsymmetricKey.TYPE);
            YHObject.delete(session, asymid2, AsymmetricKey.TYPE);
            YHObject.delete(session, hmacid, HmacKey.TYPE);
            YHObject.delete(session, wrapid, WrapKey.TYPE);
        }
        log.info("TEST END: testListObjects()");

    }

    @Test
    public void testDeleteObject() throws Exception {
        log.info("TEST START: testDeleteObject()");

        short keyid = AsymmetricKey.generateAsymmetricKey(session, (short) 0, "ec_sign_ssh", Arrays.asList(1), Algorithm.EC_P224,
                                                          Arrays.asList(Capability.SIGN_SSH_CERTIFICATE, Capability.EXPORT_WRAPPED));
        AsymmetricKey key = new AsymmetricKey(keyid, Algorithm.EC_P224);
        assertTrue(key.exists(session));

        key.delete(session);
        assertFalse(key.exists(session));

        boolean exceptionThrown = false;
        try {
            key.delete(session);
        } catch (YHDeviceException e) {
            if (YHError.OBJECT_NOT_FOUND.equals(e.getYhError())) {
                exceptionThrown = true;
            } else {
                throw e;
            }
        }
        assertFalse(exceptionThrown);

        log.info("TEST END: testDeleteObject()");
    }

    @Test
    public void testObjectInfo() throws Exception {
        YHObjectInfo info = YHObject.getObjectInfo(session, (short) 1, AuthenticationKey.TYPE);
        assertEquals(1, info.getId());
        assertEquals(AuthenticationKey.TYPE, info.getType());
        assertEquals(0, info.getSequence());
        assertTrue(info.getDomains().containsAll(Arrays.asList(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16)));
        assertEquals(Algorithm.AES128_YUBICO_AUTHENTICATION, info.getAlgorithm());
        assertEquals(Origin.YH_ORIGIN_IMPORTED, info.getOrigin());
        assertEquals("DEFAULT AUTHKEY CHANGE THIS ASAP", info.getLabel());
        assertTrue(info.getCapabilities().containsAll(Capability.ALL));
        assertTrue(info.getDelegatedCapabilities().containsAll(Capability.ALL));
    }

}
