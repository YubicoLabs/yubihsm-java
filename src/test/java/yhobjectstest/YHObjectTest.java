package yhobjectstest;

import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.exceptions.YHDeviceException;
import com.yubico.hsm.internal.util.Utils;
import com.yubico.hsm.yhconcepts.Algorithm;
import com.yubico.hsm.yhconcepts.Capability;
import com.yubico.hsm.yhconcepts.ListObjectsFilter;
import com.yubico.hsm.yhconcepts.YHError;
import com.yubico.hsm.yhdata.YHObjectInfo;
import com.yubico.hsm.yhobjects.AsymmetricKey;
import com.yubico.hsm.yhobjects.HmacKey;
import com.yubico.hsm.yhobjects.WrapKey;
import com.yubico.hsm.yhobjects.YHObject;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.logging.Logger;

import static org.junit.Assert.*;

public class YHObjectTest {
    Logger log = Logger.getLogger(YHObjectTest.class.getName());

    private static YubiHsm yubihsm;
    private static YHSession session;

    @BeforeClass
    public static void init() throws Exception {
        if (session == null) {
            Backend backend = new HttpBackend();
            yubihsm = new YubiHsm(backend);
            session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
            session.authenticateSession();
        }
    }

    @AfterClass
    public static void destroy() throws Exception {
        session.closeSession();
        yubihsm.close();
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
            if(YHError.OBJECT_NOT_FOUND.equals(e.getYhError())) {
                exceptionThrown = true;
            } else {
                throw e;
            }
        }
        assertFalse(exceptionThrown);

        log.info("TEST END: testDeleteObject()");
    }

}
