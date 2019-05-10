import com.yubico.hsm.YHCore;
import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.exceptions.YHDeviceException;
import com.yubico.hsm.internal.util.Utils;
import com.yubico.hsm.yhconcepts.*;
import com.yubico.hsm.yhdata.DeviceInfo;
import com.yubico.hsm.yhdata.LogData;
import com.yubico.hsm.yhdata.LogEntry;
import com.yubico.hsm.yhdata.YHObjectInfo;
import com.yubico.hsm.yhobjects.*;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.net.MalformedURLException;
import java.util.*;
import java.util.logging.Logger;

import static org.junit.Assert.*;

public class YubiHsmTest {
    private static Logger log = Logger.getLogger(YubiHsmTest.class.getName());

    private static YubiHsm yubihsm;

    @BeforeClass
    public static void init() throws MalformedURLException {
        if (yubihsm == null) {
            Backend backend = new HttpBackend();
            yubihsm = new YubiHsm(backend);
        }
    }

    @AfterClass
    public static void destroy() throws Exception {
        yubihsm.close();
    }


    @Test
    public void testPlainEcho() throws Exception {
        log.info("TEST START: testPlainEcho()");
        for (int i = 0; i < 5; i++) {
            byte[] data = new byte[32];
            new Random().nextBytes(data);

            byte[] response = yubihsm.echo(data);
            assertTrue(Arrays.equals(response, data));
        }
        log.info("TEST END: testPlainEcho()");
    }

    @Test
    public void testSecureEcho() throws Exception {
        log.info("TEST START: testAuthenticatedEcho()");
        YHSession session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
        for (int i = 0; i < 5; i++) {
            byte[] data = new byte[32];
            new Random().nextBytes(data);
            byte[] response = YHCore.secureEcho(session, data);
            assertTrue(Arrays.equals(response, data));
        }
        session.closeSession();
        log.info("TEST END: testAuthenticatedEcho()");
    }

    @Test
    public void testGetDeviceInfo() throws Exception {
        log.info("TEST START: testGetDeviceInfo()");
        DeviceInfo info = yubihsm.getDeviceInfo();
        assertNotNull(info);
        assertNotNull(info.getVersion());
        //assertNotEquals(0, info.getSerialnumber());
        assertNotNull(info.getSupportedAlgorithms());
        log.info("TEST END: testGetDeviceInfo()");
    }

    @Test
    public void testGetPseudoRandom() throws Exception {
        log.info("TEST START: testGetPseudoRandom()");
        YHSession session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
        for (int i = 1; i < 20; i++) {
            byte[] response = YHCore.getRandom(session, i);
            assertEquals(i, response.length);
        }
        session.closeSession();
        log.info("TEST END: testGetPseudoRandom()");
    }

    @Test
    public void testAuthenticationKeyObject() throws Exception {
        log.info("TEST START: testAuthenticationKeyObject()");
        YHSession session = new YHSession(yubihsm, (short) 1, "password".toCharArray());

        // New authentication key details
        final short id = 0x1234;
        final String label = "imported authentication key";
        final List domains = Arrays.asList(1, 2, 3, 4);
        final List capabilities = Arrays.asList(Capability.SIGN_SSH_CERTIFICATE);
        final List delegatedCapabilities = new ArrayList<Capability>();

        // Import a new authentication key into the HSM and verify import
        listObject(session, id, Type.TYPE_AUTHENTICATION_KEY, false);
        AuthenticationKey
                .importAuthenticationKey(session, id, label, domains, Algorithm.AES128_YUBICO_AUTHENTICATION, capabilities, delegatedCapabilities,
                                         "foo123".toCharArray());
        listObject(session, id, Type.TYPE_AUTHENTICATION_KEY, true);

        // Verify authentication key details
        verifyObjectInfo(session, id, Type.TYPE_AUTHENTICATION_KEY, capabilities, domains, Algorithm.AES128_YUBICO_AUTHENTICATION,
                         Origin.YH_ORIGIN_IMPORTED, label, delegatedCapabilities);


        // Communicate over a session authenticated with the new authentication key
        YHSession session2 = new YHSession(yubihsm, id, "foo123".toCharArray());
        session2.createAuthenticatedSession();
        assertEquals(id, session2.getAuthenticationKeyID());
        assertEquals(YHSession.SessionStatus.AUTHENTICATED, session2.getStatus());
        byte[] data = new byte[32];
        new Random().nextBytes(data);
        byte[] response = YHCore.secureEcho(session2, data);
        assertTrue(Arrays.equals(response, data));
        session2.closeSession();

        // Delete the new Authentication key and verify deletion
        YHObject.delete(session, id, Type.TYPE_AUTHENTICATION_KEY);
        listObject(session, id, Type.TYPE_AUTHENTICATION_KEY, false);

        session.closeSession();
        log.info("TEST END: testAuthenticationKeyObject()");
    }

    @Test
    public void testLogEntries() throws Exception {
        log.info("TEST START: testLogEntries()");
        YHSession session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
        LogData logData = YHCore.getLogData(session);

        assertTrue(logData.getUnloggedBootEvents() >= 0);
        assertTrue(logData.getUnloggedAuthenticationEvents() >= 0);
        assertFalse(logData.getLogEntries().isEmpty());

        LogEntry lastEntry = logData.getLastLogEntry();
        YHCore.setLogIndex(session, lastEntry.getItemNumber());
        logData = YHCore.getLogData(session);
        assertEquals(lastEntry.getItemNumber() + 1, logData.getFirstLogEntry().getItemNumber());

        session.closeSession();
        log.info("TEST END: testLogEntries()");
    }

    @Test
    public void testListObjects() throws Exception {
        log.info("TEST START: testListObjects()");
        YHSession session = new YHSession(yubihsm, (short) 1, "password".toCharArray());

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

            // List AsymmetricKey yhdata
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
        session.closeSession();
        log.info("TEST END: testListObjects()");

    }

    @Test
    public void testeDeleteObject() throws Exception {
        log.info("TEST START: testeDeleteObject()");
        YHSession session = new YHSession(yubihsm, (short) 1, "password".toCharArray());

        short asymid1 = AsymmetricKey.generateAsymmetricKey(session, (short) 0, "ec_sign_ssh", Arrays.asList(1), Algorithm.EC_P224,
                                                            Arrays.asList(Capability.SIGN_SSH_CERTIFICATE, Capability.EXPORT_WRAPPED));
        AsymmetricKey key = new AsymmetricKey(asymid1, Algorithm.EC_P224);
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

        session.closeSession();
        log.info("TEST END: testeDeleteObject()");
    }

    private void listObject(final YHSession session, final short id, final Type type, final boolean exists) throws Exception {

        HashMap filters = new HashMap();
        filters.put(ListObjectsFilter.ID, id);
        filters.put(ListObjectsFilter.TYPE, type);
        List<YHObjectInfo> objects = YHObject.getObjectList(session, filters);
        if (exists) {
            assertEquals(1, objects.size());
            YHObjectInfo object = objects.get(0);
            assertEquals(id, object.getId());
            assertEquals(type, object.getType());
        } else {
            assertEquals(0, objects.size());
        }
    }

    private void verifyObjectInfo(final YHSession session, final short id, final Type type, final List<Capability> capabilities,
                                  final List domains, final Algorithm algorithm, final Origin origin, final String label,
                                  final List<Capability> delegatedCapabilities) throws Exception {
        YHObjectInfo object = YHObject.getObjectInfo(session, id, type);
        assertNotNull(object);
        assertEquals(capabilities, object.getCapabilities());
        assertEquals(id, object.getId());
        assertEquals(domains, object.getDomains());
        assertEquals(type, object.getType());
        assertEquals(algorithm, object.getAlgorithm());
        assertEquals(origin, object.getOrigin());
        assertEquals(label, object.getLabel());
        assertEquals(delegatedCapabilities, object.getDelegatedCapabilities());
    }

}
