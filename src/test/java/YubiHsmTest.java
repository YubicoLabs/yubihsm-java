import com.yubico.YHCore;
import com.yubico.YHSession;
import com.yubico.YubiHsm;
import com.yubico.backend.Backend;
import com.yubico.backend.HttpBackend;
import com.yubico.objects.DeviceInfo;
import com.yubico.objects.LogData;
import com.yubico.objects.LogEntry;
import com.yubico.objects.yhconcepts.Algorithm;
import com.yubico.objects.yhconcepts.Capability;
import com.yubico.objects.yhconcepts.ObjectOrigin;
import com.yubico.objects.yhconcepts.ObjectType;
import com.yubico.objects.yhobjects.AuthenticationKey;
import com.yubico.objects.yhobjects.YHObject;
import com.yubico.objects.yhobjects.YHObjectInfo;
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
        listObject(session, id, ObjectType.TYPE_AUTHENTICATION_KEY, false);
        AuthenticationKey
                .importAuthenticationKey(session, id, label, domains, Algorithm.AES128_YUBICO_AUTHENTICATION, capabilities, delegatedCapabilities,
                                         "foo123".toCharArray());
        listObject(session, id, ObjectType.TYPE_AUTHENTICATION_KEY, true);

        // Verify authentication key details
        verifyObjectInfo(session, id, ObjectType.TYPE_AUTHENTICATION_KEY, capabilities, domains, Algorithm.AES128_YUBICO_AUTHENTICATION,
                         ObjectOrigin.YH_ORIGIN_IMPORTED, label, delegatedCapabilities);


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
        YHObject.deleteObject(session, id, ObjectType.TYPE_AUTHENTICATION_KEY);
        listObject(session, id, ObjectType.TYPE_AUTHENTICATION_KEY, false);

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

    private void listObject(final YHSession session, final short id, final ObjectType type, final boolean exists) throws Exception {

        HashMap filters = new HashMap();
        filters.put(YHObject.ListFilter.ID, id);
        filters.put(YHObject.ListFilter.TYPE, type);
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

    private void verifyObjectInfo(final YHSession session, final short id, final ObjectType type, final List<Capability> capabilities,
                                  final List domains, final Algorithm algorithm, final ObjectOrigin origin, final String label,
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
