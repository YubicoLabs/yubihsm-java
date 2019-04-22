import com.yubico.YHCore;
import com.yubico.YHSession;
import com.yubico.YubiHsm;
import com.yubico.backend.Backend;
import com.yubico.backend.HttpBackend;
import com.yubico.exceptions.YHAuthenticationException;
import com.yubico.exceptions.YHConnectionException;
import com.yubico.exceptions.YHDeviceException;
import com.yubico.exceptions.YHInvalidResponseException;
import com.yubico.objects.DeviceInfo;
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

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.logging.Logger;

import static org.junit.Assert.*;

public class YubiHsmTest {


    Logger logger = Logger.getLogger(YubiHsmTest.class.getName());

    private static YubiHsm yubihsm;

    @BeforeClass
    public static void init() throws MalformedURLException {
        if (yubihsm == null) {
            Backend backend = new HttpBackend();
            yubihsm = new YubiHsm(backend);
        }
    }

    @AfterClass
    public static void destroy() {
        yubihsm.close();
    }


    @Test
    public void testPlainEcho() throws YHDeviceException, YHInvalidResponseException, YHConnectionException, MalformedURLException {
        logger.info("TEST START: testPlainEcho()");
        for (int i = 0; i < 5; i++) {
            byte[] data = new byte[32];
            new Random().nextBytes(data);

            byte[] response = yubihsm.echo(data);
            assertTrue(Arrays.equals(response, data));
        }
        logger.info("TEST END: testPlainEcho()");
    }

    @Test
    public void testSecureEcho()
            throws YHConnectionException, NoSuchAlgorithmException, InvalidKeyException, YHDeviceException,
                   NoSuchPaddingException, BadPaddingException, YHAuthenticationException, InvalidAlgorithmParameterException,
                   YHInvalidResponseException, InvalidKeySpecException, IllegalBlockSizeException {
        logger.info("TEST START: testAuthenticatedEcho()");
        YHSession session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
        for (int i = 0; i < 5; i++) {
            byte[] data = new byte[32];
            new Random().nextBytes(data);
            byte[] response = YHCore.secureEcho(session, data);
            assertTrue(Arrays.equals(response, data));
        }
        session.closeSession();
        logger.info("TEST END: testAuthenticatedEcho()");
    }

    @Test
    public void testGetDeviceInfo() throws YHDeviceException, YHInvalidResponseException, YHConnectionException {
        logger.info("TEST START: testGetDeviceInfo()");
        DeviceInfo info = yubihsm.getDeviceInfo();
        assertNotNull(info);
        assertNotNull(info.getVersion());
        //assertNotEquals(0, info.getSerialnumber());
        assertNotNull(info.getSupportedAlgorithms());
        logger.info("TEST END: testGetDeviceInfo()");
    }

    //@Test
    public void testResetDevice()
            throws InvalidKeySpecException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException,
                   YHDeviceException, NoSuchPaddingException, BadPaddingException, YHAuthenticationException,
                   InvalidAlgorithmParameterException, YHInvalidResponseException, IllegalBlockSizeException, MalformedURLException {
        logger.info("TEST START: testResetDevice()");

        YHSession session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
        assertNotNull("Failed to create an authenticated session", session);

        YHCore.resetDevice(session);
        session.closeSession();

        logger.info("TEST END: testResetDevice()");
    }

    @Test
    public void testGetPseudoRandom()
            throws YHConnectionException, NoSuchAlgorithmException, InvalidKeyException, YHDeviceException,
                   NoSuchPaddingException, BadPaddingException, YHAuthenticationException, InvalidAlgorithmParameterException,
                   YHInvalidResponseException, InvalidKeySpecException, IllegalBlockSizeException {
        logger.info("TEST START: testGetPseudoRandom()");
        YHSession session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
        for (int i = 1; i < 20; i++) {
            byte[] response = YHCore.getRandom(session, i);
            assertEquals(i, response.length);
        }
        session.closeSession();
        logger.info("TEST END: testGetPseudoRandom()");
    }

    @Test
    public void testAuthenticationKeyObject()
            throws YHConnectionException, NoSuchAlgorithmException, InvalidKeyException, YHDeviceException,
                   NoSuchPaddingException, BadPaddingException, YHAuthenticationException, InvalidAlgorithmParameterException,
                   YHInvalidResponseException, InvalidKeySpecException, IllegalBlockSizeException, IOException {
        logger.info("TEST START: testAuthenticationKeyObject()");
        YHSession session = new YHSession(yubihsm, (short) 1, "password".toCharArray());

        // New authentication key details
        final short id = 0x1234;
        final String label = "imported authentication key";
        final List domains = Arrays.asList(1, 2, 3, 4);
        final List capabilities = Arrays.asList(Capability.SIGN_SSH_CERTIFICATE);
        final List delegatedCapabilities = new ArrayList<Capability>();

        // Import a new authentication key into the HSM and verify import
        listObject(session, id, ObjectType.TYPE_AUTHENTICATION_KEY, false);
        YHObjectInfo keyinfo = AuthenticationKey.getObjectInfoForNewKey((short) 0, label, domains, capabilities, delegatedCapabilities);
        AuthenticationKey
                .importAuthenticationKey(session, keyinfo, "foo123".toCharArray());
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
        logger.info("TEST END: testAuthenticationKeyObject()");
    }

    private void listObject(final YHSession session, final short id, final ObjectType type, final boolean exists)
            throws IOException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   NoSuchPaddingException, IllegalBlockSizeException {

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
                                  final List<Capability> delegatedCapabilities)
            throws NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   NoSuchPaddingException, IllegalBlockSizeException {
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
