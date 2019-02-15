import com.yubico.YHSession;
import com.yubico.YubiHsm;
import com.yubico.backend.Backend;
import com.yubico.backend.HttpBackend;
import com.yubico.exceptions.*;
import com.yubico.objects.DeviceInfo;
import com.yubico.objects.yhconcepts.Capability;
import com.yubico.objects.yhconcepts.ObjectType;
import com.yubico.objects.yhobjects.AuthenticationKey;
import com.yubico.objects.yhobjects.YHObject;
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
            throws YHConnectionException, InvalidSessionException, NoSuchAlgorithmException, InvalidKeyException, YHDeviceException,
                   NoSuchPaddingException, BadPaddingException, YHAuthenticationException, InvalidAlgorithmParameterException,
                   YHInvalidResponseException, InvalidKeySpecException, IllegalBlockSizeException {
        logger.info("TEST START: testAuthenticatedEcho()");
        YHSession session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
        for (int i = 0; i < 5; i++) {
            byte[] data = new byte[32];
            new Random().nextBytes(data);
            byte[] response = yubihsm.secureEcho(session, data);
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
        assertNotEquals(0, info.getSerialnumber());
        assertNotNull(info.getSupportedAlgorithms());
        logger.info("TEST END: testGetDeviceInfo()");
    }

    //@Test
    public void testResetDevice()
            throws InvalidKeySpecException, NoSuchAlgorithmException, YHConnectionException, InvalidSessionException, InvalidKeyException,
                   YHDeviceException, NoSuchPaddingException, BadPaddingException, YHAuthenticationException,
                   InvalidAlgorithmParameterException, YHInvalidResponseException, IllegalBlockSizeException, MalformedURLException {
        logger.info("TEST START: testResetDevice()");

        YHSession session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
        assertNotNull("Failed to create an authenticated session", session);

        yubihsm.resetDevice(session);
        session.closeSession();

        logger.info("TEST END: testResetDevice()");
    }

    @Test
    public void testGetPseudoRandom()
            throws YHConnectionException, InvalidSessionException, NoSuchAlgorithmException, InvalidKeyException, YHDeviceException,
                   NoSuchPaddingException, BadPaddingException, YHAuthenticationException, InvalidAlgorithmParameterException,
                   YHInvalidResponseException, InvalidKeySpecException, IllegalBlockSizeException {
        logger.info("TEST START: testGetPseudoRandom()");
        YHSession session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
        for (int i = 1; i < 20; i++) {
            byte[] response = yubihsm.getRandom(session, i);
            assertEquals(i, response.length);
        }
        session.closeSession();
        logger.info("TEST END: testGetPseudoRandom()");
    }

    @Test
    public void testAuthenticationKeyObject()
            throws YHConnectionException, InvalidSessionException, NoSuchAlgorithmException, InvalidKeyException, YHDeviceException,
                   NoSuchPaddingException, BadPaddingException, YHAuthenticationException, InvalidAlgorithmParameterException,
                   YHInvalidResponseException, InvalidKeySpecException, IllegalBlockSizeException, IOException {
        logger.info("TEST START: testAuthenticationKeyObject()");
        YHSession session = new YHSession(yubihsm, (short) 1, "password".toCharArray());

        // List the authentication keys that already exited in the YubiHSM
        HashMap filters = new HashMap();
        filters.put(YubiHsm.LIST_FILTERS.TYPE, ObjectType.TYPE_AUTHENTICATION_KEY);
        List<YHObject> yhObjects = yubihsm.getObjectList(session, filters);
        int numberOfAuthenticationKeys = yhObjects.size();

        // Create a new authentication key on the YubiHSM
        short id = AuthenticationKey.importAuthenticationKey(session, (short) 0x1234, "imported authentication key", new ArrayList(Arrays.asList(1, 2
                , 3, 4)),
                                                             new ArrayList<Capability>(Arrays.asList(Capability.SIGN_SSH_CERTIFICATE)),
                                                             new ArrayList<Capability>(), "foo123".toCharArray());
        assertEquals(0x1234, id);

        // List the authentication Keys on the HSM again and make sure that the new key is included
        yhObjects = yubihsm.getObjectList(session, filters);
        assertEquals(numberOfAuthenticationKeys + 1, yhObjects.size());
        YHObject importedKey = null;
        for (YHObject o : yhObjects) {
            if (o.getId() == id && o.getType().equals(ObjectType.TYPE_AUTHENTICATION_KEY)) {
                importedKey = o;
                break;
            }
        }
        assertNotNull("The new Authentication Key was not listed among the device objects", importedKey);

        // Communicate over a session authenticated with the new authentication key
        YHSession session2 = new YHSession(yubihsm, id, "foo123".toCharArray());
        session2.createAuthenticatedSession();
        assertEquals(id, session2.getAuthenticationKeyID());
        assertEquals(YHSession.SessionStatus.AUTHENTICATED, session2.getStatus());
        byte[] data = new byte[32];
        new Random().nextBytes(data);
        byte[] response = yubihsm.secureEcho(session2, data);
        assertTrue(Arrays.equals(response, data));
        session2.closeSession();

        // Delete the new Authentication key
        yubihsm.deleteObject(session, id, ObjectType.TYPE_AUTHENTICATION_KEY);

        // List the authentication Keys on the HSM again and make sure that the new key is no longer there
        yhObjects = yubihsm.getObjectList(session, filters);
        assertEquals(numberOfAuthenticationKeys, yhObjects.size());
        importedKey = null;
        for (YHObject o : yhObjects) {
            if (o.getId() == id && o.getType().equals(ObjectType.TYPE_AUTHENTICATION_KEY)) {
                importedKey = o;
                break;
            }
        }
        assertNull("The new Authentication Key should have been deleted", importedKey);

        session.closeSession();
        logger.info("TEST END: testAuthenticationKeyObject()");
    }

}
