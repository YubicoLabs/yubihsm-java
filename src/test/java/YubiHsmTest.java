import com.yubico.YHSession;
import com.yubico.YubiHsm;
import com.yubico.backend.Backend;
import com.yubico.backend.HttpBackend;
import com.yubico.exceptions.*;
import com.yubico.objects.DeviceInfo;
import com.yubico.objects.yhconcepts.ObjectType;
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
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Random;
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
            throws YHConnectionException, InvalidSession, NoSuchAlgorithmException, InvalidKeyException, YHDeviceException,
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
            throws InvalidKeySpecException, NoSuchAlgorithmException, YHConnectionException, InvalidSession, InvalidKeyException,
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
            throws YHConnectionException, InvalidSession, NoSuchAlgorithmException, InvalidKeyException, YHDeviceException,
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
    public void testObjectOperations()
            throws YHConnectionException, InvalidSession, NoSuchAlgorithmException, InvalidKeyException, YHDeviceException,
                   NoSuchPaddingException, BadPaddingException, YHAuthenticationException, InvalidAlgorithmParameterException,
                   YHInvalidResponseException, InvalidKeySpecException, IllegalBlockSizeException, IOException {
        logger.info("TEST START: testObjectOperations()");
        YHSession session = new YHSession(yubihsm, (short) 1, "password".toCharArray());

        HashMap filters = new HashMap();
        filters.put(YubiHsm.LIST_FILTERS.TYPE, ObjectType.TYPE_AUTHENTICATION_KEY);
        List<YHObject> yhObjects = yubihsm.getObjectList(session, null);
        assertTrue("No objects were returned", yhObjects.size() > 0);
        for(YHObject o : yhObjects) {
            System.out.println(o.toString());
            System.out.println();
        }
        session.closeSession();
        logger.info("TEST END: testObjectOperations()");
    }

}
