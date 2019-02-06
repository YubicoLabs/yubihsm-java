import com.yubico.YubiHSM;
import com.yubico.YubiHSMSession;
import com.yubico.backend.Backend;
import com.yubico.backend.HttpBackend;
import com.yubico.exceptions.*;
import com.yubico.objects.DeviceInfo;
import com.yubico.util.Utils;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.net.MalformedURLException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;
import java.util.logging.Logger;

import static org.junit.Assert.*;

public class YubiHSMTest {


    Logger logger = Logger.getLogger(YubiHSMTest.class.getName());

    private static YubiHSM yubihsm;

    @BeforeClass
    public static void init() throws MalformedURLException {
        if (yubihsm == null) {
            Backend backend = new HttpBackend();
            yubihsm = new YubiHSM(backend);
        }
    }

    @AfterClass
    public static void destroy() {
        yubihsm.close();
    }


    @Test
    public void testPlainEcho() throws YubiHsmDeviceException, YubiHsmInvalidResponseException, YubiHsmConnectionException, MalformedURLException {
        logger.info("TEST START: testPlainEcho()");
        for (int i = 0; i < 5; i++) {
            byte[] data = new byte[32];
            new Random().nextBytes(data);

            byte[] response = yubihsm.echo(data);
            assertTrue(Utils.isByteArrayEqual(response, data));
        }
        logger.info("TEST END: testPlainEcho()");
    }

    @Test
    public void testSecureEcho()
            throws YubiHsmConnectionException, InvalidSession, NoSuchAlgorithmException, InvalidKeyException, YubiHsmDeviceException,
                   NoSuchPaddingException, BadPaddingException, YubiHsmAuthenticationException, InvalidAlgorithmParameterException,
                   YubiHsmInvalidResponseException, InvalidKeySpecException, IllegalBlockSizeException {
        logger.info("TEST START: testAuthenticatedEcho()");
        YubiHSMSession session = new YubiHSMSession(yubihsm, (short) 1, "password".toCharArray());
        for (int i = 0; i < 5; i++) {
            byte[] data = new byte[32];
            new Random().nextBytes(data);
            byte[] response = yubihsm.secureEcho(session, data);
            assertTrue(Utils.isByteArrayEqual(response, data));
        }
        session.closeSession();
        logger.info("TEST END: testAuthenticatedEcho()");
    }

    @Test
    public void testGetDeviceInfo() throws YubiHsmDeviceException, YubiHsmInvalidResponseException, YubiHsmConnectionException {
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
            throws InvalidKeySpecException, NoSuchAlgorithmException, YubiHsmConnectionException, InvalidSession, InvalidKeyException,
                   YubiHsmDeviceException, NoSuchPaddingException, BadPaddingException, YubiHsmAuthenticationException,
                   InvalidAlgorithmParameterException, YubiHsmInvalidResponseException, IllegalBlockSizeException, MalformedURLException {
        logger.info("TEST START: testResetDevice()");

        YubiHSMSession session = new YubiHSMSession(yubihsm, (short) 1, "password".toCharArray());
        assertNotNull("Failed to create an authenticated session", session);

        yubihsm.resetDevice(session);
        session.closeSession();

        logger.info("TEST END: testResetDevice()");
    }

    @Test
    public void testGetPseudoRandom()
            throws YubiHsmConnectionException, InvalidSession, NoSuchAlgorithmException, InvalidKeyException, YubiHsmDeviceException,
                   NoSuchPaddingException, BadPaddingException, YubiHsmAuthenticationException, InvalidAlgorithmParameterException,
                   YubiHsmInvalidResponseException, InvalidKeySpecException, IllegalBlockSizeException {
        logger.info("TEST START: testGetPseudoRandom()");
        YubiHSMSession session = new YubiHSMSession(yubihsm, (short) 1, "password".toCharArray());
        for (int i = 1; i < 20; i++) {
            byte[] response = yubihsm.getRandom(session, i);
            assertEquals(i, response.length);
        }
        session.closeSession();
        logger.info("TEST END: testGetPseudoRandom()");
    }

}
