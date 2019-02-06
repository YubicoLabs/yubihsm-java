import com.yubico.YubiHsm;
import com.yubico.YHSession;
import com.yubico.backend.Backend;
import com.yubico.backend.HttpBackend;
import com.yubico.exceptions.*;
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

public class YHSessionTest {

    Logger logger = Logger.getLogger(YHSessionTest.class.getName());

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
    public void testSessionCreation() throws InvalidKeySpecException, NoSuchAlgorithmException, YHDeviceException,
                                             YHInvalidResponseException, YHConnectionException, YHAuthenticationException,
                                             NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException,
                                             IllegalBlockSizeException, InvalidSession {
        logger.info("TEST START: testSessionCreation()");

        YHSession session1 = new YHSession(yubihsm, (short) 1, "password".toCharArray());
        assertNotNull(session1);
        assertNotNull(session1.getAuthenticationKey());
        assertEquals((byte) -1, session1.getSessionID());
        assertEquals(YHSession.SessionStatus.NOT_INITIALIZED, session1.getStatus());

        session1.createAuthenticatedSession();
        assertEquals((byte) 0, session1.getSessionID());
        assertEquals(YHSession.SessionStatus.AUTHENTICATED, session1.getStatus());


        YHSession session2 = new YHSession(yubihsm, (short) 1, "password".toCharArray());
        session2.createAuthenticatedSession();
        assertEquals((byte) 1, session2.getSessionID());
        assertEquals(YHSession.SessionStatus.AUTHENTICATED, session2.getStatus());
        session2.createAuthenticatedSession();
        assertEquals(YHSession.SessionStatus.AUTHENTICATED, session2.getStatus());


        YHSession session3 = new YHSession(yubihsm, (short) 1, "PASSWORD".toCharArray());
        assertNotNull(session3.getAuthenticationKey());
        assertEquals((byte) -1, session3.getSessionID());
        assertEquals(YHSession.SessionStatus.NOT_INITIALIZED, session3.getStatus());

        try {
            session3.createAuthenticatedSession();
        } catch (YHAuthenticationException e) {
            assertEquals(YHError.AUTHENTICATION_FAILED, e.getErrorCode());
        }

        session2.closeSession();
        assertEquals(YHSession.SessionStatus.CLOSED, session2.getStatus());

        session2.createAuthenticatedSession();
        assertEquals(YHSession.SessionStatus.AUTHENTICATED, session2.getStatus());
        session2.closeSession();

        byte[] data = new byte[32];
        new Random().nextBytes(data);
        byte[] response = yubihsm.secureEcho(session1, data);
        assertTrue(Utils.isByteArrayEqual(response, data));

        session1.closeSession();
        assertEquals(YHSession.SessionStatus.CLOSED, session1.getStatus());


        logger.info("TEST END: testSessionCreation()");
    }
}
