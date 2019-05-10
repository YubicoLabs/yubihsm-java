import com.yubico.hsm.YHCore;
import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.exceptions.YHAuthenticationException;
import com.yubico.hsm.yhconcepts.YHError;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.net.MalformedURLException;
import java.util.Arrays;
import java.util.Random;
import java.util.logging.Logger;

import static org.junit.Assert.*;

public class YHSessionTest {
    Logger log = Logger.getLogger(YHSessionTest.class.getName());

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
    public void testSessionCreation() throws Exception {
        log.info("TEST START: testSessionCreation()");

        YHSession session1 = new YHSession(yubihsm, (short) 1, "password".toCharArray());
        assertNotNull(session1);
        assertEquals((short) 1, session1.getAuthenticationKeyID());
        assertEquals((byte) -1, session1.getSessionID());
        assertEquals(YHSession.SessionStatus.NOT_INITIALIZED, session1.getStatus());

        session1.createAuthenticatedSession();
        assertNotEquals((byte) -1, session1.getSessionID());
        assertEquals(YHSession.SessionStatus.AUTHENTICATED, session1.getStatus());


        YHSession session2 = new YHSession(yubihsm, (short) 1, "password".toCharArray());
        session2.createAuthenticatedSession();
        assertEquals((short) 1, session2.getAuthenticationKeyID());
        assertNotEquals((byte) -1, session2.getSessionID());
        assertNotEquals(session1.getSessionID(), session2.getSessionID());
        assertEquals(YHSession.SessionStatus.AUTHENTICATED, session2.getStatus());
        session2.createAuthenticatedSession();
        assertEquals(YHSession.SessionStatus.AUTHENTICATED, session2.getStatus());


        YHSession session3 = new YHSession(yubihsm, (short) 1, "PASSWORD".toCharArray());
        assertEquals((short) 1, session3.getAuthenticationKeyID());
        assertEquals((byte) -1, session3.getSessionID());
        assertEquals(YHSession.SessionStatus.NOT_INITIALIZED, session3.getStatus());

        try {
            session3.createAuthenticatedSession();
        } catch (Exception e) {
            assertTrue("Expected YHAuthenticationException. Instead got " + e.getClass().getName(),
                       (e instanceof YHAuthenticationException));
            YHAuthenticationException exp = (YHAuthenticationException) e;
            assertEquals(YHError.AUTHENTICATION_FAILED, exp.getYhError());
        }

        session2.closeSession();
        assertEquals(YHSession.SessionStatus.CLOSED, session2.getStatus());
        try {
            session2.createAuthenticatedSession();
        } catch (Exception e) {
            assertTrue("Expected YHAuthenticationException. Instead got " + e.getClass().getName(),
                       (e instanceof YHAuthenticationException));
        }

        byte[] data = new byte[32];
        new Random().nextBytes(data);
        byte[] response = YHCore.secureEcho(session1, data);
        assertTrue(Arrays.equals(response, data));

        session1.closeSession();
        assertEquals(YHSession.SessionStatus.CLOSED, session1.getStatus());

        log.info("TEST END: testSessionCreation()");
    }
}
