import com.yubico.hsm.YHCore;
import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.yhdata.LogData;
import com.yubico.hsm.yhdata.LogEntry;
import lombok.extern.slf4j.Slf4j;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.Arrays;
import java.util.Random;

import static org.junit.Assert.*;

@Slf4j
public class YHCoreTest {

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
    public void testSecureEcho() throws Exception {
        log.info("TEST START: testAuthenticatedEcho()");
        for (int i = 0; i < 5; i++) {
            byte[] data = new byte[32];
            new Random().nextBytes(data);
            byte[] response = YHCore.secureEcho(session, data);
            assertTrue(Arrays.equals(response, data));
        }
        log.info("TEST END: testAuthenticatedEcho()");
    }

    @Test
    public void testGetPseudoRandom() throws Exception {
        log.info("TEST START: testGetPseudoRandom()");
        for (int i = 1; i < 20; i++) {
            byte[] response = YHCore.getPseudoRandom(session, i);
            assertEquals(i, response.length);
        }
        log.info("TEST END: testGetPseudoRandom()");
    }

    @Test
    public void testLogEntries() throws Exception {
        log.info("TEST START: testLogEntries()");
        LogData logData = YHCore.getAuditLogData(session);

        assertTrue(logData.getUnloggedBootEvents() >= 0);
        assertTrue(logData.getUnloggedAuthenticationEvents() >= 0);
        assertFalse(logData.getLogEntries().isEmpty());

        LogEntry lastEntry = logData.getLastLogEntry();
        YHCore.setAuditLogIndex(session, lastEntry.getItemNumber());
        logData = YHCore.getAuditLogData(session);
        assertEquals(lastEntry.getItemNumber() + 1, logData.getFirstLogEntry().getItemNumber());

        log.info("TEST END: testLogEntries()");
    }

}
