import com.yubico.hsm.YHCore;
import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.internal.util.Utils;
import com.yubico.hsm.yhconcepts.Command;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import static org.junit.Assert.*;

public class OptionsTest {
    private static Logger log = Logger.getLogger(OptionsTest.class.getName());

    private static YubiHsm yubihsm;
    private static YHSession session;

    @BeforeClass
    public static void init() throws Exception {
        if (session == null) {
            Backend backend = new HttpBackend();
            yubihsm = new YubiHsm(backend);
            session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
            session.createAuthenticatedSession();
        }
    }

    @AfterClass
    public static void destroy() throws Exception {
        testCommandAuditFix();
        session.closeSession();
        yubihsm.close();
    }

    @Test
    public void testForceAudit() throws Exception {
        log.info("TEST START: testForceAudit()");
        YHCore.OptionValue original = YHCore.getForceAudit(session);

        YHCore.setForceAudit(session, YHCore.OptionValue.ON);
        assertEquals(YHCore.OptionValue.ON, YHCore.getForceAudit(session));

        YHCore.setForceAudit(session, YHCore.OptionValue.OFF);
        assertEquals(YHCore.OptionValue.OFF, YHCore.getForceAudit(session));

        YHCore.setForceAudit(session, original);
        log.info("TEST END: testForceAudit()");
    }

    @Test
    public void testCommandOptionValueConversion() {
        log.info("TEST START: testCommandOptionValueConversion()");
        Map<Command, YHCore.OptionValue> map = new HashMap<Command, YHCore.OptionValue>();
        map.put(Command.SIGN_HMAC, YHCore.OptionValue.ON);
        map.put(Command.VERIFY_HMAC, YHCore.OptionValue.OFF);
        map.put(Command.GENERATE_HMAC_KEY, YHCore.OptionValue.FIX);
        byte[] byteValue = {0x5a, 0x02, 0x53, 0x01, 0x5c, 0x00};

        byte[] retByteValue = Utils.geOptionTlvValue(map);
        assertEquals(map.size() * 2, retByteValue.length);
        for (int i = 0; i < retByteValue.length; i += 2) {
            Command c = Command.getCommand(retByteValue[i]);
            assertNotNull(c);
            assertTrue(map.containsKey(c));
            YHCore.OptionValue retV = YHCore.OptionValue.forValue(retByteValue[i + 1]);
            assertEquals(map.get(c), retV);
        }

        assertEquals(map, Utils.geOptionTlvValue(byteValue));
        log.info("TEST END: testCommandOptionValueConversion()");
    }

    @Test
    public void testCommandAudit() throws Exception {
        log.info("TEST START: testCommandAudit()");
        Map<Command, YHCore.OptionValue> original = YHCore.getCommandAudit(session);

        Map<Command, YHCore.OptionValue> testOptions = new HashMap<Command, YHCore.OptionValue>();
        testOptions.put(Command.SIGN_HMAC, YHCore.OptionValue.ON);
        testOptions.put(Command.VERIFY_HMAC, YHCore.OptionValue.OFF);
        YHCore.setCommandAudit(session, testOptions);
        Map<Command, YHCore.OptionValue> ret = YHCore.getCommandAudit(session);
        assertEquals(ret.get(Command.SIGN_HMAC), YHCore.OptionValue.ON);
        assertEquals(ret.get(Command.VERIFY_HMAC), YHCore.OptionValue.OFF);

        testOptions.put(Command.SIGN_HMAC, YHCore.OptionValue.OFF);
        testOptions.put(Command.VERIFY_HMAC, YHCore.OptionValue.ON);
        YHCore.setCommandAudit(session, testOptions);
        ret = YHCore.getCommandAudit(session);
        assertEquals(ret.get(Command.SIGN_HMAC), YHCore.OptionValue.OFF);
        assertEquals(ret.get(Command.VERIFY_HMAC), YHCore.OptionValue.ON);

        YHCore.setCommandAudit(session, original);
        log.info("TEST END: testCommandAudit()");
    }

    // This test will run after all other tests because it needs to reset the device
    public static void testCommandAuditFix() throws Exception {
        log.info("TEST START: testCommandAuditFix()");
        Map<Command, YHCore.OptionValue> testOptions = new HashMap<Command, YHCore.OptionValue>();
        testOptions.put(Command.GENERATE_HMAC_KEY, YHCore.OptionValue.FIX);
        YHCore.setCommandAudit(session, testOptions);
        Map<Command, YHCore.OptionValue> ret = YHCore.getCommandAudit(session);
        assertEquals(ret.get(Command.GENERATE_HMAC_KEY), YHCore.OptionValue.FIX);
        testOptions.put(Command.GENERATE_HMAC_KEY, YHCore.OptionValue.ON);
        boolean exceptionThrown = false;
        try {
            YHCore.setCommandAudit(session, testOptions);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue(exceptionThrown);

        YHCore.resetDevice(session);
        log.info("TEST END: testCommandAuditFix()");
    }


}
