import com.yubico.YHCore;
import com.yubico.YHSession;
import com.yubico.YubiHsm;
import com.yubico.backend.Backend;
import com.yubico.backend.HttpBackend;
import com.yubico.internal.util.Utils;
import com.yubico.objects.yhconcepts.Command;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import static org.junit.Assert.*;

public class OptionsTest {
    Logger log = Logger.getLogger(OptionsTest.class.getName());

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
        YHCore.OptionValue original = YHCore.getForceAudit(session);

        YHCore.setForceAudit(session, YHCore.OptionValue.ON);
        assertEquals(YHCore.OptionValue.ON, YHCore.getForceAudit(session));

        YHCore.setForceAudit(session, YHCore.OptionValue.OFF);
        assertEquals(YHCore.OptionValue.OFF, YHCore.getForceAudit(session));

        YHCore.setForceAudit(session, original);
    }

    @Test
    public void testCommandOptionValueConversion() throws Exception {
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
    }

    @Test
    public void testCommandAudit() throws Exception {
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
    }

    // This test will run after all other tests because it needs to reset the device
    public static void testCommandAuditFix() throws Exception {
        Map<Command, YHCore.OptionValue> original = YHCore.getCommandAudit(session);
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
        yubihsm.close();
        session = null;

        Thread.sleep(1000);
        init();

        session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
        YHCore.setCommandAudit(session, original);
    }


}
