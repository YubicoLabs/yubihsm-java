/*
 * Copyright 2019 Yubico AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import com.yubico.hsm.YHCore;
import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.internal.util.Utils;
import com.yubico.hsm.yhconcepts.Command;
import com.yubico.hsm.yhconcepts.DeviceOptionValue;
import lombok.extern.slf4j.Slf4j;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

@Slf4j
public class OptionsTest {

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
        testCommandAuditFix();
    }

    @Test
    public void testForceAudit() throws Exception {
        log.info("TEST START: testForceAudit()");
        DeviceOptionValue original = YHCore.getForceAudit(session);

        YHCore.setForceAudit(session, DeviceOptionValue.ON);
        assertEquals(DeviceOptionValue.ON, YHCore.getForceAudit(session));

        YHCore.setForceAudit(session, DeviceOptionValue.OFF);
        assertEquals(DeviceOptionValue.OFF, YHCore.getForceAudit(session));

        YHCore.setForceAudit(session, original);
        log.info("TEST END: testForceAudit()");
    }

    @Test
    public void testCommandOptionValueConversion() {
        log.info("TEST START: testCommandOptionValueConversion()");
        Map<Command, DeviceOptionValue> map = new HashMap<Command, DeviceOptionValue>();
        map.put(Command.SIGN_HMAC, DeviceOptionValue.ON);
        map.put(Command.VERIFY_HMAC, DeviceOptionValue.OFF);
        map.put(Command.GENERATE_HMAC_KEY, DeviceOptionValue.FIX);
        byte[] byteValue = {0x5a, 0x02, 0x53, 0x01, 0x5c, 0x00};

        byte[] retByteValue = Utils.geOptionTlvValue(map);
        assertEquals(map.size() * 2, retByteValue.length);
        for (int i = 0; i < retByteValue.length; i += 2) {
            Command c = Command.forId(retByteValue[i]);
            assertNotNull(c);
            assertTrue(map.containsKey(c));
            DeviceOptionValue retV = DeviceOptionValue.forValue(retByteValue[i + 1]);
            assertEquals(map.get(c), retV);
        }

        assertEquals(map, Utils.geOptionTlvValue(byteValue));
        log.info("TEST END: testCommandOptionValueConversion()");
    }

    @Test
    public void testCommandAudit() throws Exception {
        log.info("TEST START: testCommandAudit()");
        Map<Command, DeviceOptionValue> original = YHCore.getCommandAudit(session);

        Map<Command, DeviceOptionValue> testOptions = new HashMap<Command, DeviceOptionValue>();
        testOptions.put(Command.SIGN_HMAC, DeviceOptionValue.ON);
        testOptions.put(Command.VERIFY_HMAC, DeviceOptionValue.OFF);
        YHCore.setCommandAudit(session, testOptions);
        Map<Command, DeviceOptionValue> ret = YHCore.getCommandAudit(session);
        assertEquals(ret.get(Command.SIGN_HMAC), DeviceOptionValue.ON);
        assertEquals(ret.get(Command.VERIFY_HMAC), DeviceOptionValue.OFF);

        testOptions.put(Command.SIGN_HMAC, DeviceOptionValue.OFF);
        testOptions.put(Command.VERIFY_HMAC, DeviceOptionValue.ON);
        YHCore.setCommandAudit(session, testOptions);
        ret = YHCore.getCommandAudit(session);
        assertEquals(ret.get(Command.SIGN_HMAC), DeviceOptionValue.OFF);
        assertEquals(ret.get(Command.VERIFY_HMAC), DeviceOptionValue.ON);

        YHCore.setCommandAudit(session, original);
        log.info("TEST END: testCommandAudit()");
    }

    // This test will run after all other tests because it needs to reset the device
    public static void testCommandAuditFix() throws Exception {
        log.info("TEST START: testCommandAuditFix()");
        Map<Command, DeviceOptionValue> testOptions = new HashMap<Command, DeviceOptionValue>();
        testOptions.put(Command.GENERATE_HMAC_KEY, DeviceOptionValue.FIX);
        YHCore.setCommandAudit(session, testOptions);
        Map<Command, DeviceOptionValue> ret = YHCore.getCommandAudit(session);
        assertEquals(ret.get(Command.GENERATE_HMAC_KEY), DeviceOptionValue.FIX);
        testOptions.put(Command.GENERATE_HMAC_KEY, DeviceOptionValue.ON);
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
