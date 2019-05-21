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
import com.yubico.hsm.exceptions.YHAuthenticationException;
import com.yubico.hsm.yhconcepts.YHError;
import lombok.extern.slf4j.Slf4j;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.net.MalformedURLException;
import java.util.Arrays;
import java.util.Random;

import static org.junit.Assert.*;

@Slf4j
public class YHSessionTest {

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

        session1.authenticateSession();
        assertNotEquals((byte) -1, session1.getSessionID());
        assertEquals(YHSession.SessionStatus.AUTHENTICATED, session1.getStatus());


        YHSession session2 = new YHSession(yubihsm, (short) 1, "password".toCharArray());
        session2.authenticateSession();
        assertEquals((short) 1, session2.getAuthenticationKeyID());
        assertNotEquals((byte) -1, session2.getSessionID());
        assertNotEquals(session1.getSessionID(), session2.getSessionID());
        assertEquals(YHSession.SessionStatus.AUTHENTICATED, session2.getStatus());
        session2.authenticateSession();
        assertEquals(YHSession.SessionStatus.AUTHENTICATED, session2.getStatus());


        YHSession session3 = new YHSession(yubihsm, (short) 1, "PASSWORD".toCharArray());
        assertEquals((short) 1, session3.getAuthenticationKeyID());
        assertEquals((byte) -1, session3.getSessionID());
        assertEquals(YHSession.SessionStatus.NOT_INITIALIZED, session3.getStatus());

        boolean exceptionThrown = false;
        try {
            session3.authenticateSession();
        } catch (Exception e) {
            assertTrue("Expected YHAuthenticationException. Instead got " + e.getClass().getName(),
                       (e instanceof YHAuthenticationException));
            YHAuthenticationException exp = (YHAuthenticationException) e;
            assertEquals(YHError.AUTHENTICATION_FAILED, exp.getYhError());
            exceptionThrown = true;
        }
        assertTrue(exceptionThrown);

        session2.closeSession();
        assertEquals(YHSession.SessionStatus.CLOSED, session2.getStatus());
        exceptionThrown = false;
        try {
            session2.authenticateSession();
        } catch (Exception e) {
            assertTrue("Expected YHAuthenticationException. Instead got " + e.getClass().getName(),
                       (e instanceof YHAuthenticationException));
            exceptionThrown = true;
        }
        assertTrue(exceptionThrown);

        byte[] data = new byte[32];
        new Random().nextBytes(data);
        byte[] response = YHCore.secureEcho(session1, data);
        assertTrue(Arrays.equals(response, data));

        session1.closeSession();
        assertEquals(YHSession.SessionStatus.CLOSED, session1.getStatus());

        log.info("TEST END: testSessionCreation()");
    }
}
