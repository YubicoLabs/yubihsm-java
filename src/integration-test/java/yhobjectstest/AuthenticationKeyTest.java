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
package yhobjectstest;

import com.yubico.hsm.YHCore;
import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.exceptions.YHAuthenticationException;
import com.yubico.hsm.yhconcepts.*;
import com.yubico.hsm.yhdata.YHObjectInfo;
import com.yubico.hsm.yhobjects.AuthenticationKey;
import com.yubico.hsm.yhobjects.YHObject;
import lombok.extern.slf4j.Slf4j;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@Slf4j
public class AuthenticationKeyTest {

    private static YubiHsm yubihsm;
    private static YHSession session;

    @BeforeClass
    public static void init() throws Exception {
        if (session == null) {
            openSession(new HttpBackend());
        }
        YHCore.resetDevice(session);
        yubihsm.close();

        Thread.sleep(1000);
        openSession(new HttpBackend());
    }

    private static void openSession(Backend backend) throws Exception {
        yubihsm = new YubiHsm(backend);
        session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
        session.authenticateSession();
    }

    @AfterClass
    public static void destroy() throws Exception {
        if(session != null) {
            session.closeSession();
            yubihsm.close();
        }
    }

    @Test
    public void testImportAuthenticationKey() throws Exception {
        log.info("TEST START: testGetAuthenticationKey()");
        List domains = Arrays.asList(2, 5, 8);
        List capabilities = Arrays.asList(Capability.SIGN_ECDSA, Capability.GET_OPAQUE);
        String label = "test_auth_key";
        short id = AuthenticationKey.importAuthenticationKey(session, (short) 0, label, domains,
                                                             Algorithm.AES128_YUBICO_AUTHENTICATION, capabilities, capabilities,
                                                             "foo123".toCharArray());

        try {
            final YHObjectInfo authKey = YHObject.getObjectInfo(session, id, Type.TYPE_AUTHENTICATION_KEY);
            assertEquals(id, authKey.getId());
            assertEquals(Type.TYPE_AUTHENTICATION_KEY, authKey.getType());
            assertEquals(domains, authKey.getDomains());
            assertEquals(Algorithm.AES128_YUBICO_AUTHENTICATION, authKey.getAlgorithm());
            assertEquals(Origin.YH_ORIGIN_IMPORTED, authKey.getOrigin());
            assertEquals(label, authKey.getLabel());
            assertEquals(capabilities.size(), authKey.getCapabilities().size());
            assertTrue(authKey.getCapabilities().containsAll(capabilities));
            assertEquals(capabilities.size(), authKey.getDelegatedCapabilities().size());
            assertTrue(authKey.getDelegatedCapabilities().containsAll(capabilities));
        } finally {
            YHObject.delete(session, id, Type.TYPE_AUTHENTICATION_KEY);
        }
        log.info("TEST END: testGetAuthenticationKey()");
    }

    @Test
    public void testImportAuthenticationKeyWithWrongParameters() throws Exception {
        log.info("TEST START: testImportAuthenticationKeyWithWrongParameters()");

        log.info("Test importing authentication key with null password");
        boolean exceptionThrown = false;
        try {
            AuthenticationKey.importAuthenticationKey(session, (short) 0, "", Arrays.asList(2, 5, 8), Algorithm.AES128_YUBICO_AUTHENTICATION,
                                                      Capability.ALL, null, null);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue(exceptionThrown);

        log.info("Test importing authentication key with empty password");
        exceptionThrown = false;
        try {
            AuthenticationKey.importAuthenticationKey(session, (short) 0, "", Arrays.asList(2, 5, 8), Algorithm.AES128_YUBICO_AUTHENTICATION,
                                                      Capability.ALL, null, new char[0]);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue(exceptionThrown);

        log.info("Test importing authentication key with an encryption key that is too short");
        byte[] enc = new byte[8];
        byte[] mac = new byte[16];
        new Random().nextBytes(enc);
        new Random().nextBytes(mac);
        exceptionThrown = false;
        try {
            AuthenticationKey.importAuthenticationKey(session, (short) 0, "", Arrays.asList(2, 5, 8), Algorithm.AES128_YUBICO_AUTHENTICATION,
                                                      Capability.ALL, null, enc, mac);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue(exceptionThrown);

        log.info("Test importing authentication key with a MAC key that is too short");
        exceptionThrown = false;
        try {
            AuthenticationKey.importAuthenticationKey(session, (short) 0, "", Arrays.asList(2, 5, 8), Algorithm.AES128_YUBICO_AUTHENTICATION,
                                                      Capability.ALL, null, mac, enc);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue(exceptionThrown);

        log.info("Test importing authentication key with an encryption key that is too long");
        enc = new byte[32];
        new Random().nextBytes(enc);
        exceptionThrown = false;
        try {
            AuthenticationKey.importAuthenticationKey(session, (short) 0, "", Arrays.asList(2, 5, 8), Algorithm.AES128_YUBICO_AUTHENTICATION,
                                                      Capability.ALL, null, enc, mac);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue(exceptionThrown);

        log.info("Test importing authentication key with a MAC key that is too long");
        exceptionThrown = false;
        try {
            AuthenticationKey.importAuthenticationKey(session, (short) 0, "", Arrays.asList(2, 5, 8), Algorithm.AES128_YUBICO_AUTHENTICATION,
                                                      Capability.ALL, null, mac, enc);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue(exceptionThrown);

        log.info("Test importing authentication key with null encryption key and null MAC key ");
        exceptionThrown = false;
        try {
            AuthenticationKey.importAuthenticationKey(session, (short) 0, "", Arrays.asList(2, 5, 8), Algorithm.AES128_YUBICO_AUTHENTICATION,
                                                      Capability.ALL, null, null, null);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue(exceptionThrown);

        log.info("TEST END: testImportAuthenticationKeyWithWrongParameters()");
    }

    @Test
    public void testAuthenticationKeyObject() throws Exception {
        log.info("TEST START: testAuthenticationKeyObject()");

        short id = AuthenticationKey
                .importAuthenticationKey(session, (short) 0, "", Arrays.asList(1, 2, 3, 4), Algorithm.AES128_YUBICO_AUTHENTICATION,
                                         Arrays.asList(Capability.SIGN_SSH_CERTIFICATE), null, "foo123".toCharArray());

        try {
            // Communicate over a session authenticated with the new authentication key
            YHSession session2 = new YHSession(yubihsm, id, "foo123".toCharArray());
            session2.authenticateSession();
            assertEquals(id, session2.getAuthenticationKeyID());
            assertEquals(YHSession.SessionStatus.AUTHENTICATED, session2.getStatus());
            byte[] data = new byte[32];
            new Random().nextBytes(data);
            byte[] response = YHCore.secureEcho(session2, data);
            assertTrue(Arrays.equals(response, data));
            session2.closeSession();
        } finally {
            YHObject.delete(session, id, Type.TYPE_AUTHENTICATION_KEY);
        }
        log.info("TEST END: testAuthenticationKeyObject()");
    }

    @Test
    public void testChangeAuthenticationKey() throws Exception {
        log.info("TEST START: testChangeAuthenticationKey()");

        ArrayList domains = new ArrayList(Arrays.asList(2, 5, 8));
        ArrayList capabilities = new ArrayList(Arrays.asList(Capability.SIGN_ECDSA, Capability.GET_OPAQUE, Capability.CHANGE_AUTHENTICATION_KEY));

        // Create a new authentication key
        final short id = AuthenticationKey.importAuthenticationKey(session, (short) 0, "", domains, Algorithm.AES128_YUBICO_AUTHENTICATION,
                                                                   capabilities, capabilities, "foo123".toCharArray());
        try {
            // Open an authenticated session with the new key, verify that communication works then close the session
            YHSession session1 = new YHSession(yubihsm, id, "foo123".toCharArray());
            session1.authenticateSession();
            assertEquals(id, session1.getAuthenticationKeyID());
            byte[] data = new byte[32];
            new Random().nextBytes(data);
            byte[] response = YHCore.secureEcho(session1, data);
            assertTrue(Arrays.equals(response, data));

            // Change the session key password
            AuthenticationKey.changeAuthenticationKey(session1, id, "bar123".toCharArray());
            session1.closeSession();
            assertEquals(YHSession.SessionStatus.CLOSED, session1.getStatus());

            // Open a new authenticated session with the old password. Expect failure
            session1 = new YHSession(yubihsm, id, "foo123".toCharArray());
            assertEquals(id, session1.getAuthenticationKeyID());
            try {
                session1.authenticateSession();
            } catch (Exception e) {
                assertTrue("Expected YHAuthenticationException. Instead got " + e.getClass().getName(),
                           (e instanceof YHAuthenticationException));
                YHAuthenticationException exp = (YHAuthenticationException) e;
                assertEquals(YHError.AUTHENTICATION_FAILED, exp.getYhError());
            }

            // Open a new authenticated session with the new password, verify that communication works then close the session
            session1 = new YHSession(yubihsm, id, "bar123".toCharArray());
            session1.authenticateSession();
            assertEquals(id, session1.getAuthenticationKeyID());
            assertEquals(YHSession.SessionStatus.AUTHENTICATED, session1.getStatus());
            response = YHCore.secureEcho(session1, data);
            assertTrue(Arrays.equals(response, data));
            session1.closeSession();
            assertEquals(YHSession.SessionStatus.CLOSED, session1.getStatus());
        } finally {
            YHObject.delete(session, id, Type.TYPE_AUTHENTICATION_KEY);
        }
        log.info("TEST END: testChangeAuthenticationKey()");
    }
}
