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
package yhobjectstest.asymmetrickeystest;

import com.yubico.hsm.YHCore;
import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.yhconcepts.Algorithm;
import com.yubico.hsm.yhconcepts.Capability;
import com.yubico.hsm.yhconcepts.Type;
import com.yubico.hsm.yhobjects.AsymmetricKeyRsa;
import com.yubico.hsm.yhobjects.YHObject;
import lombok.extern.slf4j.Slf4j;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.PublicKey;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;

@Slf4j
public class RsaPublicKeyTest {

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
    public void testPublicKey() throws Exception {
        log.info("TEST START: testPublicKey()");
        getRsaPublicKeyTest(Algorithm.RSA_2048, 2048);
        getRsaPublicKeyTest(Algorithm.RSA_3072, 3072);
        getRsaPublicKeyTest(Algorithm.RSA_4096, 4096);
        log.info("TEST END: testPublicKey()");
    }

    private void getRsaPublicKeyTest(Algorithm algorithm, int keysize) throws Exception {
        log.info("Test retrieving the public part of an RSA key with algorithm " + algorithm.getName());
        short id = 0x1234;
        PublicKey pubKey = AsymmetricKeyTestHelper.importRsaKey(session, id, "", Arrays.asList(2, 5), Arrays.asList(Capability.SIGN_PSS), algorithm,
                                                                keysize);

        try {
            AsymmetricKeyRsa key = new AsymmetricKeyRsa(id, algorithm);
            PublicKey returnedPubKey = key.getRsaPublicKey(session);
            assertEquals(pubKey, returnedPubKey);
        } finally {
            YHObject.delete(session, id, Type.TYPE_ASYMMETRIC_KEY);
        }
    }
}
