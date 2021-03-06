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
import com.yubico.hsm.exceptions.YHDeviceException;
import com.yubico.hsm.yhconcepts.Algorithm;
import com.yubico.hsm.yhconcepts.Capability;
import com.yubico.hsm.yhconcepts.Type;
import com.yubico.hsm.yhconcepts.YHError;
import com.yubico.hsm.yhobjects.AsymmetricKeyEc;
import com.yubico.hsm.yhobjects.YHObject;
import lombok.extern.slf4j.Slf4j;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.util.Arrays;
import java.util.Random;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@Slf4j
public class EcSignTest {

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
    public void testSignDataWithInsufficientPermissions() throws Exception {
        log.info("TEST START: testSignDataWithInsufficientPermissions()");
        final short id = 0x1234;
        KeyPair keypair = AsymmetricKeyTestHelper.importEcKey(session, id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.DERIVE_ECDH),
                                                              Algorithm.EC_P224, "secp224r1", false);
        try {
            final AsymmetricKeyEc key = new AsymmetricKeyEc(id, Algorithm.EC_P224);

            boolean exceptionThrown = false;
            try {
                signEcdsa(keypair.getPublic(), key, Algorithm.EC_ECDSA_SHA256, "SHA256withECDSA", new byte[0], false);
            } catch (YHDeviceException e) {
                exceptionThrown = true;
                assertEquals("Device returned incorrect error", YHError.INSUFFICIENT_PERMISSIONS, e.getYhError());
            }
            assertTrue("Succeeded to sign in spite of insufficient permissions", exceptionThrown);

        } finally {
            YHObject.delete(session, id, Type.TYPE_ASYMMETRIC_KEY);
        }
        log.info("TEST END: testSignDataWithInsufficientPermissions()");
    }

    @Test
    public void testSignData() throws Exception {
        log.info("TEST START: testSignData()");

        signEcdsaTest(Algorithm.EC_P224, "secp224r1", false);
        signEcdsaTest(Algorithm.EC_P256, "secp256r1", false);
        signEcdsaTest(Algorithm.EC_P384, "secp384r1", false);
        signEcdsaTest(Algorithm.EC_P521, "secp521r1", false);
        signEcdsaTest(Algorithm.EC_K256, "secp256k1", false);
        signEcdsaTest(Algorithm.EC_BP256, "brainpoolP256r1", true);
        signEcdsaTest(Algorithm.EC_BP384, "brainpoolP384r1", true);
        signEcdsaTest(Algorithm.EC_BP512, "brainpoolP512r1", true);

        log.info("TEST END: testSignData()");
    }


    private void signEcdsaTest(Algorithm keyAlgorithm, String curve, boolean brainpool) throws Exception {
        final short id = 0x1234;
        KeyPair keypair = AsymmetricKeyTestHelper.importEcKey(session, id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.SIGN_ECDSA),
                                                              keyAlgorithm, curve, brainpool);
        PublicKey publicKey = keypair.getPublic();
        try {
            final AsymmetricKeyEc key = new AsymmetricKeyEc(id, keyAlgorithm);

            byte[] data = new byte[0];
            signEcdsa(publicKey, key, Algorithm.EC_ECDSA_SHA1, "SHA1withECDSA", data, brainpool);
            signEcdsa(publicKey, key, Algorithm.EC_ECDSA_SHA256, "SHA256withECDSA", data, brainpool);
            signEcdsa(publicKey, key, Algorithm.EC_ECDSA_SHA384, "SHA384withECDSA", data, brainpool);
            signEcdsa(publicKey, key, Algorithm.EC_ECDSA_SHA512, "SHA512withECDSA", data, brainpool);

            data = "This is a signing test data".getBytes();
            signEcdsa(publicKey, key, Algorithm.EC_ECDSA_SHA1, "SHA1withECDSA", data, brainpool);
            signEcdsa(publicKey, key, Algorithm.EC_ECDSA_SHA256, "SHA256withECDSA", data, brainpool);
            signEcdsa(publicKey, key, Algorithm.EC_ECDSA_SHA384, "SHA384withECDSA", data, brainpool);
            signEcdsa(publicKey, key, Algorithm.EC_ECDSA_SHA512, "SHA512withECDSA", data, brainpool);

            data = new byte[2048];
            new Random().nextBytes(data);
            signEcdsa(publicKey, key, Algorithm.EC_ECDSA_SHA1, "SHA1withECDSA", data, brainpool);
            signEcdsa(publicKey, key, Algorithm.EC_ECDSA_SHA256, "SHA256withECDSA", data, brainpool);
            signEcdsa(publicKey, key, Algorithm.EC_ECDSA_SHA384, "SHA384withECDSA", data, brainpool);
            signEcdsa(publicKey, key, Algorithm.EC_ECDSA_SHA512, "SHA512withECDSA", data, brainpool);

        } finally {
            YHObject.delete(session, id, Type.TYPE_ASYMMETRIC_KEY);
        }
    }

    private void signEcdsa(PublicKey pubKey, AsymmetricKeyEc key, Algorithm signAlgorithm, String signAlgorithmStr, byte[] data, boolean brainpool) throws Exception {
        log.info("Test performing ECDSA signing on data of length " + data.length + " with EC key of algorithm " + key.getKeyAlgorithm().getName() +
                 " using algorithm " + signAlgorithm.getName());

        byte[] signature = key.signEcdsa(session, data, signAlgorithm);

        Signature sig;
        if(brainpool) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            sig = Signature.getInstance(signAlgorithmStr, "BC");
        } else {
            sig = Signature.getInstance(signAlgorithmStr);
        }
        sig.initVerify(pubKey);
        sig.update(data);
        assertTrue(sig.verify(signature));
    }
}
