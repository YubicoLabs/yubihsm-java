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
import com.yubico.hsm.yhobjects.AsymmetricKeyRsa;
import com.yubico.hsm.yhobjects.YHObject;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.Random;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@Slf4j
public class RsaSignTest {

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

        short id = 0x1234;
        PublicKey pubKey = AsymmetricKeyTestHelper.importRsaKey(session, id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.SIGN_PKCS),
                                                                Algorithm.RSA_2048, 2048);
        try {
            final AsymmetricKeyRsa key = new AsymmetricKeyRsa(id, Algorithm.RSA_2048);

            boolean exceptionThrown = false;
            try {
                signPss(pubKey, key, Algorithm.RSA_MGF1_SHA256, "SHA256withRSA/PSS", "SHA-256", (short) 32, new byte[0]);
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

        signPkcs1Test(Algorithm.RSA_2048, 2048);
        signPkcs1Test(Algorithm.RSA_3072, 3072);
        signPkcs1Test(Algorithm.RSA_4096, 4096);

        signPssTest(Algorithm.RSA_2048, 2048);
        signPssTest(Algorithm.RSA_3072, 3072);
        signPssTest(Algorithm.RSA_4096, 4096);

        log.info("TEST END: testSignData()");
    }

    // ---------------------------------------------------------------------------------

    private void signPkcs1Test(Algorithm keyAlgorithm, int keysize) throws Exception {
        short id = 0x1234;
        PublicKey pubKey = AsymmetricKeyTestHelper.importRsaKey(session, id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.SIGN_PKCS),
                                                                keyAlgorithm, keysize);
        try {
            AsymmetricKeyRsa key = new AsymmetricKeyRsa(id, keyAlgorithm);

            byte[] data = new byte[0];
            signPkcs1(pubKey, key, Algorithm.RSA_PKCS1_SHA1, "SHA1withRSA", data);
            signPkcs1(pubKey, key, Algorithm.RSA_PKCS1_SHA256, "SHA256withRSA", data);
            signPkcs1(pubKey, key, Algorithm.RSA_PKCS1_SHA384, "SHA384withRSA", data);
            signPkcs1(pubKey, key, Algorithm.RSA_PKCS1_SHA512, "SHA512withRSA", data);

            data = "This is a signing test data".getBytes();
            signPkcs1(pubKey, key, Algorithm.RSA_PKCS1_SHA1, "SHA1withRSA", data);
            signPkcs1(pubKey, key, Algorithm.RSA_PKCS1_SHA256, "SHA256withRSA", data);
            signPkcs1(pubKey, key, Algorithm.RSA_PKCS1_SHA384, "SHA384withRSA", data);
            signPkcs1(pubKey, key, Algorithm.RSA_PKCS1_SHA512, "SHA512withRSA", data);

            data = new byte[2048];
            new Random().nextBytes(data);
            signPkcs1(pubKey, key, Algorithm.RSA_PKCS1_SHA1, "SHA1withRSA", data);
            signPkcs1(pubKey, key, Algorithm.RSA_PKCS1_SHA256, "SHA256withRSA", data);
            signPkcs1(pubKey, key, Algorithm.RSA_PKCS1_SHA384, "SHA384withRSA", data);
            signPkcs1(pubKey, key, Algorithm.RSA_PKCS1_SHA512, "SHA512withRSA", data);
        } finally {
            YHObject.delete(session, id, Type.TYPE_ASYMMETRIC_KEY);
        }
    }

    private void signPkcs1(PublicKey pubKey, AsymmetricKeyRsa key, Algorithm hashAlgorithm, String signatureAlgorithm, byte[] data) throws Exception {
        log.info("Test signing " + data.length + " bytes with RSA key of algorithm " + key.getKeyAlgorithm().getName() + " using RSA-PKCS#1v1.5");
        byte[] signature = key.signPkcs1(session, data, hashAlgorithm);

        Signature sig = Signature.getInstance(signatureAlgorithm);
        sig.initVerify(pubKey);
        sig.update(data);
        assertTrue(sig.verify(signature));
    }

    private void signPssTest(Algorithm keyAlgorithm, int keysize) throws Exception {
        short id = 0x1234;
        PublicKey pubKey = AsymmetricKeyTestHelper.importRsaKey(session, id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.SIGN_PSS),
                                                                keyAlgorithm, keysize);

        try {
            AsymmetricKeyRsa key = new AsymmetricKeyRsa(id, keyAlgorithm);

            byte[] data = new byte[0];
            signPss(pubKey, key, Algorithm.RSA_MGF1_SHA1, "SHA1withRSA/PSS", "SHA-1", (short) 32, data);
            signPss(pubKey, key, Algorithm.RSA_MGF1_SHA256, "SHA256withRSA/PSS", "SHA-256", (short) 32, data);
            signPss(pubKey, key, Algorithm.RSA_MGF1_SHA384, "SHA384withRSA/PSS", "SHA-384", (short) 32, data);
            signPss(pubKey, key, Algorithm.RSA_MGF1_SHA512, "SHA512withRSA/PSS", "SHA-512", (short) 32, data);

            data = "This is a signing test data".getBytes();
            signPss(pubKey, key, Algorithm.RSA_MGF1_SHA1, "SHA1withRSA/PSS", "SHA-1", (short) 32, data);
            signPss(pubKey, key, Algorithm.RSA_MGF1_SHA256, "SHA256withRSA/PSS", "SHA-256", (short) 32, data);
            signPss(pubKey, key, Algorithm.RSA_MGF1_SHA384, "SHA384withRSA/PSS", "SHA-384", (short) 32, data);
            signPss(pubKey, key, Algorithm.RSA_MGF1_SHA512, "SHA512withRSA/PSS", "SHA-512", (short) 32, data);

            data = new byte[2048];
            new Random().nextBytes(data);
            signPss(pubKey, key, Algorithm.RSA_MGF1_SHA1, "SHA1withRSA/PSS", "SHA-1", (short) 32, data);
            signPss(pubKey, key, Algorithm.RSA_MGF1_SHA256, "SHA256withRSA/PSS", "SHA-256", (short) 32, data);
            signPss(pubKey, key, Algorithm.RSA_MGF1_SHA384, "SHA384withRSA/PSS", "SHA-384", (short) 32, data);
            signPss(pubKey, key, Algorithm.RSA_MGF1_SHA512, "SHA512withRSA/PSS", "SHA-512", (short) 32, data);
        } finally {
            YHObject.delete(session, id, Type.TYPE_ASYMMETRIC_KEY);
        }
    }

    private void signPss(PublicKey pubKey, AsymmetricKeyRsa key, Algorithm signAlgorithm, String signAlgorithmStr, String hashAlgorithm,
                         short saltLength, byte[] data) throws Exception {
        log.info("Test signing " + data.length + " bytes with RSA key of algorithm " + key.getKeyAlgorithm().getName() + " using RSA-PSS");
        byte[] signature = key.signPss(session, signAlgorithm, saltLength, data);

        Security.addProvider(new BouncyCastleProvider());
        Signature sig = Signature.getInstance(signAlgorithmStr, "BC");
        MGF1ParameterSpec mgf1Param = new MGF1ParameterSpec(hashAlgorithm);
        PSSParameterSpec pssParam = new PSSParameterSpec(hashAlgorithm, "MGF1", mgf1Param, saltLength, 1);
        sig.setParameter(pssParam);
        sig.initVerify(pubKey);
        sig.update(data);
        assertTrue(sig.verify(signature));
    }

}
