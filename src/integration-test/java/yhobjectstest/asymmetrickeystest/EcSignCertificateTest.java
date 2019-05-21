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

import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.yhconcepts.Algorithm;
import com.yubico.hsm.yhconcepts.Capability;
import com.yubico.hsm.yhobjects.AsymmetricKey;
import com.yubico.hsm.yhobjects.Opaque;
import com.yubico.hsm.yhobjects.YHObject;
import lombok.extern.slf4j.Slf4j;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

@Slf4j
public class EcSignCertificateTest {

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
    public void testSigningAttestationCertificate() throws Exception {
        log.info("TEST START: testSigningAttestationCertificate()");
        signAttestationCert(Algorithm.EC_P224, "secp224r1", Algorithm.EC_P224, false);
        signAttestationCert(Algorithm.EC_P224, "secp224r1", Algorithm.EC_P256, false);
        signAttestationCert(Algorithm.EC_P224, "secp224r1", Algorithm.RSA_2048, false);

        signAttestationCert(Algorithm.EC_P256, "secp256r1", Algorithm.EC_P256, false);
        signAttestationCert(Algorithm.EC_P256, "secp256r1", Algorithm.EC_P384, false);
        signAttestationCert(Algorithm.EC_P256, "secp256r1", Algorithm.RSA_2048, false);

        signAttestationCert(Algorithm.EC_P384, "secp384r1", Algorithm.EC_P384, false);
        signAttestationCert(Algorithm.EC_P384, "secp384r1", Algorithm.EC_P521, false);
        signAttestationCert(Algorithm.EC_P384, "secp384r1", Algorithm.RSA_2048, false);

        signAttestationCert(Algorithm.EC_P521, "secp521r1", Algorithm.EC_P521, false);
        signAttestationCert(Algorithm.EC_P521, "secp521r1", Algorithm.EC_K256, false);
        signAttestationCert(Algorithm.EC_P521, "secp521r1", Algorithm.RSA_2048, false);

        signAttestationCert(Algorithm.EC_K256, "secp256k1", Algorithm.EC_K256, false);
        signAttestationCert(Algorithm.EC_K256, "secp256k1", Algorithm.EC_BP256, false);
        signAttestationCert(Algorithm.EC_K256, "secp256k1", Algorithm.RSA_2048, false);

        signAttestationCert(Algorithm.EC_BP256, "brainpoolP256r1", Algorithm.EC_BP256, true);
        signAttestationCert(Algorithm.EC_BP256, "brainpoolP256r1", Algorithm.EC_BP384, true);
        signAttestationCert(Algorithm.EC_BP256, "brainpoolP256r1", Algorithm.RSA_2048, true);

        signAttestationCert(Algorithm.EC_BP384, "brainpoolP384r1", Algorithm.EC_BP384, true);
        signAttestationCert(Algorithm.EC_BP384, "brainpoolP384r1", Algorithm.EC_BP512, true);
        signAttestationCert(Algorithm.EC_BP384, "brainpoolP384r1", Algorithm.RSA_2048, true);

        signAttestationCert(Algorithm.EC_BP512, "brainpoolP512r1", Algorithm.EC_BP512, true);
        signAttestationCert(Algorithm.EC_BP512, "brainpoolP512r1", Algorithm.EC_P224, true);
        signAttestationCert(Algorithm.EC_BP512, "brainpoolP512r1", Algorithm.RSA_2048, true);
        log.info("TEST END: testSigningAttestationCertificate()");
    }

    private void signAttestationCert(Algorithm key1Algorithm, String key1Curve, Algorithm key2Algorithm, boolean brainpool) throws Exception {
        log.info("Test signing attestation certificate using EC key with algorithm " + key1Algorithm.getName());
        short attestingKeyid = 0x5678;
        short attestedKeyid = 0x0123;
        try {
            KeyPair attestingKeypair = AsymmetricKeyTestHelper.importEcKey(session, attestingKeyid, "", Arrays.asList(2, 5, 8),
                                                                           Arrays.asList(Capability.SIGN_ATTESTATION_CERTIFICATE), key1Algorithm,
                                                                           key1Curve, brainpool);
            AsymmetricKey attestingKey = new AsymmetricKey(attestingKeyid, key1Algorithm);

            AsymmetricKey.generateAsymmetricKey(session, attestedKeyid, "", Arrays.asList(2, 5, 8), key2Algorithm,
                                                Arrays.asList(Capability.SIGN_ECDSA));

            boolean exceptionThrown = false;
            try {
                attestingKey.signAttestationCertificate(session, attestedKeyid);
            } catch (UnsupportedOperationException e) {
                exceptionThrown = true;
            }
            assertTrue(exceptionThrown);

            Opaque.importCertificate(session, attestingKeyid, "", Arrays.asList(2, 5, 8), AsymmetricKeyTestHelper.getTestCertificate());
            X509Certificate attestationCert = attestingKey.signAttestationCertificate(session, attestedKeyid);

            try {
                attestationCert.verify(attestingKeypair.getPublic());
            } catch (Exception e) {
                fail("Attestation certificate was not valid");
            }

        } finally {
            YHObject.delete(session, attestedKeyid, AsymmetricKey.TYPE);
            YHObject.delete(session, attestingKeyid, AsymmetricKey.TYPE);
            YHObject.delete(session, attestingKeyid, Opaque.TYPE);
        }
    }

}
