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
import com.yubico.hsm.yhconcepts.*;
import com.yubico.hsm.yhdata.YHObjectInfo;
import com.yubico.hsm.yhobjects.AsymmetricKey;
import com.yubico.hsm.yhobjects.AsymmetricKeyEc;
import com.yubico.hsm.yhobjects.YHObject;
import lombok.extern.slf4j.Slf4j;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

@Slf4j
public class EcNewKeyTest {

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
    public void testGenerateKey() throws Exception {
        log.info("TEST START: testGenerateKey()");
        generateKey(Algorithm.EC_P224);
        generateKey(Algorithm.EC_P256);
        generateKey(Algorithm.EC_P384);
        generateKey(Algorithm.EC_P521);
        generateKey(Algorithm.EC_K256);
        generateKey(Algorithm.EC_BP256);
        generateKey(Algorithm.EC_BP384);
        generateKey(Algorithm.EC_BP512);
        log.info("TEST END: testGenerateKey()");
    }

    private void generateKey(Algorithm algorithm) throws Exception {
        log.info("Test generating EC key with algorithm " + algorithm.getName());
        final List domains = Arrays.asList(2, 5, 8);
        final List capabilities = Arrays.asList(Capability.SIGN_PKCS, Capability.SIGN_ECDSA, Capability.SIGN_EDDSA);
        final String label = "asym_key";

        // Generate the key on the device
        final short id = AsymmetricKey.generateAsymmetricKey(session, (short) 0, label, domains, algorithm, capabilities);

        try {
            // Verify key properties
            final YHObjectInfo key = YHObject.getObjectInfo(session, id, Type.TYPE_ASYMMETRIC_KEY);
            assertNotEquals(0, key.getId());
            assertEquals(id, key.getId());
            assertEquals(Type.TYPE_ASYMMETRIC_KEY, key.getType());
            assertEquals(domains, key.getDomains());
            assertEquals(algorithm, key.getAlgorithm());
            assertEquals(Origin.YH_ORIGIN_GENERATED, key.getOrigin());
            assertEquals(label, key.getLabel());
            assertEquals(capabilities.size(), key.getCapabilities().size());
            assertTrue(key.getCapabilities().containsAll(capabilities));
            assertEquals(0, key.getDelegatedCapabilities().size());
        } finally {
            YHObject.delete(session, id, Type.TYPE_ASYMMETRIC_KEY);
        }
    }

    // -------------------------------------------------------------------------------
    //                               Key Import
    // -------------------------------------------------------------------------------

    @Test
    public void testImportKeyWithWrongParameters() throws Exception {
        log.info("TEST START: testImportKeyWithWrongParameters()");

        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = generator.generateKeyPair();
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        byte[] d = privateKey.getS().toByteArray();

        log.info("Test importing an EC key with a non Asymmetric key algorithm");
        boolean exceptionThrown = false;
        try {
            AsymmetricKeyEc.importKey(session, (short) 0, "", Arrays.asList(2), Algorithm.AES128_CCM_WRAP, Arrays.asList(Capability.SIGN_ECDSA), d);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue("Succeeded in importing an EC key even though the specified algorithm is a non asymmetric key algorithm", exceptionThrown);

        log.info("Test importing and RSA key as an EC key");
        exceptionThrown = false;
        try {
            AsymmetricKeyEc.importKey(session, (short) 0, "", Arrays.asList(2), Algorithm.RSA_3072, Arrays.asList(Capability.SIGN_ECDSA), d);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue("Succeeded in importing an RSA key as an EC key", exceptionThrown);

        log.info("Test importing an EC key whose parameter does not match the specified EC algorithm");
        exceptionThrown = false;
        try {
            AsymmetricKeyEc.importKey(session, (short) 0, "", Arrays.asList(2, 5), Algorithm.EC_P224, Arrays.asList(Capability.SIGN_ECDSA), d);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue("Succeeded in importing an EC key whose parameters do not match the specified algorithm", exceptionThrown);

        log.info("Test importing an EC key with null private key");
        exceptionThrown = false;
        try {
            AsymmetricKeyEc.importKey(session, (short) 0, "", Arrays.asList(2), Algorithm.EC_P256, Arrays.asList(Capability.SIGN_ECDSA),
                                      (byte[]) null);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue("Succeeded in importing an EC key in spite of missing private key", exceptionThrown);

        log.info("Test importing an EC key with an empty private key");
        exceptionThrown = false;
        try {
            AsymmetricKeyEc.importKey(session, (short) 0, "", Arrays.asList(2), Algorithm.EC_P256, Arrays.asList(Capability.SIGN_ECDSA), new byte[0]);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue("Succeeded in importing an EC key in spite of missing private key", exceptionThrown);

        log.info("TEST END: testImportKeyWithWrongParameters()");
    }

    @Test
    public void testNonEcKey() throws Exception {
        log.info("TEST START: testNonEcKey()");

        log.info("Test creating an AsymmetricKeyEc object without specifying an algorithm");
        boolean exceptionThrown = false;
        try {
            new AsymmetricKeyEc((short) 0x1234, null);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue("Succeeded in creating an AsymmetricKeyEc object in spite of missing algorithm", exceptionThrown);

        log.info("Test creating an AsymmetricKeyEc object with a non EC algorithm");
        exceptionThrown = false;
        try {
            new AsymmetricKeyEc((short) 0x1234, Algorithm.RSA_2048);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue("Succeeded in creating an AsymmetricKeyEc object with a non EC algorithm", exceptionThrown);

        log.info("Test creating an AsymmetricKeyEc object for a key that does not exist in the device");
        AsymmetricKeyEc key = new AsymmetricKeyEc((short) 0x1234, Algorithm.EC_P256);
        exceptionThrown = false;
        try {
            key.getPublicKey(session);
        } catch (YHDeviceException e) {
            exceptionThrown = true;
            assertEquals(YHError.OBJECT_NOT_FOUND, e.getYhError());
        }
        assertTrue("Succeeded in retrieving a public key of an EC key that does not exist on the device", exceptionThrown);

        log.info("TEST END: testNonEcKey()");
    }

    @Test
    public void testImportKey() throws Exception {
        log.info("TEST START: testImportKey()");
        importEcKeyTest(Algorithm.EC_P224, "secp224r1", false);
        importEcKeyTest(Algorithm.EC_P256, "secp256r1", false);
        importEcKeyTest(Algorithm.EC_P384, "secp384r1", false);
        importEcKeyTest(Algorithm.EC_P521, "secp521r1", false);
        importEcKeyTest(Algorithm.EC_K256, "secp256k1", false);
        importEcKeyTest(Algorithm.EC_BP256, "brainpoolP256r1", true);
        importEcKeyTest(Algorithm.EC_BP384, "brainpoolP384r1", true);
        importEcKeyTest(Algorithm.EC_BP512, "brainpoolP512r1", true);
        log.info("TEST END: testImportKey()");
    }

    private void importEcKeyTest(Algorithm algorithm, String curve, boolean brainpool) throws Exception {
        log.info("Test importing EC key with algorithm " + algorithm.getName());
        final List domains = Arrays.asList(2, 5, 8);
        final List capabilities = Arrays.asList(Capability.SIGN_ECDSA);
        final String label = "imported_asym_key";
        final short id = 0x1234;

        AsymmetricKeyTestHelper.importEcKey(session, id, label, domains, capabilities, algorithm, curve, brainpool);

        try {
            // Verify key properties
            final YHObjectInfo key = YHObject.getObjectInfo(session, id, Type.TYPE_ASYMMETRIC_KEY);
            assertEquals(id, key.getId());
            assertEquals(Type.TYPE_ASYMMETRIC_KEY, key.getType());
            assertEquals(domains, key.getDomains());
            assertEquals(algorithm, key.getAlgorithm());
            assertEquals(Origin.YH_ORIGIN_IMPORTED, key.getOrigin());
            assertEquals(label, key.getLabel());
            assertEquals(capabilities.size(), key.getCapabilities().size());
            assertTrue(key.getCapabilities().containsAll(capabilities));
            assertEquals(0, key.getDelegatedCapabilities().size());
        } finally {
            YHObject.delete(session, id, Type.TYPE_ASYMMETRIC_KEY);
        }
    }

}
