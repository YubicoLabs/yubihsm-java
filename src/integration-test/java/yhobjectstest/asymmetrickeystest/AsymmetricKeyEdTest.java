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
import com.yubico.hsm.exceptions.YHDeviceException;
import com.yubico.hsm.yhconcepts.*;
import com.yubico.hsm.yhdata.YHObjectInfo;
import com.yubico.hsm.yhobjects.AsymmetricKey;
import com.yubico.hsm.yhobjects.AsymmetricKeyEd;
import com.yubico.hsm.yhobjects.YHObject;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

@Slf4j
public class AsymmetricKeyEdTest {

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

    // ---------------------------------------------------------
    //                  Key Generation
    // ---------------------------------------------------------

    @Test
    public void testGenerateKey() throws Exception {
        log.info("TEST START: testGenerateKey()");

        final List domains = Arrays.asList(2, 5, 8);
        final List capabilities = Arrays.asList(Capability.SIGN_PKCS, Capability.SIGN_ECDSA, Capability.SIGN_EDDSA);
        final String label = "asym_key";

        // Generate the key on the device
        final short id = AsymmetricKey.generateAsymmetricKey(session, (short) 0, label, domains, Algorithm.EC_ED25519, capabilities);

        try {
            // Verify key properties
            final YHObjectInfo key = YHObject.getObjectInfo(session, id, Type.TYPE_ASYMMETRIC_KEY);
            assertNotEquals(0, key.getId());
            assertEquals(id, key.getId());
            assertEquals(Type.TYPE_ASYMMETRIC_KEY, key.getType());
            assertEquals(domains, key.getDomains());
            assertEquals(Algorithm.EC_ED25519, key.getAlgorithm());
            assertEquals(Origin.YH_ORIGIN_GENERATED, key.getOrigin());
            assertEquals(label, key.getLabel());
            assertEquals(capabilities.size(), key.getCapabilities().size());
            assertTrue(key.getCapabilities().containsAll(capabilities));
            assertEquals(0, key.getDelegatedCapabilities().size());
        } finally {
            YHObject.delete(session, id, Type.TYPE_ASYMMETRIC_KEY);
        }

        log.info("TEST END: testGenerateKey()");
    }

    // -------------------------------------------------------------------------------
    //                               Key Import
    // -------------------------------------------------------------------------------

    @Test
    public void testImportKeyWithWrongParameters() throws Exception {
        log.info("TEST START: testImportKeyWithWrongParameters()");

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Ed25519KeyPairGenerator keyPairGenerator = new Ed25519KeyPairGenerator();
        keyPairGenerator.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair asymmetricCipherKeyPair = keyPairGenerator.generateKeyPair();
        Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters) asymmetricCipherKeyPair.getPrivate();
        byte[] d = privateKey.getEncoded();

        // Test importing the key with a non Asymmetric key algorithm
        boolean exceptionThrown = false;
        try {
            AsymmetricKeyEd.importKey(session, (short) 0, "", Arrays.asList(2), Algorithm.AES128_CCM_WRAP, Arrays.asList(Capability.SIGN_EDDSA), d);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue("Succeeded in importing an ED key even though the specified algorithm is a non asymmetric key algorithm", exceptionThrown);

        // Test importing an RSA key as an ED key
        exceptionThrown = false;
        try {
            AsymmetricKeyEd.importKey(session, (short) 0, "", Arrays.asList(2), Algorithm.RSA_3072, Arrays.asList(Capability.SIGN_EDDSA), d);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue("Succeeded in importing an RSA key as an ED key", exceptionThrown);

        // Test importing an ED key without specifying the private key
        exceptionThrown = false;
        try {
            AsymmetricKeyEd
                    .importKey(session, (short) 0, "", Arrays.asList(2), Algorithm.EC_P256, Arrays.asList(Capability.SIGN_EDDSA), (byte[]) null);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue("Succeeded in importing an ED key in spite of missing private key", exceptionThrown);

        // Test importing an ED key without specifying the private key
        exceptionThrown = false;
        try {
            AsymmetricKeyEd.importKey(session, (short) 0, "", Arrays.asList(2), Algorithm.EC_P256, Arrays.asList(Capability.SIGN_EDDSA), new byte[0]);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue("Succeeded in importing an ED key in spite of missing private key", exceptionThrown);

        log.info("TEST END: testImportKeyWithWrongParameters()");
    }

    @Test
    public void testNonEdKey() throws Exception {
        log.info("TEST START: testNonEdKey()");

        // Test creating an AsymmetricKeyEd object without algorithm
        boolean exceptionThrown = false;
        try {
            new AsymmetricKeyEd((short) 0x1234, null);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue("Succeeded in creating an AsymmetricKeyEd object in spite of missing algorithm", exceptionThrown);

        // Test creating an AsymmetricKeyEd object with a non ED algorithm
        exceptionThrown = false;
        try {
            new AsymmetricKeyEd((short) 0x1234, Algorithm.RSA_2048);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue("Succeeded in creating an AsymmetricKeyEd object with a non ED algorithm", exceptionThrown);

        // Test creating an AsymmetricKeyEd object for a key that does not exist in the device
        AsymmetricKeyEd key = new AsymmetricKeyEd((short) 0x1234, Algorithm.EC_ED25519);
        exceptionThrown = false;
        try {
            key.getPublicKey(session);
        } catch (YHDeviceException e) {
            exceptionThrown = true;
            assertEquals(YHError.OBJECT_NOT_FOUND, e.getYhError());
        }
        assertTrue("Succeeded in retrieving a public key of an ED key that does not exist on the device", exceptionThrown);

        log.info("TEST END: testNonEdKey()");
    }

    @Test
    public void testImportKey() throws Exception {
        log.info("TEST START: testImportKey()");

        final List domains = Arrays.asList(2, 5, 8);
        final List capabilities = Arrays.asList(Capability.SIGN_EDDSA);
        final String label = "imported_asym_key";
        short id = 0x1234;


        importEdKey(id, label, domains, capabilities);

        try {

            final YHObjectInfo key = YHObject.getObjectInfo(session, id, Type.TYPE_ASYMMETRIC_KEY);
            assertEquals(id, key.getId());
            assertEquals(Type.TYPE_ASYMMETRIC_KEY, key.getType());
            assertEquals(domains, key.getDomains());
            assertEquals(Algorithm.EC_ED25519, key.getAlgorithm());
            assertEquals(Origin.YH_ORIGIN_IMPORTED, key.getOrigin());
            assertEquals(label, key.getLabel());
            assertEquals(capabilities.size(), key.getCapabilities().size());
            assertTrue(key.getCapabilities().containsAll(capabilities));
            assertEquals(0, key.getDelegatedCapabilities().size());
        } finally {
            YHObject.delete(session, id, Type.TYPE_ASYMMETRIC_KEY);
        }

        log.info("TEST END: testImportKey()");
    }

    private Ed25519PublicKeyParameters importEdKey(short id, String label, List<Integer> domains, List<Capability> capabilities) throws Exception {

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Ed25519KeyPairGenerator keyPairGenerator = new Ed25519KeyPairGenerator();
        keyPairGenerator.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair asymmetricCipherKeyPair = keyPairGenerator.generateKeyPair();
        Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters) asymmetricCipherKeyPair.getPrivate();
        Ed25519PublicKeyParameters publicKey = (Ed25519PublicKeyParameters) asymmetricCipherKeyPair.getPublic();

        AsymmetricKeyEd.importKey(session, id, label, domains, Algorithm.EC_ED25519, capabilities, privateKey);
        return publicKey;
    }

    // ----------------------------------------------------------------------------
    //                                 Public Key
    // ----------------------------------------------------------------------------

    @Test
    public void testPublicKey() throws Exception {
        log.info("TEST START: testPublicKey()");

        final short id = 0x1234;
        Ed25519PublicKeyParameters pubKey = importEdKey(id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.SIGN_EDDSA));

        try {
            final AsymmetricKeyEd key = new AsymmetricKeyEd(id, Algorithm.EC_ED25519);
            byte[] returnedPubKeyBytes = key.getPublicKey(session);
            assertArrayEquals(pubKey.getEncoded(), returnedPubKeyBytes);

        } finally {
            YHObject.delete(session, id, Type.TYPE_ASYMMETRIC_KEY);
        }

        log.info("TEST END: testPublicKey()");
    }

    // ----------------------------------------------------------------------------------------------------
    //                                         Signing
    // ----------------------------------------------------------------------------------------------------

    @Test
    public void testSignDataWithInsufficientPermissions() throws Exception {
        log.info("TEST START: testSignDataWithInsufficientPermissions()");
        short id = 0x1234;
        importEdKey(id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.GET_OPAQUE));
        try {
            AsymmetricKeyEd key = new AsymmetricKeyEd(id, Algorithm.EC_ED25519);
            byte[] data = "test sign data".getBytes();

            boolean exceptionThrown = false;
            try {
                key.signEddsa(session, data);
            } catch (YHDeviceException e) {
                exceptionThrown = true;
                assertEquals("Device returned incorrect error", YHError.INSUFFICIENT_PERMISSIONS, e.getYhError());
            }
            assertTrue("Succeeded in signing in spite of insufficient permissions", exceptionThrown);

        } finally {
            YHObject.delete(session, id, Type.TYPE_ASYMMETRIC_KEY);
        }
        log.info("TEST END: testSignDataWithInsufficientPermissions()");
    }

    @Test
    public void testSignData() throws Exception {
        log.info("TEST START: testSignData()");

        final short id = 0x1234;
        Ed25519PublicKeyParameters pubKey = importEdKey(id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.SIGN_EDDSA));

        try {
            final AsymmetricKeyEd key = new AsymmetricKeyEd(id, Algorithm.EC_ED25519);

            signDataTest(key, pubKey, new byte[0]);
            signDataTest(key, pubKey, "This is a signing test data".getBytes());

        } finally {
            YHObject.delete(session, id, Type.TYPE_ASYMMETRIC_KEY);
        }

        log.info("TEST END: testSignData()");
    }

    private void signDataTest(AsymmetricKeyEd key, Ed25519PublicKeyParameters pubKey, byte[] data) throws Exception {

        byte[] signature = key.signEddsa(session, data);
        assertEquals(64, signature.length);

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        Signer signer = new Ed25519Signer();
        signer.init(false, pubKey);
        signer.update(data, 0, data.length);
        assertTrue(signer.verifySignature(signature));
    }
}
