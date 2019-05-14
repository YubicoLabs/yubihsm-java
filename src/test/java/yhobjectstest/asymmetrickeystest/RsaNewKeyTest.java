package yhobjectstest.asymmetrickeystest;

import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.exceptions.YHDeviceException;
import com.yubico.hsm.yhconcepts.*;
import com.yubico.hsm.yhdata.YHObjectInfo;
import com.yubico.hsm.yhobjects.AsymmetricKey;
import com.yubico.hsm.yhobjects.AsymmetricKeyRsa;
import com.yubico.hsm.yhobjects.YHObject;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

import static org.junit.Assert.*;

public class RsaNewKeyTest {
    Logger log = Logger.getLogger(RsaNewKeyTest.class.getName());

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
    public void testGenerateKey() throws Exception {
        log.info("TEST START: testGenerateKey()");
        generateKey(Algorithm.RSA_2048);
        generateKey(Algorithm.RSA_3072);
        generateKey(Algorithm.RSA_4096);
        log.info("TEST END: testGenerateKey()");
    }

    @Test
    public void testImportKeyWithWrongParameters() throws Exception {
        log.info("TEST START: testImportKeyWithWrongParameters()");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateCrtKeySpec ks = kf.getKeySpec(kp.getPrivate(), RSAPrivateCrtKeySpec.class);

        byte[] p = ks.getPrimeP().toByteArray();
        byte[] q = ks.getPrimeQ().toByteArray();

        log.info("Test importing an RSA key with a non Asymmetric key algorithm");
        boolean exceptionThrown = false;
        try {
            AsymmetricKeyRsa.importKey(session, (short) 0, "", Arrays.asList(2, 5), Algorithm.AES128_CCM_WRAP, Arrays.asList(Capability.SIGN_PKCS),
                                       p, q);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue("Succeeded in importing an RSA key even though the specified algorithm is not an asymmetric key algorithm", exceptionThrown);

        log.info("Test importing an EC key as an RSA key");
        exceptionThrown = false;
        try {
            AsymmetricKeyRsa.importKey(session, (short) 0, "", Arrays.asList(2, 5), Algorithm.EC_P224, Arrays.asList(Capability.SIGN_PKCS), p, q);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue("Succeeded in importing an EC key as an RSA key", exceptionThrown);

        log.info("Test importing an RSA key whose parameter does not match the specified RSA algorithm");
        exceptionThrown = false;
        try {
            AsymmetricKeyRsa.importKey(session, (short) 0, "", Arrays.asList(2, 5), Algorithm.RSA_3072, Arrays.asList(Capability.SIGN_PKCS), p, q);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue("Succeeded in importing an RSA key whose parameters do not match the specified algorithm", exceptionThrown);

        log.info("Test importing an RSA key without specifying one of the required private key primes");
        exceptionThrown = false;
        try {
            AsymmetricKeyRsa.importKey(session, (short) 0, "", Arrays.asList(2, 5), Algorithm.RSA_2048, Arrays.asList(Capability.SIGN_PKCS), p,
                                       null);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue("Succeeded in importing an RSA key in spite of missing private key", exceptionThrown);

        log.info("Test importing an RSA key with empty private key primes");
        exceptionThrown = false;
        try {
            AsymmetricKeyRsa.importKey(session, (short) 0, "", Arrays.asList(2, 5), Algorithm.RSA_2048, Arrays.asList(Capability.SIGN_PKCS),
                                       new byte[0], new byte[0]);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue("Succeeded in importing an RSA key in spite of missing private key", exceptionThrown);

        log.info("TEST END: testImportKeyWithWrongParameters()");
    }

    @Test
    public void testNonRsaKey() throws Exception {
        log.info("TEST START: testNonRsaKey()");

        log.info("Test creating an AsymmetricKeyRsa object without specifying an algorithm");
        boolean exceptionThrown = false;
        try {
            new AsymmetricKeyRsa((short) 0x1234, null);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue("Succeeded in creating an AsymmetricKeyRsa object in spite of missing algorithm", exceptionThrown);

        log.info("Test creating an AsymmetricKeyRsa object with a non RSA algorithm");
        exceptionThrown = false;
        try {
            new AsymmetricKeyRsa((short) 0x1234, Algorithm.EC_P256);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue("Succeeded in creating an AsymmetricKeyRsa object with a non RSA algorithm", exceptionThrown);

        log.info("Test creating an AsymmetricKeyRsa object for a key that does not exist in the device");
        AsymmetricKeyRsa key = new AsymmetricKeyRsa((short) 0x1234, Algorithm.RSA_2048);
        exceptionThrown = false;
        try {
            key.getPublicKey(session);
        } catch (YHDeviceException e) {
            exceptionThrown = true;
            assertEquals(YHError.OBJECT_NOT_FOUND, e.getYhError());
        }
        assertTrue("Succeeded in in retrieving a public key for an RSA key that does not exist on the device", exceptionThrown);

        log.info("TEST END: testNonRsaKey()");
    }

    @Test
    public void testImportKey() throws Exception {
        log.info("TEST START: testImportKey()");
        importRsaKeyTest(Algorithm.RSA_2048, 2048);
        importRsaKeyTest(Algorithm.RSA_3072, 3072);
        importRsaKeyTest(Algorithm.RSA_4096, 4096);
        log.info("TEST END: testImportKey()");
    }

    // -----------------------------------------------------------------------------------------

    private void generateKey(Algorithm algorithm) throws Exception {
        log.info("Test generating an RSA key using algorithm " + algorithm.getName());

        List domains = Arrays.asList(2, 5, 8);
        List capabilities = Arrays.asList(Capability.SIGN_PKCS, Capability.SIGN_ECDSA, Capability.SIGN_EDDSA);
        String label = "rsa_key";

        // Generate the key on the device
        short id = AsymmetricKey.generateAsymmetricKey(session, (short) 0, label, domains, algorithm, capabilities);

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

    private void importRsaKeyTest(Algorithm algorithm, int keysize) throws Exception {
        log.info("Test importing an RSA key with algorithm " + algorithm.getName());

        final List domains = Arrays.asList(2, 5, 8);
        final List capabilities = Arrays.asList(Capability.SIGN_PKCS);
        final String label = "imported_asym_key";
        final short id = 0x1234;

        AsymmetricKeyTestHelper.importRsaKey(session, id, label, domains, capabilities, algorithm, keysize);

        try {
            // Verify key property
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
