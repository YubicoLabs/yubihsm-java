package AsymmetricKeyTest;

import com.yubico.YHSession;
import com.yubico.YubiHsm;
import com.yubico.backend.Backend;
import com.yubico.backend.HttpBackend;
import com.yubico.exceptions.*;
import com.yubico.objects.yhconcepts.Algorithm;
import com.yubico.objects.yhconcepts.Capability;
import com.yubico.objects.yhconcepts.ObjectOrigin;
import com.yubico.objects.yhconcepts.ObjectType;
import com.yubico.objects.yhobjects.AsymmetricKey;
import com.yubico.objects.yhobjects.AsymmetricKeyRsa;
import com.yubico.objects.yhobjects.YHObject;
import com.yubico.objects.yhobjects.YHObjectInfo;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.net.MalformedURLException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

import static org.junit.Assert.*;

public class RsaNewKeyTest {
    Logger logger = Logger.getLogger(RsaNewKeyTest.class.getName());

    private static YubiHsm yubihsm;
    private static YHSession session;

    @BeforeClass
    public static void init()
            throws MalformedURLException, InvalidKeySpecException, NoSuchAlgorithmException, YHConnectionException, YHDeviceException,
                   YHAuthenticationException, YHInvalidResponseException {
        if (session == null) {
            Backend backend = new HttpBackend();
            yubihsm = new YubiHsm(backend);
            session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
            session.createAuthenticatedSession();
        }
    }

    @AfterClass
    public static void destroy()
            throws YHDeviceException, YHAuthenticationException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, BadPaddingException,
                   IllegalBlockSizeException {
        session.closeSession();
        yubihsm.close();
    }

    @Test
    public void testGenerateKey()
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException {
        logger.info("TEST START: testGenerateKey()");

        generateKey(Algorithm.RSA_2048);
        generateKey(Algorithm.RSA_3072);
        generateKey(Algorithm.RSA_4096);

        logger.info("TEST END: testGenerateKey()");
    }

    @Test
    public void testImportKeyWithWrongParameters()
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidKeySpecException, UnsupportedAlgorithmException {
        logger.info("TEST START: testImportKeyWithWrongParameters()");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateCrtKeySpec ks = kf.getKeySpec(kp.getPrivate(), RSAPrivateCrtKeySpec.class);

        byte[] p = ks.getPrimeP().toByteArray();
        byte[] q = ks.getPrimeQ().toByteArray();

        // Test importing the key with a non Asymmetric key algorithm
        boolean exceptionThrown = false;
        try {
            AsymmetricKeyRsa.importKey(session, (short) 0, "", Arrays.asList(2, 5), Algorithm.AES128_CCM_WRAP, Arrays.asList(Capability.SIGN_PKCS),
                                       p, q);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue("Succeeded in importing an RSA key even though the specified algorithm is not an asymmetric key algorithm", exceptionThrown);

        // Test importing an EC key as an RSA key
        exceptionThrown = false;
        try {
            AsymmetricKeyRsa.importKey(session, (short) 0, "", Arrays.asList(2, 5), Algorithm.EC_P224, Arrays.asList(Capability.SIGN_PKCS), p, q);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue("Succeeded in importing an EC key as an RSA key", exceptionThrown);

        // Test importing an RSA key whose parameter does not match the specified RSA algorithm
        exceptionThrown = false;
        try {
            AsymmetricKeyRsa.importKey(session, (short) 0, "", Arrays.asList(2, 5), Algorithm.RSA_3072, Arrays.asList(Capability.SIGN_PKCS), p, q);
        } catch (InvalidParameterException e) {
            exceptionThrown = true;
        }
        assertTrue("Succeeded in importing an RSA key whose parameters do not match the specified algorithm", exceptionThrown);

        // Test importing an RSA key without specifying one of the required private key primes
        exceptionThrown = false;
        try {
            AsymmetricKeyRsa.importKey(session, (short) 0, "", Arrays.asList(2, 5), Algorithm.RSA_2048, Arrays.asList(Capability.SIGN_PKCS), p,
                                       null);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue("Succeeded in importing an RSA key in spite of missing private key", exceptionThrown);

        logger.info("TEST END: testImportKeyWithWrongParameters()");

    }

    @Test
    public void testNonRsaKey()
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, InvalidAlgorithmParameterException
            , YHAuthenticationException, YHInvalidResponseException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException,
                   UnsupportedAlgorithmException {
        logger.info("TEST START: testNonRsaKey()");

        // Test creating an AsymmetricKeyRsa object without algorithm
        boolean exceptionThrown = false;
        try {
            new AsymmetricKeyRsa((short) 0x1234, null);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue("Succeeded in creating an AsymmetricKeyRsa object in spite of missing algorithm", exceptionThrown);

        // Test creating an AsymmetricKeyRsa object with a non RSA algorithm
        exceptionThrown = false;
        try {
            new AsymmetricKeyRsa((short) 0x1234, Algorithm.EC_P256);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue("Succeeded in creating an AsymmetricKeyRsa object with a non RSA algorithm", exceptionThrown);

        // Test creating an AsymmetricKeyRsa object for a key that does not exist in the device
        AsymmetricKeyRsa key = new AsymmetricKeyRsa((short) 0x1234, Algorithm.RSA_2048);
        exceptionThrown = false;
        try {
            key.getPublicKey(session);
        } catch (YHDeviceException e) {
            exceptionThrown = true;
            assertEquals(YHError.OBJECT_NOT_FOUND, e.getErrorCode());
        }
        assertTrue("Succeeded in in retrieving a public key for an RSA key that does not exist on the device", exceptionThrown);

        logger.info("TEST END: testNonRsaKey()");
    }

    @Test
    public void testImportKey()
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidKeySpecException,
                   UnsupportedAlgorithmException {
        logger.info("TEST START: testImportKey()");

        importRsaKeyTest(Algorithm.RSA_2048, 2048, 128);
        importRsaKeyTest(Algorithm.RSA_3072, 3072, 192);
        importRsaKeyTest(Algorithm.RSA_4096, 4096, 256);

        logger.info("TEST END: testImportKey()");
    }

    // -----------------------------------------------------------------------------------------

    private void generateKey(Algorithm algorithm)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException {

        List domains = Arrays.asList(2, 5, 8);
        List capabilities = Arrays.asList(Capability.SIGN_PKCS, Capability.SIGN_ECDSA, Capability.SIGN_EDDSA);
        String label = "rsa_key";

        // Generate the key on the device
        short id = AsymmetricKey.generateAsymmetricKey(session, (short) 0, label, domains, algorithm, capabilities);

        try {
            // Verify key properties
            final YHObjectInfo key = YHObject.getObjectInfo(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            assertNotEquals(0, key.getId());
            assertEquals(id, key.getId());
            assertEquals(ObjectType.TYPE_ASYMMETRIC_KEY, key.getType());
            assertEquals(domains, key.getDomains());
            assertEquals(algorithm, key.getAlgorithm());
            assertEquals(ObjectOrigin.YH_ORIGIN_GENERATED, key.getOrigin());
            assertEquals(label, key.getLabel());
            assertEquals(capabilities.size(), key.getCapabilities().size());
            assertTrue(key.getCapabilities().containsAll(capabilities));
            assertEquals(0, key.getDelegatedCapabilities().size());
        } finally {
            // Delete the key and verify deletion
            YHObject.deleteObject(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            try {
                YHObject.getObjectInfo(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            } catch (YHDeviceException e1) {
                assertEquals(YHError.OBJECT_NOT_FOUND, e1.getErrorCode());
            }
        }
    }

    private void importRsaKeyTest(Algorithm algorithm, int keysize, int componentLength)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidKeySpecException, UnsupportedAlgorithmException {

        final List domains = Arrays.asList(2, 5, 8);
        final List capabilities = Arrays.asList(Capability.SIGN_PKCS);
        final String label = "imported_asym_key";
        final short id = 0x1234;

        AsymmetricKeyTestHelper.importRsaKey(session, id, label, domains, capabilities, algorithm, keysize, componentLength);

        try {
            // Verify key property
            final YHObjectInfo key = YHObject.getObjectInfo(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            assertEquals(id, key.getId());
            assertEquals(ObjectType.TYPE_ASYMMETRIC_KEY, key.getType());
            assertEquals(domains, key.getDomains());
            assertEquals(algorithm, key.getAlgorithm());
            assertEquals(ObjectOrigin.YH_ORIGIN_IMPORTED, key.getOrigin());
            assertEquals(label, key.getLabel());
            assertEquals(capabilities.size(), key.getCapabilities().size());
            assertTrue(key.getCapabilities().containsAll(capabilities));
            assertEquals(0, key.getDelegatedCapabilities().size());
        } finally {
            // Delete key
            YHObject.deleteObject(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            try {
                YHObject.getObjectInfo(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            } catch (YHDeviceException e1) {
                assertEquals(YHError.OBJECT_NOT_FOUND, e1.getErrorCode());
            }
        }
    }


}
