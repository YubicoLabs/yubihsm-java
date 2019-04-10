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
import com.yubico.objects.yhobjects.AsymmetricKeyEd;
import com.yubico.objects.yhobjects.YHObject;
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

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.net.MalformedURLException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

import static org.junit.Assert.*;

public class AsymmetricKeyEdTest {
    Logger logger = Logger.getLogger(AsymmetricKeyEdTest.class.getName());

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

    // ---------------------------------------------------------
    //                  Key Generation
    // ---------------------------------------------------------

    @Test
    public void testGenerateKey()
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidSessionException {
        logger.info("TEST START: testGenerateKey()");

        final List domains = Arrays.asList(2, 5, 8);
        final List capabilities = Arrays.asList(Capability.SIGN_PKCS, Capability.SIGN_ECDSA, Capability.SIGN_EDDSA);
        final String label = "asym_key";

        // Generate the key on the device
        final short id = AsymmetricKey.generateAsymmetricKey(session, (short) 0, label, domains, capabilities, Algorithm.EC_ED25519);

        try {
            // Verify key properties
            final YHObject key = yubihsm.getObjectInfo(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            assertNotEquals(0, key.getId());
            assertEquals(id, key.getId());
            assertEquals(ObjectType.TYPE_ASYMMETRIC_KEY, key.getType());
            assertEquals(domains, key.getDomains());
            assertEquals(Algorithm.EC_ED25519, key.getAlgorithm());
            assertEquals(ObjectOrigin.YH_ORIGIN_GENERATED, key.getOrigin());
            assertEquals(label, key.getLabel());
            assertEquals(capabilities.size(), key.getCapabilities().size());
            assertTrue(key.getCapabilities().containsAll(capabilities));
            assertEquals(0, key.getDelegatedCapabilities().size());
        } finally {
            // Delete the key and verify deletion
            yubihsm.deleteObject(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            try {
                yubihsm.getObjectInfo(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            } catch (YHDeviceException e1) {
                assertEquals(YHError.OBJECT_NOT_FOUND, e1.getErrorCode());
            }
        }

        logger.info("TEST END: testGenerateKey()");
    }

    // -------------------------------------------------------------------------------
    //                               Key Import
    // -------------------------------------------------------------------------------

    @Test
    public void testImportKeyWithWrongParameters()
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, UnsupportedAlgorithmException {
        logger.info("TEST START: testImportKeyWithWrongParameters()");

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Ed25519KeyPairGenerator keyPairGenerator = new Ed25519KeyPairGenerator();
        keyPairGenerator.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair asymmetricCipherKeyPair = keyPairGenerator.generateKeyPair();
        Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters) asymmetricCipherKeyPair.getPrivate();
        byte[] d = privateKey.getEncoded();

        // Test importing the key with a non Asymmetric key algorithm
        boolean exceptionThrown = false;
        try {
            AsymmetricKeyEd.importKey(session, (short) 0, "", Arrays.asList(2, 5), Arrays.asList(Capability.SIGN_EDDSA), Algorithm.AES128_CCM_WRAP, d);
        } catch (UnsupportedAlgorithmException e) {
            exceptionThrown = true;
            assertEquals("Specified algorithm is not a supported ED algorithm", e.getMessage());
        }
        assertTrue("Succeeded in importing an ED key even though the specified algorithm is a non asymmetric key algorithm", exceptionThrown);

        // Test importing an RSA key as an ED key
        exceptionThrown = false;
        try {
            AsymmetricKeyEd.importKey(session, (short) 0, "", Arrays.asList(2, 5), Arrays.asList(Capability.SIGN_EDDSA), Algorithm.RSA_3072, d);
        } catch (UnsupportedAlgorithmException e) {
            exceptionThrown = true;
            assertEquals("Specified algorithm is not a supported ED algorithm", e.getMessage());
        }
        assertTrue("Succeeded in importing an RSA key as an ED key", exceptionThrown);

        // Test importing an ED key without specifying the private key
        exceptionThrown = false;
        try {
            AsymmetricKeyEd.importKey(session, (short) 0, "", Arrays.asList(2, 5), Arrays.asList(Capability.SIGN_ECDSA), Algorithm.EC_P256, null);
        } catch (InvalidParameterException e) {
            exceptionThrown = true;
            assertEquals("Missing parameter: k", e.getMessage());
        }
        assertTrue("Succeeded in importing an ED key in spite of missing private key", exceptionThrown);

        logger.info("TEST END: testImportKeyWithWrongParameters()");
    }

    @Test
    public void testNonEcKey()
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, UnsupportedAlgorithmException {
        logger.info("TEST START: testNonEcKey()");

        // Test creating an AsymmetricKeyEd object without algorithm
        YHObject objectInfo = new YHObject((short) 0x1234, AsymmetricKey.TYPE, (byte) 0);
        boolean exceptionThrown = false;
        try {
            AsymmetricKeyEd.getInstance(objectInfo);
        } catch (UnsupportedAlgorithmException e) {
            exceptionThrown = true;
            assertEquals("The object is not an ED key", e.getMessage());
        }
        assertTrue("Succeeded in creating an AsymmetricKeyEd object in spite of missing algorithm", exceptionThrown);

        // Test creating an AsymmetricKeyEd object with a non ED algorithm
        objectInfo = new YHObject((short) 0x1234, AsymmetricKey.TYPE, Arrays.asList(Capability.SIGN_ECDSA), (short) 128, Arrays.asList(2, 5),
                                  Algorithm.RSA_2048, (byte) 0, ObjectOrigin.YH_ORIGIN_IMPORTED, "", null);
        exceptionThrown = false;
        try {
            AsymmetricKeyEd.getInstance(objectInfo);
        } catch (UnsupportedAlgorithmException e) {
            exceptionThrown = true;
            assertEquals("The object is not an ED key", e.getMessage());
        }
        assertTrue("Succeeded in creating an AsymmetricKeyEd object with a non ED algorithm", exceptionThrown);

        // Test creating an AsymmetricKeyEd object for a key that does not exist in the device
        objectInfo = new YHObject((short) 0x1234, AsymmetricKey.TYPE, Arrays.asList(Capability.SIGN_PKCS), (short) 2048, Arrays.asList(2, 5),
                                  Algorithm.EC_ED25519, (byte) 0, ObjectOrigin.YH_ORIGIN_IMPORTED, "", null);
        AsymmetricKeyEd key = AsymmetricKeyEd.getInstance(objectInfo);
        exceptionThrown = false;
        try {
            key.getPublicKey(session);
        } catch (YHDeviceException e) {
            exceptionThrown = true;
            assertEquals(YHError.OBJECT_NOT_FOUND, e.getErrorCode());
        }
        assertTrue("Succeeded in retrieving a public key of an ED key that does not exist on the device", exceptionThrown);

        logger.info("TEST END: testNonEcKey()");
    }

    @Test
    public void testImportKey()
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidSessionException, UnsupportedAlgorithmException {
        logger.info("TEST START: testImportKey()");

        final List domains = Arrays.asList(2, 5, 8);
        final List capabilities = Arrays.asList(Capability.SIGN_EDDSA);
        final String label = "imported_asym_key";
        short id = 0x1234;


        importEdKey(id, label, domains, capabilities);

        try {

            final YHObject key = yubihsm.getObjectInfo(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            assertEquals(id, key.getId());
            assertEquals(ObjectType.TYPE_ASYMMETRIC_KEY, key.getType());
            assertEquals(domains, key.getDomains());
            assertEquals(Algorithm.EC_ED25519, key.getAlgorithm());
            assertEquals(ObjectOrigin.YH_ORIGIN_IMPORTED, key.getOrigin());
            assertEquals(label, key.getLabel());
            assertEquals(capabilities.size(), key.getCapabilities().size());
            assertTrue(key.getCapabilities().containsAll(capabilities));
            assertEquals(0, key.getDelegatedCapabilities().size());
        } finally {
            yubihsm.deleteObject(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            try {
                yubihsm.getObjectInfo(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            } catch (YHDeviceException e1) {
                assertEquals(YHError.OBJECT_NOT_FOUND, e1.getErrorCode());
            }
        }

        logger.info("TEST END: testImportKey()");
    }

    private Ed25519PublicKeyParameters importEdKey(short id, String label, List<Integer> domains, List<Capability> capabilities)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, UnsupportedAlgorithmException {

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Ed25519KeyPairGenerator keyPairGenerator = new Ed25519KeyPairGenerator();
        keyPairGenerator.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair asymmetricCipherKeyPair = keyPairGenerator.generateKeyPair();
        Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters) asymmetricCipherKeyPair.getPrivate();
        Ed25519PublicKeyParameters publicKey = (Ed25519PublicKeyParameters) asymmetricCipherKeyPair.getPublic();

        AsymmetricKeyEd.importKey(session, id, label, domains, capabilities, Algorithm.EC_ED25519, privateKey.getEncoded());
        return publicKey;
    }

    // ----------------------------------------------------------------------------
    //                                 Public Key
    // ----------------------------------------------------------------------------

    @Test
    public void testPublicKey()
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidSessionException, UnsupportedAlgorithmException {

        logger.info("TEST START: testPublicKey()");

        final short id = 0x1234;
        Ed25519PublicKeyParameters pubKey = importEdKey(id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.SIGN_EDDSA));

        try {
            final YHObject keyinfo = yubihsm.getObjectInfo(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            final AsymmetricKeyEd key = AsymmetricKeyEd.getInstance(keyinfo);
            byte[] returnedPubKeyBytes = (byte[]) key.getPublicKey(session);
            assertTrue("Returned EDDSA public key is not correct", Arrays.equals(pubKey.getEncoded(), returnedPubKeyBytes));

        } finally {
            yubihsm.deleteObject(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
        }

        logger.info("TEST END: testPublicKey()");

    }

    // ----------------------------------------------------------------------------------------------------
    //                                         Signing
    // ----------------------------------------------------------------------------------------------------

    @Test
    public void testSignDataWithInsufficientPermissions()
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidSessionException, UnsupportedAlgorithmException {
        short id = 0x1234;
        importEdKey(id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.GET_OPAQUE));
        try {
            YHObject keyinfo = yubihsm.getObjectInfo(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            AsymmetricKeyEd key = AsymmetricKeyEd.getInstance(keyinfo);
            byte[] data = "test sign data".getBytes();

            boolean exceptionThrown = false;
            try {
                key.signEddsa(session, data);
            } catch (YHDeviceException e) {
                exceptionThrown = true;
                assertEquals("Device returned incorrect error", YHError.INSUFFICIENT_PERMISSIONS, e.getErrorCode());
            }
            assertTrue("Succeeded in signing in spite of insufficient permissions", exceptionThrown);

        } finally {
            yubihsm.deleteObject(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
        }
    }

    @Test
    public void testSignData()
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidSessionException, UnsupportedAlgorithmException {
        logger.info("TEST START: testSignData()");

        final short id = 0x1234;
        Ed25519PublicKeyParameters pubKey = importEdKey(id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.SIGN_EDDSA));

        try {
            final YHObject keyinfo = yubihsm.getObjectInfo(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            final AsymmetricKeyEd key = AsymmetricKeyEd.getInstance(keyinfo);

            final byte[] data = "This is a signing test data".getBytes();
            final byte[] signature = key.signEddsa(session, data);
            assertEquals(64, signature.length);

            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            Signer signer = new Ed25519Signer();
            signer.init(false, pubKey);
            signer.update(data, 0, data.length);
            assertTrue(signer.verifySignature(signature));

        } finally {
            yubihsm.deleteObject(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
        }

        logger.info("TEST END: testSignData()");
    }

}
