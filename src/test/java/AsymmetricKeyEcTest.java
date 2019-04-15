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
import com.yubico.objects.yhobjects.AsymmetricKeyEc;
import com.yubico.objects.yhobjects.YHObject;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.net.MalformedURLException;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

import static org.junit.Assert.*;

public class AsymmetricKeyEcTest {
    Logger logger = Logger.getLogger(AsymmetricKeyEcTest.class.getName());

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

        generateKey(Algorithm.EC_P224);
        generateKey(Algorithm.EC_P256);
        generateKey(Algorithm.EC_P384);
        generateKey(Algorithm.EC_P521);
        generateKey(Algorithm.EC_K256);
        generateKey(Algorithm.EC_BP256);
        generateKey(Algorithm.EC_BP384);
        generateKey(Algorithm.EC_BP512);

        logger.info("TEST END: testGenerateKey()");
    }

    private void generateKey(Algorithm algorithm)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidSessionException {

        final List domains = Arrays.asList(2, 5, 8);
        final List capabilities = Arrays.asList(Capability.SIGN_PKCS, Capability.SIGN_ECDSA, Capability.SIGN_EDDSA);
        final String label = "asym_key";

        // Generate the key on the device
        final short id = AsymmetricKey.generateAsymmetricKey(session, (short) 0, label, domains, capabilities, algorithm);

        try {
            // Verify key properties
            final YHObject key = yubihsm.getObjectInfo(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
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
            yubihsm.deleteObject(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            try {
                yubihsm.getObjectInfo(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            } catch (YHDeviceException e1) {
                assertEquals(YHError.OBJECT_NOT_FOUND, e1.getErrorCode());
            }
        }
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

        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = generator.generateKeyPair();
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        byte[] d = privateKey.getS().toByteArray();

        // Test importing the key with a non Asymmetric key algorithm
        boolean exceptionThrown = false;
        try {
            AsymmetricKeyEc
                    .importKey(session, (short) 0, "", Arrays.asList(2, 5), Arrays.asList(Capability.SIGN_ECDSA), Algorithm.AES128_CCM_WRAP, d);
        } catch (UnsupportedAlgorithmException e) {
            exceptionThrown = true;
            assertEquals("Specified algorithm is not a supported EC algorithm", e.getMessage());
        }
        assertTrue("Succeeded in importing an EC key even though the specified algorithm is a non asymmetric key algorithm", exceptionThrown);

        // Test importing an RSA key as an EC key
        exceptionThrown = false;
        try {
            AsymmetricKeyEc.importKey(session, (short) 0, "", Arrays.asList(2, 5), Arrays.asList(Capability.SIGN_ECDSA), Algorithm.RSA_3072, d);
        } catch (UnsupportedAlgorithmException e) {
            exceptionThrown = true;
            assertEquals("Specified algorithm is not a supported EC algorithm", e.getMessage());
        }
        assertTrue("Succeeded in importing an RSA key as an EC key", exceptionThrown);

        // Test importing an EC key whose parameter does not match the specified EC algorithm
        exceptionThrown = false;
        try {
            AsymmetricKeyEc.importKey(session, (short) 0, "", Arrays.asList(2, 5), Arrays.asList(Capability.SIGN_ECDSA), Algorithm.EC_P224, d);
        } catch (InvalidParameterException e) {
            exceptionThrown = true;
            assertEquals("Invalid parameter: d", e.getMessage());
        }
        assertTrue("Succeeded in importing an EC key whose parameters do not match the specified algorithm", exceptionThrown);

        // Test importing an EC key without specifying the private key
        exceptionThrown = false;
        try {
            AsymmetricKeyEc.importKey(session, (short) 0, "", Arrays.asList(2, 5), Arrays.asList(Capability.SIGN_ECDSA), Algorithm.EC_P256, null);
        } catch (InvalidParameterException e) {
            exceptionThrown = true;
            assertEquals("Missing parameter d", e.getMessage());
        }
        assertTrue("Succeeded in importing an EC key in spite of missing private key", exceptionThrown);

        logger.info("TEST END: testImportKeyWithWrongParameters()");
    }

    @Test
    public void testNonEcKey()
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, InvalidAlgorithmParameterException
            , YHAuthenticationException, YHInvalidResponseException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException,
                   UnsupportedAlgorithmException, InvalidParameterSpecException, NoSuchProviderException {
        logger.info("TEST START: testNonEcKey()");

        // Test creating an AsymmetricKeyEc object without algorithm
        YHObject objectInfo = new YHObject((short) 0x1234, AsymmetricKey.TYPE, (byte) 0);
        boolean exceptionThrown = false;
        try {
            AsymmetricKeyEc.getInstance(objectInfo);
        } catch (UnsupportedAlgorithmException e) {
            exceptionThrown = true;
            assertEquals("The object is not an EC key", e.getMessage());
        }
        assertTrue("Succeeded in creating an AsymmetricKeyEc object in spite of missing algorithm", exceptionThrown);

        // Test creating an AsymmetricKeyEc object with a non EC algorithm
        objectInfo = new YHObject((short) 0x1234, AsymmetricKey.TYPE, Arrays.asList(Capability.SIGN_ECDSA), (short) 128, Arrays.asList(2, 5),
                                  Algorithm.RSA_2048, (byte) 0, ObjectOrigin.YH_ORIGIN_IMPORTED, "", null);
        exceptionThrown = false;
        try {
            AsymmetricKeyEc.getInstance(objectInfo);
        } catch (UnsupportedAlgorithmException e) {
            exceptionThrown = true;
            assertEquals("The object is not an EC key", e.getMessage());
        }
        assertTrue("Succeeded in creating an AsymmetricKeyEc object with a non EC algorithm", exceptionThrown);

        // Test creating an AsymmetricKeyEc object for a key that does not exist in the device
        objectInfo = new YHObject((short) 0x1234, AsymmetricKey.TYPE, Arrays.asList(Capability.SIGN_PKCS), (short) 2048, Arrays.asList(2, 5),
                                  Algorithm.EC_P256, (byte) 0, ObjectOrigin.YH_ORIGIN_IMPORTED, "", null);
        AsymmetricKeyEc key = AsymmetricKeyEc.getInstance(objectInfo);
        exceptionThrown = false;
        try {
            key.getPublicKey(session);
        } catch (YHDeviceException e) {
            exceptionThrown = true;
            assertEquals(YHError.OBJECT_NOT_FOUND, e.getErrorCode());
        }
        assertTrue("Succeeded in retrieving a public key of an EC key that does not exist on the device", exceptionThrown);

        logger.info("TEST END: testNonEcKey()");

    }

    @Test
    public void testImportKey()
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidSessionException, NoSuchProviderException,
                   UnsupportedAlgorithmException {
        logger.info("TEST START: testImportKey()");

        importEcKeyTest(Algorithm.EC_P224, "secp224r1", 28, false);
        importEcKeyTest(Algorithm.EC_P256, "secp256r1", 32, false);
        importEcKeyTest(Algorithm.EC_P384, "secp384r1", 48, false);
        importEcKeyTest(Algorithm.EC_P521, "secp521r1", 66, false);
        importEcKeyTest(Algorithm.EC_K256, "secp256k1", 32, false);
        importEcKeyTest(Algorithm.EC_BP256, "brainpoolP256r1", 32, true);
        importEcKeyTest(Algorithm.EC_BP384, "brainpoolP384r1", 48, true);
        importEcKeyTest(Algorithm.EC_BP512, "brainpoolP512r1", 64, true);

        logger.info("TEST END: testImportKey()");
    }

    private void importEcKeyTest(Algorithm algorithm, String curve, int componentLength, boolean brainpool)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidSessionException, NoSuchProviderException, UnsupportedAlgorithmException {
        final List domains = Arrays.asList(2, 5, 8);
        final List capabilities = Arrays.asList(Capability.SIGN_ECDSA);
        final String label = "imported_asym_key";
        final short id = 0x1234;

        if (brainpool) {
            importEcBrainpoolKey(id, label, domains, capabilities, algorithm, curve, componentLength);
        } else {
            importEcKey(id, label, domains, capabilities, algorithm, curve, componentLength);
        }

        try {
            // Verify key properties
            final YHObject key = yubihsm.getObjectInfo(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
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
            yubihsm.deleteObject(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            try {
                yubihsm.getObjectInfo(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            } catch (YHDeviceException e1) {
                assertEquals(YHError.OBJECT_NOT_FOUND, e1.getErrorCode());
            }
        }
    }

    private KeyPair importEcKey(short id, String label, List<Integer> domains, List<Capability> capabilities, Algorithm algorithm, String curve,
                                int componentLength)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, UnsupportedAlgorithmException {
        byte[] d;
        KeyPair keypair;

        // Sometimes, the prime numbers byte array is not exactly the expected length. When it is longer, it starts with 0 bytes
        // TODO Find out why and how to avoid it (it seems to be a java.security thing)
        do {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec(curve));
            keypair = generator.generateKeyPair();
            ECPrivateKey privateKey = (ECPrivateKey) keypair.getPrivate();
            d = privateKey.getS().toByteArray();
        } while (d.length < componentLength);
        if (d.length > componentLength) {
            d = Arrays.copyOfRange(d, d.length - componentLength, d.length);
        }

        AsymmetricKeyEc.importKey(session, id, label, domains, capabilities, algorithm, d);
        return keypair;
    }

    private KeyPair importEcBrainpoolKey(short id, String label, List<Integer> domains, List<Capability> capabilities, Algorithm algorithm,
                                         String curve, int componentLength)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, NoSuchProviderException, UnsupportedAlgorithmException {
        byte[] d;
        KeyPair keypair;

        // Sometimes, the prime numbers byte array is not exactly the expected length. When it is longer, it starts with 0 bytes
        // TODO Find out why and how to avoid it (it seems to be a java.security thing)
        do {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "BC");
            generator.initialize(new ECGenParameterSpec(curve));
            keypair = generator.generateKeyPair();
            ECPrivateKey privateKey = (ECPrivateKey) keypair.getPrivate();
            d = privateKey.getS().toByteArray();
        } while (d.length < componentLength);
        if (d.length > componentLength) {
            d = Arrays.copyOfRange(d, d.length - componentLength, d.length);
        }

        AsymmetricKeyEc.importKey(session, id, label, domains, capabilities, algorithm, d);
        return keypair;
    }

    // ----------------------------------------------------------------------------
    //                                 Public Key
    // ----------------------------------------------------------------------------

    @Test
    public void testPublicKey()
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidSessionException, InvalidKeySpecException, InvalidParameterSpecException,
                   UnsupportedAlgorithmException, NoSuchProviderException {

        logger.info("TEST START: testPublicKey()");

        getEcPublicKeyTest(Algorithm.EC_P224, "secp224r1", 28, false);
        getEcPublicKeyTest(Algorithm.EC_P256, "secp256r1", 32, false);
        getEcPublicKeyTest(Algorithm.EC_P384, "secp384r1", 48, false);
        getEcPublicKeyTest(Algorithm.EC_P521, "secp521r1", 66, false);
        getEcPublicKeyTest(Algorithm.EC_K256, "secp256k1", 32, false);
        getEcPublicKeyTest(Algorithm.EC_BP256, "brainpoolP256r1", 32, true);
        getEcPublicKeyTest(Algorithm.EC_BP384, "brainpoolP384r1", 48, true);
        getEcPublicKeyTest(Algorithm.EC_BP512, "brainpoolP512r1", 64, true);

        logger.info("TEST END: testPublicKey()");

    }


    private void getEcPublicKeyTest(Algorithm algorithm, String curve, int componentLength, boolean brainpool)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidSessionException, InvalidKeySpecException, UnsupportedAlgorithmException,
                   InvalidParameterSpecException, NoSuchProviderException {
        final short id = 0x1234;
        KeyPair keypair;
        if (brainpool) {
            keypair = importEcBrainpoolKey(id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.SIGN_ECDSA), algorithm, curve, componentLength);
        } else {
            keypair = importEcKey(id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.SIGN_ECDSA), algorithm, curve, componentLength);
        }

        try {
            final YHObject keyinfo = yubihsm.getObjectInfo(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            final AsymmetricKeyEc key = AsymmetricKeyEc.getInstance(keyinfo);
            PublicKey returnedPubKey = (PublicKey) key.getPublicKey(session);
            assertEquals(keypair.getPublic(), returnedPubKey);
        } finally {
            yubihsm.deleteObject(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
        }
    }

    // ----------------------------------------------------------------------------------------------------
    //                                         Signing
    // ----------------------------------------------------------------------------------------------------

    @Test
    public void testSignDataWithInsufficientPermissions()
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidSessionException, SignatureException, UnsupportedAlgorithmException {
        final short id = 0x1234;
        KeyPair keypair = importEcKey(id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.DERIVE_ECDH), Algorithm.EC_P224, "secp224r1", 28);
        ;
        try {
            final YHObject keyinfo = yubihsm.getObjectInfo(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            final AsymmetricKeyEc key = AsymmetricKeyEc.getInstance(keyinfo);

            boolean exceptionThrown = false;
            try {
                signEcdsa(keypair.getPublic(), key, Algorithm.EC_ECDSA_SHA256, "SHA256withECDSA", new byte[0]);
            } catch (YHDeviceException e) {
                exceptionThrown = true;
                assertEquals("Device returned incorrect error", YHError.INSUFFICIENT_PERMISSIONS, e.getErrorCode());
            }
            assertTrue("Succeeded to sign in spite of insufficient permissions", exceptionThrown);

        } finally {
            yubihsm.deleteObject(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
        }
    }

    @Test
    public void testSignData()
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidSessionException, SignatureException, NoSuchProviderException, UnsupportedAlgorithmException {
        logger.info("TEST START: testSignData()");

        signEcdsaTest(Algorithm.EC_P224, "secp224r1", 28);
        signEcdsaTest(Algorithm.EC_P256, "secp256r1", 32);
        signEcdsaTest(Algorithm.EC_P384, "secp384r1", 48);
        signEcdsaTest(Algorithm.EC_P521, "secp521r1", 66);
        signEcdsaTest(Algorithm.EC_K256, "secp256k1", 32);

        signEcdsaBrainpoolTest(Algorithm.EC_BP256, "brainpoolP256r1", 32);
        signEcdsaBrainpoolTest(Algorithm.EC_BP384, "brainpoolP384r1", 48);
        signEcdsaBrainpoolTest(Algorithm.EC_BP512, "brainpoolP512r1", 64);

        logger.info("TEST END: testSignData()");
    }


    private void signEcdsaTest(Algorithm keyAlgorithm, String curve, int componentLength)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidSessionException, SignatureException, UnsupportedAlgorithmException {
        final short id = 0x1234;
        KeyPair keypair = importEcKey(id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.SIGN_ECDSA), keyAlgorithm, curve, componentLength);
        PublicKey publicKey = keypair.getPublic();
        try {
            final YHObject keyinfo = yubihsm.getObjectInfo(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            final AsymmetricKeyEc key = AsymmetricKeyEc.getInstance(keyinfo);

            byte[] data = new byte[0];
            signEcdsa(publicKey, key, Algorithm.EC_ECDSA_SHA1, "SHA1withECDSA", data);
            signEcdsa(publicKey, key, Algorithm.EC_ECDSA_SHA256, "SHA256withECDSA", data);
            signEcdsa(publicKey, key, Algorithm.EC_ECDSA_SHA384, "SHA384withECDSA", data);
            signEcdsa(publicKey, key, Algorithm.EC_ECDSA_SHA512, "SHA512withECDSA", data);

            data = "This is a signing test data".getBytes();
            signEcdsa(publicKey, key, Algorithm.EC_ECDSA_SHA1, "SHA1withECDSA", data);
            signEcdsa(publicKey, key, Algorithm.EC_ECDSA_SHA256, "SHA256withECDSA", data);
            signEcdsa(publicKey, key, Algorithm.EC_ECDSA_SHA384, "SHA384withECDSA", data);
            signEcdsa(publicKey, key, Algorithm.EC_ECDSA_SHA512, "SHA512withECDSA", data);

        } finally {
            yubihsm.deleteObject(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
        }
    }

    private void signEcdsa(PublicKey pubKey, AsymmetricKeyEc key, Algorithm signAlgorithm, String signAlgorithmStr, byte[] data)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, SignatureException {

        byte[] signature = key.signEcdsa(session, data, signAlgorithm);

        Signature sig = Signature.getInstance(signAlgorithmStr);
        sig.initVerify(pubKey);
        sig.update(data);
        assertTrue(sig.verify(signature));
    }

    private void signEcdsaBrainpoolTest(Algorithm keyAlgorithm, String curve, int componentLength)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidSessionException, SignatureException, NoSuchProviderException, UnsupportedAlgorithmException {
        final short id = 0x1234;
        KeyPair keyPair =
                importEcBrainpoolKey(id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.SIGN_ECDSA), keyAlgorithm, curve, componentLength);
        PublicKey publicKey = keyPair.getPublic();
        try {
            final YHObject keyinfo = yubihsm.getObjectInfo(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            final AsymmetricKeyEc key = AsymmetricKeyEc.getInstance(keyinfo);

            signEcdsaBrainpool(publicKey, key, Algorithm.EC_ECDSA_SHA1, "SHA1withECDSA");
            signEcdsaBrainpool(publicKey, key, Algorithm.EC_ECDSA_SHA256, "SHA256withECDSA");
            signEcdsaBrainpool(publicKey, key, Algorithm.EC_ECDSA_SHA384, "SHA384withECDSA");
            signEcdsaBrainpool(publicKey, key, Algorithm.EC_ECDSA_SHA512, "SHA512withECDSA");

        } finally {
            yubihsm.deleteObject(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
        }
    }

    private void signEcdsaBrainpool(PublicKey pubKey, AsymmetricKeyEc key, Algorithm signAlgorithm, String signAlgorithmStr)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, SignatureException, NoSuchProviderException {
        final byte[] data = "This is a signing test data".getBytes();
        final byte[] signature = key.signEcdsa(session, data, signAlgorithm);

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Signature sig = Signature.getInstance(signAlgorithmStr, "BC");
        sig.initVerify(pubKey);
        sig.update(data);
        assertTrue(sig.verify(signature));
    }


}
