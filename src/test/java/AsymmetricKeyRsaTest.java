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
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.net.MalformedURLException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

import static org.junit.Assert.*;

public class AsymmetricKeyRsaTest {
    Logger logger = Logger.getLogger(AsymmetricKeyRsaTest.class.getName());

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

        generateKey(Algorithm.RSA_2048);
        generateKey(Algorithm.RSA_3072);
        generateKey(Algorithm.RSA_4096);

        logger.info("TEST END: testGenerateKey()");
    }

    private void generateKey(Algorithm algorithm)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidSessionException {

        final List domains = Arrays.asList(2, 5, 8);
        final List capabilities = Arrays.asList(Capability.SIGN_PKCS, Capability.SIGN_ECDSA, Capability.SIGN_EDDSA);
        final String label = "rsa_key";

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
            AsymmetricKeyRsa
                    .importKey(session, (short) 0, "", Arrays.asList(2, 5), Arrays.asList(Capability.SIGN_PKCS), Algorithm.AES128_CCM_WRAP, p, q);
        } catch (UnsupportedAlgorithmException e) {
            exceptionThrown = true;
            assertEquals("Specified algorithm is not a supported RSA algorithm", e.getMessage());
        }
        assertTrue("Succeeded in importing an RSA key even though the specified algorithm is not an asymmetric key algorithm", exceptionThrown);

        // Test importing an EC key as an RSA key
        exceptionThrown = false;
        try {
            AsymmetricKeyRsa.importKey(session, (short) 0, "", Arrays.asList(2, 5), Arrays.asList(Capability.SIGN_PKCS), Algorithm.EC_P224, p, q);
        } catch (UnsupportedAlgorithmException e) {
            exceptionThrown = true;
            assertEquals("Specified algorithm is not a supported RSA algorithm", e.getMessage());
        }
        assertTrue("Succeeded in importing an EC key as an RSA key", exceptionThrown);

        // Test importing an RSA key whose parameter does not match the specified RSA algorithm
        exceptionThrown = false;
        try {
            AsymmetricKeyRsa.importKey(session, (short) 0, "", Arrays.asList(2, 5), Arrays.asList(Capability.SIGN_PKCS), Algorithm.RSA_3072, p, q);
        } catch (InvalidParameterException e) {
            exceptionThrown = true;
            assertEquals("Invalid parameter: primeP, primeQ", e.getMessage());
        }
        assertTrue("Succeeded in importing an RSA key whose parameters do not match the specified algorithm", exceptionThrown);

        // Test importing an RSA key without specifying one of the required private key primes
        exceptionThrown = false;
        try {
            AsymmetricKeyRsa.importKey(session, (short) 0, "", Arrays.asList(2, 5), Arrays.asList(Capability.SIGN_PKCS), Algorithm.RSA_2048, p, null);
        } catch (InvalidParameterException e) {
            exceptionThrown = true;
            assertEquals("Missing prime Q", e.getMessage());
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
        YHObject objectInfo = new YHObject((short) 0x1234, AsymmetricKey.TYPE, (byte) 0);
        boolean exceptionThrown = false;
        try {
            AsymmetricKeyRsa.getInstance(objectInfo);
        } catch (UnsupportedAlgorithmException e) {
            exceptionThrown = true;
            assertEquals("The object is not an RSA key", e.getMessage());
        }
        assertTrue("Succeeded in creating an AsymmetricKeyRsa object in spite of missing algorithm", exceptionThrown);

        // Test creating an AsymmetricKeyRsa object with a non RSA algorithm
        objectInfo = new YHObject((short) 0x1234, AsymmetricKey.TYPE, Arrays.asList(Capability.SIGN_PKCS), (short) 2048, Arrays.asList(2, 5),
                                  Algorithm.EC_P256, (byte) 0, ObjectOrigin.YH_ORIGIN_IMPORTED, "", null);
        exceptionThrown = false;
        try {
            AsymmetricKeyRsa.getInstance(objectInfo);
        } catch (UnsupportedAlgorithmException e) {
            exceptionThrown = true;
            assertEquals("The object is not an RSA key", e.getMessage());
        }
        assertTrue("Succeeded in creating an AsymmetricKeyRsa object with a non RSA algorithm", exceptionThrown);

        // Test creating an AsymmetricKeyRsa object for a key that does not exist in the device
        objectInfo = new YHObject((short) 0x1234, AsymmetricKey.TYPE, Arrays.asList(Capability.SIGN_PKCS), (short) 2048, Arrays.asList(2, 5),
                                  Algorithm.RSA_2048, (byte) 0, ObjectOrigin.YH_ORIGIN_IMPORTED, "", null);
        AsymmetricKeyRsa key = AsymmetricKeyRsa.getInstance(objectInfo);
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
                   IllegalBlockSizeException, InvalidSessionException, InvalidKeySpecException,
                   UnsupportedAlgorithmException {
        logger.info("TEST START: testImportKey()");

        importRsaKeyTest(Algorithm.RSA_2048, 2048, 128);
        importRsaKeyTest(Algorithm.RSA_3072, 3072, 192);
        importRsaKeyTest(Algorithm.RSA_4096, 4096, 256);

        logger.info("TEST END: testImportKey()");
    }

    private void importRsaKeyTest(Algorithm algorithm, int keysize, int componentLength)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidSessionException, InvalidKeySpecException, UnsupportedAlgorithmException {

        final List domains = Arrays.asList(2, 5, 8);
        final List capabilities = Arrays.asList(Capability.SIGN_PKCS);
        final String label = "imported_asym_key";
        final short id = 0x1234;

        importRsaKey(id, label, domains, capabilities, algorithm, keysize, componentLength);

        try {
            // Verify key property
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

    private PublicKey importRsaKey(short id, String label, List<Integer> domains, List<Capability> capabilities, Algorithm algorithm, int keysize,
                                   int componentLength)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidKeySpecException, UnsupportedAlgorithmException {
        byte[] p;
        byte[] q;
        PublicKey publicKey;

        // Sometimes, the prime numbers byte array is not exactly the expected length. When it is longer, it starts with 0 bytes
        // TODO Find out why and how to avoid it (it seems to be a java.security thing)
        do {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(keysize);
            KeyPair keypair = kpg.generateKeyPair();
            publicKey = keypair.getPublic();

            KeyFactory kf = KeyFactory.getInstance("RSA");
            RSAPrivateCrtKeySpec ks = kf.getKeySpec(keypair.getPrivate(), RSAPrivateCrtKeySpec.class);

            p = ks.getPrimeP().toByteArray();
            q = ks.getPrimeQ().toByteArray();

        } while (p.length < componentLength);

        if (p.length > componentLength) {
            p = Arrays.copyOfRange(p, p.length - componentLength, p.length);
            q = Arrays.copyOfRange(q, q.length - componentLength, q.length);
        }

        AsymmetricKeyRsa.importKey(session, id, label, domains, capabilities, algorithm, p, q);

        return publicKey;
    }

    // ----------------------------------------------------------------------------
    //                                 Public Key
    // ----------------------------------------------------------------------------

    @Test
    public void testPublicKey() throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException,
                                       YHDeviceException, InvalidAlgorithmParameterException, YHAuthenticationException,
                                       YHInvalidResponseException, BadPaddingException, IllegalBlockSizeException, InvalidSessionException,
                                       InvalidKeySpecException, UnsupportedAlgorithmException {

        logger.info("TEST START: testPublicKey()");

        getRsaPublicKeyTest(Algorithm.RSA_2048, 2048, 128);
        getRsaPublicKeyTest(Algorithm.RSA_3072, 3072, 192);
        getRsaPublicKeyTest(Algorithm.RSA_4096, 4096, 256);

        logger.info("TEST END: testPublicKey()");

    }

    private void getRsaPublicKeyTest(Algorithm algorithm, int keysize, int componentLength)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidSessionException, InvalidKeySpecException, UnsupportedAlgorithmException {

        final short id = 0x1234;
        PublicKey pubKey = importRsaKey(id, "", Arrays.asList(2, 5), Arrays.asList(Capability.SIGN_PSS), algorithm, keysize, componentLength);

        try {
            final YHObject keyinfo = yubihsm.getObjectInfo(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            final AsymmetricKeyRsa key = AsymmetricKeyRsa.getInstance(keyinfo);
            PublicKey returnedPubKey = (PublicKey) key.getPublicKey(session);
            assertEquals(pubKey, returnedPubKey);
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
                   IllegalBlockSizeException, InvalidSessionException, InvalidKeySpecException, SignatureException, NoSuchProviderException,
                   UnsupportedAlgorithmException {
        logger.info("TEST START: testSignDataWithInsufficientPermissions()");

        final short id = 0x1234;
        PublicKey pubKey = importRsaKey(id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.SIGN_PKCS), Algorithm.RSA_2048, 2048,
                                        128);
        try {
            final YHObject keyinfo = yubihsm.getObjectInfo(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            final AsymmetricKeyRsa key = AsymmetricKeyRsa.getInstance(keyinfo);

            boolean exceptionThrown = false;
            try {
                signPss(pubKey, key, Algorithm.RSA_MGF1_SHA256, "SHA256withRSA/PSS", "SHA-256", (short) 32, new byte[0]);
            } catch (YHDeviceException e) {
                exceptionThrown = true;
                assertEquals("Device returned incorrect error", YHError.INSUFFICIENT_PERMISSIONS, e.getErrorCode());
            }
            assertTrue("Succeeded to sign in spite of insufficient permissions", exceptionThrown);

        } finally {
            yubihsm.deleteObject(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
        }

        logger.info("TEST END: testSignDataWithInsufficientPermissions()");
    }

    @Test
    public void testSignData()
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidSessionException, InvalidKeySpecException, SignatureException, NoSuchProviderException,
                   UnsupportedAlgorithmException {
        logger.info("TEST START: testSignData()");

        signPkcs1Test(Algorithm.RSA_2048, 2048, 128);
        signPkcs1Test(Algorithm.RSA_3072, 3072, 192);
        signPkcs1Test(Algorithm.RSA_4096, 4096, 256);

        signPssTest(Algorithm.RSA_2048, 2048, 128);
        signPssTest(Algorithm.RSA_3072, 3072, 192);
        signPssTest(Algorithm.RSA_4096, 4096, 256);

        logger.info("TEST END: testSignData()");
    }

    private void signPkcs1Test(Algorithm keyAlgorithm, int keysize, int componentLength)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidSessionException, InvalidKeySpecException, SignatureException, UnsupportedAlgorithmException {

        final short id = 0x1234;
        PublicKey pubKey = importRsaKey(id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.SIGN_PKCS), keyAlgorithm, keysize,
                                        componentLength);
        try {
            final YHObject keyinfo = yubihsm.getObjectInfo(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            final AsymmetricKeyRsa key = AsymmetricKeyRsa.getInstance(keyinfo);

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
        } finally {
            yubihsm.deleteObject(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
        }
    }

    private void signPkcs1(PublicKey pubKey, AsymmetricKeyRsa key, Algorithm hashAlgorithm, String signatureAlgorithm, byte[] data)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, SignatureException, UnsupportedAlgorithmException {

        byte[] signature = key.signPkcs1(session, data, hashAlgorithm);

        Signature sig = Signature.getInstance(signatureAlgorithm);
        sig.initVerify(pubKey);
        sig.update(data);
        assertTrue(sig.verify(signature));
    }

    private void signPssTest(Algorithm keyAlgorithm, int keysize, int componentLength)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidSessionException, InvalidKeySpecException, SignatureException, NoSuchProviderException,
                   UnsupportedAlgorithmException {
        final short id = 0x1234;
        PublicKey pubKey = importRsaKey(id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.SIGN_PSS), keyAlgorithm, keysize,
                                        componentLength);

        try {
            final YHObject keyinfo = yubihsm.getObjectInfo(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            final AsymmetricKeyRsa key = AsymmetricKeyRsa.getInstance(keyinfo);

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

        } finally {
            yubihsm.deleteObject(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
        }
    }

    private void signPss(PublicKey pubKey, AsymmetricKeyRsa key, Algorithm signAlgorithm, String signAlgorithmStr, String hashAlgorithm,
                         short saltLength, byte[] data)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, SignatureException, NoSuchProviderException, UnsupportedAlgorithmException {


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

    // ----------------------------------------------------------------------------------------------------
    //                                         Decrypt
    // ----------------------------------------------------------------------------------------------------

    @Test
    public void testDecryptDataWithInsufficientPermissions()
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidSessionException, InvalidKeySpecException, SignatureException, NoSuchProviderException,
                   UnsupportedAlgorithmException {
        final short id = 0x1234;
        PublicKey pubKey = importRsaKey(id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.SIGN_PKCS, Capability.SIGN_PSS), Algorithm.RSA_2048,
                                        2048, 128);
        try {
            final YHObject keyinfo = yubihsm.getObjectInfo(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            final AsymmetricKeyRsa key = AsymmetricKeyRsa.getInstance(keyinfo);


            byte[] data = "This is test data for decryption".getBytes();
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);
            byte[] enc = cipher.doFinal(data);
            boolean exceptionThrown = false;
            try {
                key.decryptPkcs1(session, enc);
            } catch (YHDeviceException e) {
                exceptionThrown = true;
                assertEquals("Device returned incorrect error", YHError.INSUFFICIENT_PERMISSIONS, e.getErrorCode());
            }
            assertTrue("Succeeded to sign in spite of insufficient permissions", exceptionThrown);

            exceptionThrown = false;
            try {
                decryptOaep(key, pubKey, Algorithm.RSA_MGF1_SHA1, Algorithm.RSA_OAEP_SHA1, "RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
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
    public void testDecryptPkcs1()
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidSessionException, InvalidKeySpecException, SignatureException, UnsupportedAlgorithmException,
                   NoSuchProviderException {
        logger.info("TEST START: testDecryptPkcs1()");

        byte[] data = new byte[0];
        decryptPkcs1Test(Algorithm.RSA_2048, 2048, 128, data);
        decryptPkcs1Test(Algorithm.RSA_3072, 3072, 192, data);
        decryptPkcs1Test(Algorithm.RSA_4096, 4096, 256, data);

        data = "This is test data for decryption".getBytes();
        decryptPkcs1Test(Algorithm.RSA_2048, 2048, 128, data);
        decryptPkcs1Test(Algorithm.RSA_3072, 3072, 192, data);
        decryptPkcs1Test(Algorithm.RSA_4096, 4096, 256, data);

        logger.info("TEST END: testDecryptPkcs1()");
    }

    private void decryptPkcs1Test(Algorithm keyAlgorithm, int keysize, int componentLength, byte[] data)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidSessionException, InvalidKeySpecException, SignatureException, UnsupportedAlgorithmException,
                   NoSuchProviderException {

        final short id = 0x1234;
        PublicKey publicKey =
                importRsaKey(id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.DECRYPT_PKCS), keyAlgorithm, keysize, componentLength);

        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] enc = cipher.doFinal(data);

            YHObject keyinfo = yubihsm.getObjectInfo(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            AsymmetricKeyRsa key = AsymmetricKeyRsa.getInstance(keyinfo);

            byte[] dec = key.decryptPkcs1(session, enc);


            assertArrayEquals(data, dec);
        } finally {
            yubihsm.deleteObject(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
        }
    }

    @Test
    public void testDecryptOaep()
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidSessionException, InvalidKeySpecException, SignatureException, UnsupportedAlgorithmException,
                   NoSuchProviderException {
        logger.info("TEST START: testDecryptOaep()");

        decryptOaepTest(Algorithm.RSA_2048, 2048, 128);
        decryptOaepTest(Algorithm.RSA_3072, 3072, 192);
        decryptOaepTest(Algorithm.RSA_4096, 4096, 256);

        logger.info("TEST END: testDecryptOaep()");
    }

    private void decryptOaepTest(Algorithm keyAlgorithm, int keysize, int componentLength)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidSessionException, InvalidKeySpecException, SignatureException, UnsupportedAlgorithmException,
                   NoSuchProviderException {

        final short id = 0x1234;
        PublicKey publicKey =
                importRsaKey(id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.DECRYPT_OAEP), keyAlgorithm, keysize, componentLength);

        try {

            YHObject keyinfo = yubihsm.getObjectInfo(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            AsymmetricKeyRsa key = AsymmetricKeyRsa.getInstance(keyinfo);

            decryptOaep(key, publicKey, Algorithm.RSA_MGF1_SHA1, Algorithm.RSA_OAEP_SHA1, "RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
            decryptOaep(key, publicKey, Algorithm.RSA_MGF1_SHA1, Algorithm.RSA_OAEP_SHA256, "RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            decryptOaep(key, publicKey, Algorithm.RSA_MGF1_SHA1, Algorithm.RSA_OAEP_SHA384, "RSA/ECB/OAEPWithSHA-384AndMGF1Padding");
            decryptOaep(key, publicKey, Algorithm.RSA_MGF1_SHA1, Algorithm.RSA_OAEP_SHA512, "RSA/ECB/OAEPWithSHA-512AndMGF1Padding");

            decryptOaepBc(key, publicKey, Algorithm.RSA_MGF1_SHA1, Algorithm.RSA_OAEP_SHA1, "RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
            decryptOaepBc(key, publicKey, Algorithm.RSA_MGF1_SHA256, Algorithm.RSA_OAEP_SHA256, "RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            decryptOaepBc(key, publicKey, Algorithm.RSA_MGF1_SHA384, Algorithm.RSA_OAEP_SHA384, "RSA/ECB/OAEPWithSHA-384AndMGF1Padding");
            decryptOaepBc(key, publicKey, Algorithm.RSA_MGF1_SHA512, Algorithm.RSA_OAEP_SHA512, "RSA/ECB/OAEPWithSHA-512AndMGF1Padding");


        } finally {
            yubihsm.deleteObject(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
        }
    }

    private void decryptOaep(AsymmetricKeyRsa key, PublicKey pubKey, Algorithm mgf1Algorithm, Algorithm hashAlgorithm, String cipherAlgorithm)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, UnsupportedAlgorithmException {


        byte[] data = "This is test data for decryption".getBytes();

        Cipher cipher = Cipher.getInstance(cipherAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] enc = cipher.doFinal(data);

        byte[] dec = key.decryptOaep(session, enc, "", mgf1Algorithm, hashAlgorithm);

        assertArrayEquals(data, dec);

    }

    private void decryptOaepBc(AsymmetricKeyRsa key, PublicKey pubKey, Algorithm mgf1Algorithm, Algorithm hashAlgorithm, String cipherAlgorithm)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, UnsupportedAlgorithmException, NoSuchProviderException {


        byte[] data = "This is test data for decryption".getBytes();

        Security.addProvider(new BouncyCastleProvider());
        Cipher cipher = Cipher.getInstance(cipherAlgorithm, "BC");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey, new SecureRandom());
        byte[] enc = cipher.doFinal(data);

        byte[] dec = key.decryptOaep(session, enc, "", mgf1Algorithm, hashAlgorithm);

        assertArrayEquals(data, dec);

    }

}
