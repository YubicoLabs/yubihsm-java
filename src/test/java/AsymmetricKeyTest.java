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
import java.security.interfaces.ECPrivateKey;
import java.security.spec.*;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

import static org.junit.Assert.*;

public class AsymmetricKeyTest {
    Logger logger = Logger.getLogger(AsymmetricKeyTest.class.getName());

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

        // RSA keys
        generateKey(Algorithm.RSA_2048);
        generateKey(Algorithm.RSA_3072);
        generateKey(Algorithm.RSA_4096);

        // EC keys
        generateKey(Algorithm.EC_P224);
        generateKey(Algorithm.EC_P256);
        generateKey(Algorithm.EC_P384);
        generateKey(Algorithm.EC_P521);
        generateKey(Algorithm.EC_K256);
        generateKey(Algorithm.EC_BP256);
        generateKey(Algorithm.EC_BP384);
        generateKey(Algorithm.EC_BP512);

        // ED key
        generateKey(Algorithm.EC_ED25519);

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
    public void testImportKeyWithWrongAlgorithm()
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidSessionException, InvalidKeySpecException {
        logger.info("TEST START: testImportKeyWithWrongAlgorithm()");

        final List domains = Arrays.asList(2, 5, 8);
        final List capabilities = Arrays.asList(Capability.SIGN_ECDSA);

        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = generator.generateKeyPair();
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        byte[] d = privateKey.getS().toByteArray();

        try {
            AsymmetricKey.importEcKey(session, (short) 0, "asym_key", domains, capabilities, Algorithm.AES128_CCM_WRAP, d);
        } catch (InvalidParameterException e) {
            // Expected behaviour
        }

        try {
            AsymmetricKey.importEcKey(session, (short) 0, "asym_key", domains, capabilities, Algorithm.RSA_3072, d);
        } catch (InvalidParameterException e) {
            // Expected behaviour
        }

        logger.info("TEST END: testImportKeyWithWrongAlgorithm()");

    }

    @Test
    public void testImportKey()
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidSessionException, InvalidKeySpecException, NoSuchProviderException {
        logger.info("TEST START: testImportKey()");

        importRsaKeyTest(Algorithm.RSA_2048, 2048, 128);
        importRsaKeyTest(Algorithm.RSA_3072, 3072, 192);
        importRsaKeyTest(Algorithm.RSA_4096, 4096, 256);

        importEcKeyTest(Algorithm.EC_P224, "secp224r1", 28, false);
        importEcKeyTest(Algorithm.EC_P256, "secp256r1", 32, false);
        importEcKeyTest(Algorithm.EC_P384, "secp384r1", 48, false);
        importEcKeyTest(Algorithm.EC_P521, "secp521r1", 66, false);
        importEcKeyTest(Algorithm.EC_K256, "secp256k1", 32, false);
        importEcKeyTest(Algorithm.EC_BP256, "brainpoolP256r1", 32, true);
        importEcKeyTest(Algorithm.EC_BP384, "brainpoolP384r1", 48, true);
        importEcKeyTest(Algorithm.EC_BP512, "brainpoolP512r1", 64, true);

        importEdKeyTest();

        logger.info("TEST END: testImportKey()");
    }

    private void importRsaKeyTest(Algorithm algorithm, int keysize, int componentLength)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidSessionException, InvalidKeySpecException {

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
                   IllegalBlockSizeException, InvalidKeySpecException {
        byte[] p;
        byte[] q;
        PublicKey pubKey;

        // Sometimes, the prime numbers byte array is not exactly the expected length. When it is longer, it starts with 0 bytes
        // TODO Find out why and how to avoid it (it seems to be a java.security thing)
        do {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(keysize);
            KeyPair kp = kpg.generateKeyPair();

            KeyFactory kf = KeyFactory.getInstance("RSA");
            RSAPrivateCrtKeySpec ks = kf.getKeySpec(kp.getPrivate(), RSAPrivateCrtKeySpec.class);

            p = ks.getPrimeP().toByteArray();
            q = ks.getPrimeQ().toByteArray();
            pubKey = kp.getPublic();

        } while (p.length < componentLength);

        if (p.length > componentLength) {
            p = Arrays.copyOfRange(p, p.length - componentLength, p.length);
            q = Arrays.copyOfRange(q, q.length - componentLength, q.length);
        }

        AsymmetricKey.importRsaKey(session, id, label, domains, capabilities, algorithm, p, q);

        return pubKey;
    }

    private void importEcKeyTest(Algorithm algorithm, String curve, int componentLength, boolean brainpool)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidSessionException, NoSuchProviderException {
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

    private PublicKey importEcKey(short id, String label, List<Integer> domains, List<Capability> capabilities, Algorithm algorithm, String curve,
                                  int componentLength)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException {
        byte[] d;
        PublicKey pubKey;

        // Sometimes, the prime numbers byte array is not exactly the expected length. When it is longer, it starts with 0 bytes
        // TODO Find out why and how to avoid it (it seems to be a java.security thing)
        do {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec(curve));
            KeyPair keyPair = generator.generateKeyPair();
            ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
            d = privateKey.getS().toByteArray();
            pubKey = keyPair.getPublic();
        } while (d.length < componentLength);
        if (d.length > componentLength) {
            d = Arrays.copyOfRange(d, d.length - componentLength, d.length);
        }

        AsymmetricKey.importEcKey(session, id, label, domains, capabilities, algorithm, d);
        return pubKey;
    }

    private PublicKey importEcBrainpoolKey(short id, String label, List<Integer> domains, List<Capability> capabilities, Algorithm algorithm,
                                           String curve, int componentLength)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, NoSuchProviderException {
        byte[] d;
        PublicKey pubKey;

        // Sometimes, the prime numbers byte array is not exactly the expected length. When it is longer, it starts with 0 bytes
        // TODO Find out why and how to avoid it (it seems to be a java.security thing)
        do {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "BC");
            generator.initialize(new ECGenParameterSpec(curve));
            KeyPair keyPair = generator.generateKeyPair();
            ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
            d = privateKey.getS().toByteArray();
            pubKey = keyPair.getPublic();
        } while (d.length < componentLength);
        if (d.length > componentLength) {
            d = Arrays.copyOfRange(d, d.length - componentLength, d.length);
        }

        AsymmetricKey.importEcKey(session, id, label, domains, capabilities, algorithm, d);
        return pubKey;
    }


    private void importEdKeyTest() throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException,
                                          YHDeviceException, InvalidAlgorithmParameterException, YHAuthenticationException,
                                          YHInvalidResponseException, BadPaddingException, IllegalBlockSizeException, InvalidSessionException {
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
    }

    private Ed25519PublicKeyParameters importEdKey(short id, String label, List<Integer> domains, List<Capability> capabilities)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException {

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Ed25519KeyPairGenerator keyPairGenerator = new Ed25519KeyPairGenerator();
        keyPairGenerator.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair asymmetricCipherKeyPair = keyPairGenerator.generateKeyPair();
        Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters) asymmetricCipherKeyPair.getPrivate();
        Ed25519PublicKeyParameters publicKey = (Ed25519PublicKeyParameters) asymmetricCipherKeyPair.getPublic();

        AsymmetricKey.importEdKey(session, id, label, domains, capabilities, Algorithm.EC_ED25519, privateKey.getEncoded());
        return publicKey;
    }

    // ----------------------------------------------------------------------------
    //                                 Public Key
    // ----------------------------------------------------------------------------

    @Test
    public void testPublicKey() throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException,
                                       YHDeviceException, InvalidAlgorithmParameterException, YHAuthenticationException,
                                       YHInvalidResponseException, BadPaddingException, IllegalBlockSizeException, InvalidSessionException,
                                       InvalidKeySpecException, InvalidParameterSpecException, UnsupportedAlgorithmException,
                                       NoSuchProviderException {

        logger.info("TEST START: testPublicKey()");

        getRsaPublicKeyTest(Algorithm.RSA_2048, 2048, 128);
        getRsaPublicKeyTest(Algorithm.RSA_3072, 3072, 192);
        getRsaPublicKeyTest(Algorithm.RSA_4096, 4096, 256);

        getEcPublicKeyTest(Algorithm.EC_P224, "secp224r1", 28, false);
        getEcPublicKeyTest(Algorithm.EC_P256, "secp256r1", 32, false);
        getEcPublicKeyTest(Algorithm.EC_P384, "secp384r1", 48, false);
        getEcPublicKeyTest(Algorithm.EC_P521, "secp521r1", 66, false);
        getEcPublicKeyTest(Algorithm.EC_K256, "secp256k1", 32, false);
        getEcPublicKeyTest(Algorithm.EC_BP256, "brainpoolP256r1", 32, true);
        getEcPublicKeyTest(Algorithm.EC_BP384, "brainpoolP384r1", 48, true);
        getEcPublicKeyTest(Algorithm.EC_BP512, "brainpoolP512r1", 64, true);

        getEdPublicKeyTest();

        logger.info("TEST END: testPublicKey()");

    }

    private void getRsaPublicKeyTest(Algorithm algorithm, int keysize, int componentLength)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidSessionException, InvalidKeySpecException, InvalidParameterSpecException,
                   UnsupportedAlgorithmException, NoSuchProviderException {

        final short id = 0x1234;
        PublicKey pubKey = importRsaKey(id, "", Arrays.asList(2, 5), Arrays.asList(Capability.SIGN_PSS), algorithm, keysize, componentLength);

        try {
            final YHObject keyinfo = yubihsm.getObjectInfo(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            final AsymmetricKey key = new AsymmetricKey(keyinfo);
            PublicKey returnedPubKey = (PublicKey) key.getPublicKey(session);
            assertEquals(pubKey, returnedPubKey);
        } finally {
            yubihsm.deleteObject(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
        }
    }

    private void getEcPublicKeyTest(Algorithm algorithm, String curve, int componentLength, boolean brainpool)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidSessionException, InvalidKeySpecException, UnsupportedAlgorithmException,
                   InvalidParameterSpecException, NoSuchProviderException {
        final short id = 0x1234;
        PublicKey pubKey;
        if (brainpool) {
            pubKey = importEcBrainpoolKey(id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.SIGN_ECDSA), algorithm, curve, componentLength);
        } else {
            pubKey = importEcKey(id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.SIGN_ECDSA), algorithm, curve, componentLength);
        }

        try {
            final YHObject keyinfo = yubihsm.getObjectInfo(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            final AsymmetricKey key = new AsymmetricKey(keyinfo);
            PublicKey returnedPubKey = (PublicKey) key.getPublicKey(session);
            assertEquals(pubKey, returnedPubKey);
        } finally {
            yubihsm.deleteObject(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
        }
    }

    private void getEdPublicKeyTest() throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException,
                                             YHDeviceException, InvalidAlgorithmParameterException, YHAuthenticationException,
                                             YHInvalidResponseException, BadPaddingException, IllegalBlockSizeException, InvalidSessionException,
                                             InvalidKeySpecException, UnsupportedAlgorithmException, InvalidParameterSpecException,
                                             NoSuchProviderException {
        final short id = 0x1234;
        Ed25519PublicKeyParameters pubKey = importEdKey(id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.SIGN_EDDSA));

        try {
            final YHObject keyinfo = yubihsm.getObjectInfo(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            final AsymmetricKey key = new AsymmetricKey(keyinfo);
            byte[] returnedPubKeyBytes = (byte[]) key.getPublicKey(session);
            assertTrue("Returned EDDSA public key is not correct", Arrays.equals(pubKey.getEncoded(), returnedPubKeyBytes));

        } finally {
            yubihsm.deleteObject(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
        }

    }

    // ----------------------------------------------------------------------------------------------------
    //                                         Signing
    // ----------------------------------------------------------------------------------------------------

    @Test
    public void testSignDataWithError() throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException,
                                               YHDeviceException, InvalidAlgorithmParameterException, YHAuthenticationException,
                                               YHInvalidResponseException, BadPaddingException, IllegalBlockSizeException, InvalidSessionException,
                                               InvalidKeySpecException, SignatureException, NoSuchProviderException {
        final short id = 0x1234;
        PublicKey pubKey = importRsaKey(id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.SIGN_PKCS), Algorithm.RSA_2048, 2048,
                                        128);
        try {
            final YHObject keyinfo = yubihsm.getObjectInfo(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            final AsymmetricKey key = new AsymmetricKey(keyinfo);

            try {
                signPss(pubKey, key, Algorithm.RSA_MGF1_SHA256, "SHA256withRSA/PSS", "SHA-256", (short) 32);
            } catch (YHDeviceException e) {
                assertEquals("Device returned incorrect error", YHError.INSUFFICIENT_PERMISSIONS, e.getErrorCode());
            }

            try {
                signEcdsa(pubKey, key, Algorithm.EC_ECDSA_SHA256, "SHA256withECDSA");
            } catch (UnsupportedOperationException e) {
                // Expected behaviour
            }


        } finally {
            yubihsm.deleteObject(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
        }
    }

    @Test
    public void testSignData() throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException,
                                      YHDeviceException, InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException,
                                      BadPaddingException, IllegalBlockSizeException, InvalidSessionException, InvalidKeySpecException,
                                      SignatureException, NoSuchProviderException {
        logger.info("TEST START: testSignData()");

        signPkcs1Test(Algorithm.RSA_2048, 2048, 128);
        signPkcs1Test(Algorithm.RSA_3072, 3072, 192);
        signPkcs1Test(Algorithm.RSA_4096, 4096, 256);

        signPssTest(Algorithm.RSA_2048, 2048, 128);
        signPssTest(Algorithm.RSA_3072, 3072, 192);
        signPssTest(Algorithm.RSA_4096, 4096, 256);

        signEcdsaTest(Algorithm.EC_P224, "secp224r1", 28);
        signEcdsaTest(Algorithm.EC_P256, "secp256r1", 32);
        signEcdsaTest(Algorithm.EC_P384, "secp384r1", 48);
        signEcdsaTest(Algorithm.EC_P521, "secp521r1", 66);
        signEcdsaTest(Algorithm.EC_K256, "secp256k1", 32);

        signEcdsaBrainpoolTest(Algorithm.EC_BP256, "brainpoolP256r1", 32);
        signEcdsaBrainpoolTest(Algorithm.EC_BP384, "brainpoolP384r1", 48);
        signEcdsaBrainpoolTest(Algorithm.EC_BP512, "brainpoolP512r1", 64);

        signEddsaTest();

        logger.info("TEST END: testSignData()");
    }

    private void signPkcs1Test(Algorithm keyAlgorithm, int keysize, int componentLength)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidSessionException, InvalidKeySpecException, SignatureException {

        final short id = 0x1234;
        PublicKey pubKey = importRsaKey(id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.SIGN_PKCS), keyAlgorithm, keysize,
                                        componentLength);
        try {
            final YHObject keyinfo = yubihsm.getObjectInfo(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            final AsymmetricKey key = new AsymmetricKey(keyinfo);

            signPkcs1(pubKey, key, Algorithm.RSA_PKCS1_SHA1, "SHA1withRSA");
            signPkcs1(pubKey, key, Algorithm.RSA_PKCS1_SHA256, "SHA256withRSA");
            signPkcs1(pubKey, key, Algorithm.RSA_PKCS1_SHA384, "SHA384withRSA");
            signPkcs1(pubKey, key, Algorithm.RSA_PKCS1_SHA512, "SHA512withRSA");
        } finally {
            yubihsm.deleteObject(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
        }
    }

    private void signPkcs1(PublicKey pubKey, AsymmetricKey rsaKey, Algorithm hashAlgorithm, String signatureAlgorithm)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, SignatureException {

        final byte[] data = "This is a signing test data".getBytes();
        final byte[] signature = rsaKey.signPkcs1(session, data, hashAlgorithm);

        Signature sig = Signature.getInstance(signatureAlgorithm);
        sig.initVerify(pubKey);
        sig.update(data);
        assertTrue(sig.verify(signature));
    }

    private void signPssTest(Algorithm keyAlgorithm, int keysize, int componentLength)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidSessionException, InvalidKeySpecException, SignatureException, NoSuchProviderException {
        final short id = 0x1234;
        PublicKey pubKey = importRsaKey(id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.SIGN_PSS), keyAlgorithm, keysize,
                                        componentLength);

        try {
            final YHObject keyinfo = yubihsm.getObjectInfo(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            final AsymmetricKey key = new AsymmetricKey(keyinfo);

            signPss(pubKey, key, Algorithm.RSA_MGF1_SHA1, "SHA1withRSA/PSS", "SHA-1", (short) 32);
            signPss(pubKey, key, Algorithm.RSA_MGF1_SHA256, "SHA256withRSA/PSS", "SHA-256", (short) 32);
            signPss(pubKey, key, Algorithm.RSA_MGF1_SHA384, "SHA384withRSA/PSS", "SHA-384", (short) 32);
            signPss(pubKey, key, Algorithm.RSA_MGF1_SHA512, "SHA512withRSA/PSS", "SHA-512", (short) 32);

        } finally {
            yubihsm.deleteObject(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
        }
    }

    private void signPss(PublicKey pubKey, AsymmetricKey rsaKey, Algorithm signAlgorithm, String signAlgorithmStr, String hashAlgorithm,
                         short saltLength)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, SignatureException, NoSuchProviderException {

        final byte[] data = "This is a signing test data".getBytes();
        final byte[] signature = rsaKey.signPss(session, signAlgorithm, saltLength, data);

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Signature sig = Signature.getInstance(signAlgorithmStr, "BC");
        MGF1ParameterSpec mgf1Param = new MGF1ParameterSpec(hashAlgorithm);
        PSSParameterSpec pssParam = new PSSParameterSpec(hashAlgorithm, "MGF1", mgf1Param, saltLength, 1);
        sig.setParameter(pssParam);
        sig.initVerify(pubKey);
        sig.update(data);
        assertTrue(sig.verify(signature));
    }

    private void signEcdsaTest(Algorithm keyAlgorithm, String curve, int componentLength)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidSessionException, SignatureException {
        final short id = 0x1234;
        PublicKey pubKey = importEcKey(id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.SIGN_ECDSA), keyAlgorithm, curve, componentLength);

        try {
            final YHObject keyinfo = yubihsm.getObjectInfo(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            final AsymmetricKey key = new AsymmetricKey(keyinfo);

            signEcdsa(pubKey, key, Algorithm.EC_ECDSA_SHA1, "SHA1withECDSA");
            signEcdsa(pubKey, key, Algorithm.EC_ECDSA_SHA256, "SHA256withECDSA");
            signEcdsa(pubKey, key, Algorithm.EC_ECDSA_SHA384, "SHA384withECDSA");
            signEcdsa(pubKey, key, Algorithm.EC_ECDSA_SHA512, "SHA512withECDSA");

        } finally {
            yubihsm.deleteObject(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
        }
    }

    private void signEcdsa(PublicKey pubKey, AsymmetricKey ecKey, Algorithm signAlgorithm, String signAlgorithmStr)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, SignatureException {
        final byte[] data = "This is a signing test data".getBytes();
        final byte[] signature = ecKey.signEcdsa(session, data, signAlgorithm);

        Signature sig = Signature.getInstance(signAlgorithmStr);
        sig.initVerify(pubKey);
        sig.update(data);
        assertTrue(sig.verify(signature));
    }

    private void signEcdsaBrainpoolTest(Algorithm keyAlgorithm, String curve, int componentLength)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidSessionException, SignatureException, NoSuchProviderException {
        final short id = 0x1234;
        PublicKey pubKey =
                importEcBrainpoolKey(id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.SIGN_ECDSA), keyAlgorithm, curve, componentLength);

        try {
            final YHObject keyinfo = yubihsm.getObjectInfo(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            final AsymmetricKey key = new AsymmetricKey(keyinfo);

            signEcdsaBrainpool(pubKey, key, Algorithm.EC_ECDSA_SHA1, "SHA1withECDSA");
            signEcdsaBrainpool(pubKey, key, Algorithm.EC_ECDSA_SHA256, "SHA256withECDSA");
            signEcdsaBrainpool(pubKey, key, Algorithm.EC_ECDSA_SHA384, "SHA384withECDSA");
            signEcdsaBrainpool(pubKey, key, Algorithm.EC_ECDSA_SHA512, "SHA512withECDSA");

        } finally {
            yubihsm.deleteObject(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
        }
    }

    private void signEcdsaBrainpool(PublicKey pubKey, AsymmetricKey ecKey, Algorithm signAlgorithm, String signAlgorithmStr)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, SignatureException, NoSuchProviderException {
        final byte[] data = "This is a signing test data".getBytes();
        final byte[] signature = ecKey.signEcdsa(session, data, signAlgorithm);

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Signature sig = Signature.getInstance(signAlgorithmStr, "BC");
        sig.initVerify(pubKey);
        sig.update(data);
        assertTrue(sig.verify(signature));
    }

    private void signEddsaTest() throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException,
                                        YHDeviceException, InvalidAlgorithmParameterException, YHAuthenticationException,
                                        YHInvalidResponseException, BadPaddingException, IllegalBlockSizeException, InvalidSessionException {
        final short id = 0x1234;
        Ed25519PublicKeyParameters pubKey = importEdKey(id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.SIGN_EDDSA));

        try {
            final YHObject keyinfo = yubihsm.getObjectInfo(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
            final AsymmetricKey key = new AsymmetricKey(keyinfo);

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
    }

}
