package AsymmetricKeyTest;

import com.yubico.YHSession;
import com.yubico.YubiHsm;
import com.yubico.backend.Backend;
import com.yubico.backend.HttpBackend;
import com.yubico.exceptions.*;
import com.yubico.objects.yhconcepts.Algorithm;
import com.yubico.objects.yhconcepts.Capability;
import com.yubico.objects.yhconcepts.ObjectType;
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
import java.util.Arrays;
import java.util.logging.Logger;

import static org.junit.Assert.*;
import static org.junit.Assert.assertArrayEquals;

public class RsaDecryptTest {
    Logger logger = Logger.getLogger(RsaDecryptTest.class.getName());

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
    public void testDecryptDataWithInsufficientPermissions()
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidKeySpecException, SignatureException, NoSuchProviderException,
                   UnsupportedAlgorithmException {
        final short id = 0x1234;
        PublicKey pubKey = AsymmetricKeyTestHelper.importRsaKey(session, id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.SIGN_PKCS,
                                                                Capability.SIGN_PSS), Algorithm.RSA_2048, 2048, 128);
        try {
            AsymmetricKeyRsa key = new AsymmetricKeyRsa(id, Algorithm.RSA_2048);

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
            YHObject.deleteObject(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
        }
    }

    @Test
    public void testDecryptPkcs1()
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidKeySpecException, SignatureException, UnsupportedAlgorithmException,
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

    @Test
    public void testDecryptOaep()
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidKeySpecException, SignatureException, UnsupportedAlgorithmException,
                   NoSuchProviderException {
        logger.info("TEST START: testDecryptOaep()");

        decryptOaepTest(Algorithm.RSA_2048, 2048, 128);
        decryptOaepTest(Algorithm.RSA_3072, 3072, 192);
        decryptOaepTest(Algorithm.RSA_4096, 4096, 256);

        logger.info("TEST END: testDecryptOaep()");
    }

    // --------------------------------------------------------------------------------------------------

    private void decryptPkcs1Test(Algorithm keyAlgorithm, int keysize, int componentLength, byte[] data)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidKeySpecException, UnsupportedAlgorithmException {

        final short id = 0x1234;
        PublicKey publicKey =
                AsymmetricKeyTestHelper.importRsaKey(session, id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.DECRYPT_PKCS), keyAlgorithm,
                                                     keysize, componentLength);

        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] enc = cipher.doFinal(data);

            AsymmetricKeyRsa key = new AsymmetricKeyRsa(id, keyAlgorithm);
            byte[] dec = key.decryptPkcs1(session, enc);

            assertArrayEquals(data, dec);
        } finally {
            YHObject.deleteObject(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
        }
    }

    private void decryptOaepTest(Algorithm keyAlgorithm, int keysize, int componentLength)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidKeySpecException, SignatureException, UnsupportedAlgorithmException,
                   NoSuchProviderException {

        final short id = 0x1234;
        PublicKey publicKey =
                AsymmetricKeyTestHelper.importRsaKey(session, id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.DECRYPT_OAEP), keyAlgorithm,
                                                     keysize, componentLength);

        try {
            AsymmetricKeyRsa key = new AsymmetricKeyRsa(id, keyAlgorithm);

            decryptOaep(key, publicKey, Algorithm.RSA_MGF1_SHA1, Algorithm.RSA_OAEP_SHA1, "RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
            decryptOaep(key, publicKey, Algorithm.RSA_MGF1_SHA1, Algorithm.RSA_OAEP_SHA256, "RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            decryptOaep(key, publicKey, Algorithm.RSA_MGF1_SHA1, Algorithm.RSA_OAEP_SHA384, "RSA/ECB/OAEPWithSHA-384AndMGF1Padding");
            decryptOaep(key, publicKey, Algorithm.RSA_MGF1_SHA1, Algorithm.RSA_OAEP_SHA512, "RSA/ECB/OAEPWithSHA-512AndMGF1Padding");

            decryptOaepBc(key, publicKey, Algorithm.RSA_MGF1_SHA1, Algorithm.RSA_OAEP_SHA1, "RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
            decryptOaepBc(key, publicKey, Algorithm.RSA_MGF1_SHA256, Algorithm.RSA_OAEP_SHA256, "RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            decryptOaepBc(key, publicKey, Algorithm.RSA_MGF1_SHA384, Algorithm.RSA_OAEP_SHA384, "RSA/ECB/OAEPWithSHA-384AndMGF1Padding");
            decryptOaepBc(key, publicKey, Algorithm.RSA_MGF1_SHA512, Algorithm.RSA_OAEP_SHA512, "RSA/ECB/OAEPWithSHA-512AndMGF1Padding");


        } finally {
            YHObject.deleteObject(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
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
