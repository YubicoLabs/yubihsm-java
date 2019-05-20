package yhobjectstest.asymmetrickeystest;

import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.exceptions.YHDeviceException;
import com.yubico.hsm.yhconcepts.Algorithm;
import com.yubico.hsm.yhconcepts.Capability;
import com.yubico.hsm.yhconcepts.Type;
import com.yubico.hsm.yhconcepts.YHError;
import com.yubico.hsm.yhobjects.AsymmetricKeyRsa;
import com.yubico.hsm.yhobjects.YHObject;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.Cipher;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Random;

import static org.junit.Assert.*;

@Slf4j
public class RsaDecryptTest {

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
    public void testDecryptDataWithInsufficientPermissions() throws Exception {
        log.info("TEST START: testDecryptDataWithInsufficientPermissions()");
        final short id = 0x1234;
        PublicKey pubKey = AsymmetricKeyTestHelper.importRsaKey(session, id, "", Arrays.asList(2, 5, 8),
                                                                Arrays.asList(Capability.SIGN_PKCS, Capability.SIGN_PSS), Algorithm.RSA_2048, 2048);
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
                assertEquals("Device returned incorrect error", YHError.INSUFFICIENT_PERMISSIONS, e.getYhError());
            }
            assertTrue("Succeeded to sign in spite of insufficient permissions", exceptionThrown);

            exceptionThrown = false;
            try {
                decryptOaep(key, pubKey, Algorithm.RSA_MGF1_SHA1, Algorithm.RSA_OAEP_SHA1, "RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
            } catch (YHDeviceException e) {
                exceptionThrown = true;
                assertEquals("Device returned incorrect error", YHError.INSUFFICIENT_PERMISSIONS, e.getYhError());
            }
            assertTrue("Succeeded to sign in spite of insufficient permissions", exceptionThrown);
        } finally {
            YHObject.delete(session, id, Type.TYPE_ASYMMETRIC_KEY);
        }
        log.info("TEST END: testDecryptDataWithInsufficientPermissions()");
    }

    @Test
    public void testDecryptPkcs1() throws Exception {
        log.info("TEST START: testDecryptPkcs1()");

        byte[] data = new byte[0];
        decryptPkcs1Test(Algorithm.RSA_2048, 2048, data);
        decryptPkcs1Test(Algorithm.RSA_3072, 3072, data);
        decryptPkcs1Test(Algorithm.RSA_4096, 4096, data);

        data = "This is test data for decryption".getBytes();
        decryptPkcs1Test(Algorithm.RSA_2048, 2048, data);
        decryptPkcs1Test(Algorithm.RSA_3072, 3072, data);
        decryptPkcs1Test(Algorithm.RSA_4096, 4096, data);

        data = new byte[244]; // The maximum number of bytes that can be encrypted using javax.crypto
        new Random().nextBytes(data);
        decryptPkcs1Test(Algorithm.RSA_2048, 2048, data);
        decryptPkcs1Test(Algorithm.RSA_3072, 3072, data);
        decryptPkcs1Test(Algorithm.RSA_4096, 4096, data);

        log.info("TEST END: testDecryptPkcs1()");
    }

    @Test
    public void testDecryptOaep() throws Exception {
        log.info("TEST START: testDecryptOaep()");
        decryptOaepTest(Algorithm.RSA_2048, 2048);
        decryptOaepTest(Algorithm.RSA_3072, 3072);
        decryptOaepTest(Algorithm.RSA_4096, 4096);
        log.info("TEST END: testDecryptOaep()");
    }

    // --------------------------------------------------------------------------------------------------

    private void decryptPkcs1Test(Algorithm keyAlgorithm, int keysize, byte[] data) throws Exception {
        log.info("Test decrypting data of length " + data.length + " with RSA key of algorithm " + keyAlgorithm.getName() + " using RSA-PKCS#1v1.5");

        final short id = 0x1234;
        PublicKey publicKey =
                AsymmetricKeyTestHelper.importRsaKey(session, id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.DECRYPT_PKCS), keyAlgorithm,
                                                     keysize);

        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] enc = cipher.doFinal(data);

            AsymmetricKeyRsa key = new AsymmetricKeyRsa(id, keyAlgorithm);
            byte[] dec = key.decryptPkcs1(session, enc);

            assertArrayEquals(data, dec);
        } finally {
            YHObject.delete(session, id, Type.TYPE_ASYMMETRIC_KEY);
        }
    }

    private void decryptOaepTest(Algorithm keyAlgorithm, int keysize) throws Exception {

        final short id = 0x1234;
        PublicKey publicKey =
                AsymmetricKeyTestHelper.importRsaKey(session, id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.DECRYPT_OAEP), keyAlgorithm,
                                                     keysize);

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
            YHObject.delete(session, id, Type.TYPE_ASYMMETRIC_KEY);
        }
    }

    private void decryptOaep(AsymmetricKeyRsa key, PublicKey pubKey, Algorithm mgf1Algorithm, Algorithm hashAlgorithm, String cipherAlgorithm)
            throws Exception {
        log.info("Test decrypting with RSA key of algorithm " + key.getKeyAlgorithm().getName() + " using RSA-OAEP");

        byte[] data = "This is test data for decryption".getBytes();

        Cipher cipher = Cipher.getInstance(cipherAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] enc = cipher.doFinal(data);

        byte[] dec = key.decryptOaep(session, enc, "", mgf1Algorithm, hashAlgorithm);

        assertArrayEquals(data, dec);
    }

    private void decryptOaepBc(AsymmetricKeyRsa key, PublicKey pubKey, Algorithm mgf1Algorithm, Algorithm hashAlgorithm, String cipherAlgorithm)
            throws Exception {
        log.info("Test decrypting with RSA key of algorithm " + key.getKeyAlgorithm().getName() + " using RSA-OAEP");

        byte[] data = "This is test data for decryption".getBytes();

        Security.addProvider(new BouncyCastleProvider());
        Cipher cipher = Cipher.getInstance(cipherAlgorithm, "BC");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey, new SecureRandom());
        byte[] enc = cipher.doFinal(data);

        byte[] dec = key.decryptOaep(session, enc, "", mgf1Algorithm, hashAlgorithm);

        assertArrayEquals(data, dec);
    }

}
