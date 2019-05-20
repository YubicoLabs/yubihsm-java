package yhobjectstest;

import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.yhconcepts.Algorithm;
import com.yubico.hsm.yhconcepts.Capability;
import com.yubico.hsm.yhconcepts.Origin;
import com.yubico.hsm.yhconcepts.Type;
import com.yubico.hsm.yhdata.YHObjectInfo;
import com.yubico.hsm.yhobjects.HmacKey;
import com.yubico.hsm.yhobjects.YHObject;
import lombok.extern.slf4j.Slf4j;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import static org.junit.Assert.*;

@Slf4j
public class HmacKeyTest {

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
    public void testGenerateHmacKey() throws Exception {
        log.info("TEST START: testGenerateHmacKey()");
        generateHmacKey(Algorithm.HMAC_SHA1);
        generateHmacKey(Algorithm.HMAC_SHA256);
        generateHmacKey(Algorithm.HMAC_SHA384);
        generateHmacKey(Algorithm.HMAC_SHA512);
        log.info("TEST END: testGenerateHmacKey()");
    }

    private void generateHmacKey(Algorithm keyAlgorithm) throws Exception {
        log.info("Test generating an HMAC key with algorithm " + keyAlgorithm.getName());
        List domains = Arrays.asList(2, 5, 8);
        List capabilities = Capability.ALL;
        String label = "test_wrap_key";

        short id = HmacKey.generateHmacKey(session, (short) 0, label, domains, keyAlgorithm, capabilities);

        try {
            final YHObjectInfo hmackey = YHObject.getObjectInfo(session, id, Type.TYPE_HMAC_KEY);
            assertEquals(id, hmackey.getId());
            assertEquals(Type.TYPE_HMAC_KEY, hmackey.getType());
            assertEquals(domains, hmackey.getDomains());
            assertEquals(keyAlgorithm, hmackey.getAlgorithm());
            assertEquals(Origin.YH_ORIGIN_GENERATED, hmackey.getOrigin());
            assertEquals(label, hmackey.getLabel());
            assertEquals(capabilities.size(), hmackey.getCapabilities().size());
            assertTrue(hmackey.getCapabilities().containsAll(capabilities));
            assertTrue(hmackey.getDelegatedCapabilities().isEmpty());
        } finally {
            YHObject.delete(session, id, Type.TYPE_HMAC_KEY);
        }
    }

    @Test
    public void testImportHmacKey() throws Exception {
        log.info("TEST START: testImportHmacKey()");
        importHmacKey(Algorithm.HMAC_SHA1, 20);
        importHmacKey(Algorithm.HMAC_SHA256, 32);
        importHmacKey(Algorithm.HMAC_SHA384, 48);
        importHmacKey(Algorithm.HMAC_SHA512, 64);
        log.info("TEST END: testImportHmacKey()");
    }

    private void importHmacKey(Algorithm keyAlgorithm, int keyLength) throws Exception {
        log.info("Test importing an HMAC key with algorithm " + keyAlgorithm.getName());
        List domains = Arrays.asList(2, 5, 8);
        List capabilities = Capability.ALL;
        String label = "test_wrap_key";

        byte[] key = new byte[keyLength];
        new SecureRandom().nextBytes(key);

        short id = HmacKey.importHmacKey(session, (short) 0, label, domains, keyAlgorithm, capabilities, key);

        try {
            final YHObjectInfo hmackey = YHObject.getObjectInfo(session, id, Type.TYPE_HMAC_KEY);
            assertEquals(id, hmackey.getId());
            assertEquals(Type.TYPE_HMAC_KEY, hmackey.getType());
            assertEquals(domains, hmackey.getDomains());
            assertEquals(keyAlgorithm, hmackey.getAlgorithm());
            assertEquals(Origin.YH_ORIGIN_IMPORTED, hmackey.getOrigin());
            assertEquals(label, hmackey.getLabel());
            assertEquals(capabilities.size(), hmackey.getCapabilities().size());
            assertTrue(hmackey.getCapabilities().containsAll(capabilities));
            assertTrue(hmackey.getDelegatedCapabilities().isEmpty());
        } finally {
            YHObject.delete(session, id, Type.TYPE_HMAC_KEY);
        }
    }

    @Test
    public void testImportHmacKeyDifferentLengths() throws Exception {
        log.info("TEST START: testImportHmacKey()");
        importHmacKey(Algorithm.HMAC_SHA1, 0, false);
        importHmacKey(Algorithm.HMAC_SHA1, 1, true);
        importHmacKey(Algorithm.HMAC_SHA1, 64, true);
        importHmacKey(Algorithm.HMAC_SHA1, 65, false);

        importHmacKey(Algorithm.HMAC_SHA256, 0, false);
        importHmacKey(Algorithm.HMAC_SHA256, 1, true);
        importHmacKey(Algorithm.HMAC_SHA256, 64, true);
        importHmacKey(Algorithm.HMAC_SHA256, 65, false);

        importHmacKey(Algorithm.HMAC_SHA384, 0, false);
        importHmacKey(Algorithm.HMAC_SHA384, 1, true);
        importHmacKey(Algorithm.HMAC_SHA384, 128, true);
        importHmacKey(Algorithm.HMAC_SHA384, 129, false);

        importHmacKey(Algorithm.HMAC_SHA512, 0, false);
        importHmacKey(Algorithm.HMAC_SHA512, 1, true);
        importHmacKey(Algorithm.HMAC_SHA512, 128, true);
        importHmacKey(Algorithm.HMAC_SHA512, 129, false);
        log.info("TEST END: testImportHmacKey()");
    }

    private void importHmacKey(Algorithm keyAlgorithm, int keyLength, boolean success) throws Exception {
        log.info("Testing importing HMAC key with algorithm " + keyAlgorithm.getName() + " and key length " + keyLength + " bytes");

        short id = (short) 0x1234;

        try {
            assertFalse(YHObject.exists(session, id, HmacKey.TYPE));

            byte[] key = new byte[keyLength];
            new SecureRandom().nextBytes(key);

            boolean exceptionThrown = false;
            try {
                HmacKey.importHmacKey(session, id, "", Arrays.asList(2, 5, 8), keyAlgorithm, Capability.ALL, key);
            } catch (IllegalArgumentException e) {
                exceptionThrown = true;
            }
            assertEquals(!success, exceptionThrown);

            if (success) {
                assertTrue(YHObject.exists(session, id, HmacKey.TYPE));
            }
        } finally {
            YHObject.delete(session, id, HmacKey.TYPE);
        }
    }

    @Test
    public void testSignVerifyHmac() throws Exception {
        log.info("TEST START: testSignHmac()");
        signVerifyHmacDifferentLengths(Algorithm.HMAC_SHA1, 20, "HmacSHA1");
        signVerifyHmacDifferentLengths(Algorithm.HMAC_SHA256, 32, "HmacSHA256");
        signVerifyHmacDifferentLengths(Algorithm.HMAC_SHA384, 48, "HmacSHA384");
        signVerifyHmacDifferentLengths(Algorithm.HMAC_SHA512, 64, "HmacSHA512");

        verifyHmacDifferentAlgorithm(Algorithm.HMAC_SHA1, 20, "HmacSHA256");
        verifyHmacDifferentAlgorithm(Algorithm.HMAC_SHA256, 32, "HmacSHA384");
        verifyHmacDifferentAlgorithm(Algorithm.HMAC_SHA384, 48, "HmacSHA512");
        verifyHmacDifferentAlgorithm(Algorithm.HMAC_SHA512, 64, "HmacSHA1");

        verifyHmacDifferentKey(Algorithm.HMAC_SHA1, 20, "HmacSHA1");
        verifyHmacDifferentKey(Algorithm.HMAC_SHA256, 32, "HmacSHA256");
        verifyHmacDifferentKey(Algorithm.HMAC_SHA384, 48, "HmacSHA384");
        verifyHmacDifferentKey(Algorithm.HMAC_SHA512, 64, "HmacSHA512");

        log.info("TEST END: testSignHmac()");
    }

    private void signVerifyHmacDifferentLengths(Algorithm keyAlgorithm, int keyLength, String hmacAlgorithm) throws Exception {
        byte[] key = new byte[keyLength];
        new SecureRandom().nextBytes(key);

        short id = HmacKey.importHmacKey(session, (short) 0, "", Arrays.asList(2, 5, 8), keyAlgorithm, Capability.ALL, key);

        try {
            HmacKey hmacKey = new HmacKey(id, keyAlgorithm);

            verifyHmacSignature("test signing data".getBytes(), hmacKey, key, hmacAlgorithm, true);
            verifyHmacVerification("test signing data".getBytes(), hmacKey, key, hmacAlgorithm, true);

            verifyHmacSignature(new byte[0], hmacKey, key, hmacAlgorithm, false);
            verifyHmacVerification(new byte[0], hmacKey, key, hmacAlgorithm, false);

            byte[] data = new byte[1];
            new Random().nextBytes(data);
            verifyHmacSignature(data, hmacKey, key, hmacAlgorithm, true);
            verifyHmacVerification(data, hmacKey, key, hmacAlgorithm, true);

            data = new byte[1024];
            new Random().nextBytes(data);
            verifyHmacSignature(data, hmacKey, key, hmacAlgorithm, true);
            verifyHmacVerification(data, hmacKey, key, hmacAlgorithm, true);

            data = new byte[2048];
            new Random().nextBytes(data);
            verifyHmacSignature(data, hmacKey, key, hmacAlgorithm, false);
            verifyHmacVerification(data, hmacKey, key, hmacAlgorithm, false);
        } finally {
            YHObject.delete(session, id, Type.TYPE_HMAC_KEY);
        }

    }

    private void verifyHmacSignature(byte[] data, HmacKey hmacKey, byte[] hmacKeyBytes, String hmacAlgorithm, boolean success) throws Exception {
        log.info("Testing HMAC signing with " + data.length + " bytes long data and HMAC key algorithm " + hmacKey.getKeyAlgorithm().getName() +
                 " Expecting " + (success ? "success" : "failure"));

        if (success) {
            byte[] yhHmac = hmacKey.signHmac(session, data);

            SecretKeySpec signingKey = new SecretKeySpec(hmacKeyBytes, hmacAlgorithm);
            Mac mac = Mac.getInstance(hmacAlgorithm);
            mac.init(signingKey);
            byte[] hmac = mac.doFinal(data);
            assertTrue(Arrays.equals(hmac, yhHmac));
        } else {
            boolean exceptionThrown = false;
            try {
                hmacKey.signHmac(session, data);
            } catch (Exception e) {
                exceptionThrown = true;
            }
            assertTrue(exceptionThrown);
        }
    }

    private void verifyHmacVerification(byte[] data, HmacKey hmacKey, byte[] hmacKeyBytes, String hmacAlgorithm, boolean success) throws Exception {
        log.info("Testing HMAC verification with " + data.length + " bytes long data and HMAC key algorithm " + hmacKey.getKeyAlgorithm().getName() +
                 " Expecting " + (success ? "success" : "failure"));

        SecretKeySpec signingKey = new SecretKeySpec(hmacKeyBytes, hmacAlgorithm);
        Mac mac = Mac.getInstance(hmacAlgorithm);
        mac.init(signingKey);
        byte[] hmac = mac.doFinal(data);

        if (success) {
            assertTrue(hmacKey.verifyHmac(session, data, hmac));
        } else {
            boolean exceptionThrown = false;
            try {
                hmacKey.verifyHmac(session, data, hmac);
            } catch (Exception e) {
                exceptionThrown = true;
            }
            assertTrue(exceptionThrown);
        }
    }

    private void verifyHmacDifferentAlgorithm(Algorithm keyAlgorithm, int keyLength, String hmacAlgorithm) throws Exception {
        log.info("Test verifying HMAC created with algorithm " + hmacAlgorithm + " with HMAC key of algorithm " + keyAlgorithm.getName());
        byte[] key = new byte[keyLength];
        new SecureRandom().nextBytes(key);

        byte[] data = "test signing data".getBytes();

        short id = HmacKey.importHmacKey(session, (short) 0, "", Arrays.asList(2, 5, 8), keyAlgorithm, Capability.ALL, key);

        try {

            SecretKeySpec signingKey = new SecretKeySpec(key, hmacAlgorithm);
            Mac mac = Mac.getInstance(hmacAlgorithm);
            mac.init(signingKey);
            byte[] hmac = mac.doFinal(data);

            HmacKey hmacKey = new HmacKey(id, keyAlgorithm);
            boolean exceptionThrown = false;
            try {
                hmacKey.verifyHmac(session, data, hmac);
            } catch (IllegalArgumentException e) {
                exceptionThrown = true;
            }
            assertTrue(exceptionThrown);
        } finally {
            YHObject.delete(session, id, Type.TYPE_HMAC_KEY);
        }
    }

    private void verifyHmacDifferentKey(Algorithm keyAlgorithm, int keyLength, String hmacAlgorithm) throws Exception {
        log.info("Test verifying HMAC created with algorithm " + keyAlgorithm.getName() + " but with a different HMAC key");
        byte[] data = "test signing data".getBytes();

        byte[] key = new byte[keyLength];
        new SecureRandom().nextBytes(key);
        SecretKeySpec signingKey = new SecretKeySpec(key, hmacAlgorithm);
        Mac mac = Mac.getInstance(hmacAlgorithm);
        mac.init(signingKey);
        byte[] hmac = mac.doFinal(data);

        byte[] yhkey = new byte[keyLength];
        new SecureRandom().nextBytes(yhkey);
        short id = HmacKey.importHmacKey(session, (short) 0, "", Arrays.asList(2, 5, 8), keyAlgorithm, Capability.ALL, yhkey);

        try {
            HmacKey hmacKey = new HmacKey(id, keyAlgorithm);
            assertFalse(hmacKey.verifyHmac(session, data, hmac));
        } finally {
            YHObject.delete(session, id, Type.TYPE_HMAC_KEY);
        }
    }
}
