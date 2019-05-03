import com.yubico.YHSession;
import com.yubico.YubiHsm;
import com.yubico.backend.Backend;
import com.yubico.backend.HttpBackend;
import com.yubico.exceptions.YHDeviceException;
import com.yubico.exceptions.YHError;
import com.yubico.objects.YubicoOtpData;
import com.yubico.objects.yhconcepts.Algorithm;
import com.yubico.objects.yhconcepts.Capability;
import com.yubico.objects.yhconcepts.ObjectOrigin;
import com.yubico.objects.yhconcepts.ObjectType;
import com.yubico.objects.yhobjects.OtpAeadKey;
import com.yubico.objects.yhobjects.YHObject;
import com.yubico.objects.yhobjects.YHObjectInfo;
import org.bouncycastle.util.encoders.Hex;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.annotation.Nonnull;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.logging.Logger;

import static org.junit.Assert.*;

public class OtpAeadKeyTest {
    Logger log = Logger.getLogger(OtpAeadKeyTest.class.getName());

    private static YubiHsm yubihsm;
    private static YHSession session;

    @BeforeClass
    public static void init() throws Exception {
        if (session == null) {
            Backend backend = new HttpBackend();
            yubihsm = new YubiHsm(backend);
            session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
            session.createAuthenticatedSession();
        }
    }

    @AfterClass
    public static void destroy() throws Exception {
        session.closeSession();
        yubihsm.close();
    }

    @Test
    public void testGenerateOtpAeadKey() throws Exception {
        log.info("TEST START: testGenerateOtpAeadKey()");
        generateOtpAead(Algorithm.AES128_YUBICO_OTP);
        generateOtpAead(Algorithm.AES192_YUBICO_OTP);
        generateOtpAead(Algorithm.AES256_YUBICO_OTP);
        log.info("TEST END: testGenerateOtpAeadKey()");
    }

    private void generateOtpAead(Algorithm keyAlgorithm) throws Exception {
        log.info("Test generating OTP AEAD key with algorithm " + keyAlgorithm.getName());
        List domains = Arrays.asList(2, 5, 8);
        List capabilities = Arrays.asList(Capability.CREATE_OTP_AEAD, Capability.DECRYPT_OTP);
        String label = "test_otp-aead_key";

        short id = OtpAeadKey.generateOtpAeadKey(session, (short) 0, label, domains, keyAlgorithm, capabilities, 4711);

        try {
            final YHObjectInfo key = YHObject.getObjectInfo(session, id, ObjectType.TYPE_OTP_AEAD_KEY);
            assertEquals(id, key.getId());
            assertEquals(ObjectType.TYPE_OTP_AEAD_KEY, key.getType());
            assertEquals(domains, key.getDomains());
            assertEquals(keyAlgorithm, key.getAlgorithm());
            assertEquals(ObjectOrigin.YH_ORIGIN_GENERATED, key.getOrigin());
            assertEquals(label, key.getLabel());
            assertEquals(capabilities.size(), key.getCapabilities().size());
            assertTrue(key.getCapabilities().containsAll(capabilities));
            assertEquals(0, key.getDelegatedCapabilities().size());
        } finally {
            YHObject.deleteObject(session, id, ObjectType.TYPE_OTP_AEAD_KEY);
        }
    }

    @Test
    public void testImportOtpAeadKey() throws Exception {
        log.info("TEST START: testImportOtpAeadKey()");
        importOtpAeadKey(Algorithm.AES128_YUBICO_OTP, 16);
        importOtpAeadKey(Algorithm.AES192_YUBICO_OTP, 24);
        importOtpAeadKey(Algorithm.AES256_YUBICO_OTP, 32);
        log.info("TEST END: testImportOtpAeadKey()");
    }

    private void importOtpAeadKey(Algorithm keyAlgorithm, int keyLength) throws Exception {
        log.info("Test importing " + keyLength + " bytes long OTP AEAD key with algorithm " + keyAlgorithm.getName());
        byte[] otpAeadKey = new byte[keyLength];
        new SecureRandom().nextBytes(otpAeadKey);
        byte[] nonceId = new byte[4];
        new Random().nextBytes(nonceId);

        List domains = Arrays.asList(2, 5, 8);
        List capabilities = Arrays.asList(Capability.CREATE_OTP_AEAD, Capability.DECRYPT_OTP);
        String label = "test_otp_aead_key";
        short id = (short) 0x1234;

        OtpAeadKey.importOtpAeadKey(session, id, label, domains, keyAlgorithm, capabilities, nonceId, otpAeadKey);

        try {
            final YHObjectInfo key = YHObject.getObjectInfo(session, id, ObjectType.TYPE_OTP_AEAD_KEY);
            assertEquals(id, key.getId());
            assertEquals(ObjectType.TYPE_OTP_AEAD_KEY, key.getType());
            assertEquals(domains, key.getDomains());
            assertEquals(keyAlgorithm, key.getAlgorithm());
            assertEquals(ObjectOrigin.YH_ORIGIN_IMPORTED, key.getOrigin());
            assertEquals(label, key.getLabel());
            assertEquals(capabilities.size(), key.getCapabilities().size());
            assertTrue(key.getCapabilities().containsAll(capabilities));
            assertEquals(0, key.getDelegatedCapabilities().size());
        } finally {
            YHObject.deleteObject(session, id, ObjectType.TYPE_OTP_AEAD_KEY);
        }
    }

    @Test
    public void testRandomizeOtpAead() throws Exception {
        byte[] keyBytes = new byte[16];
        new SecureRandom().nextBytes(keyBytes);
        byte[] nonceId = new BigInteger("01234567", 16).toByteArray();


        short id = OtpAeadKey.importOtpAeadKey(session, (short) 0, "Test OTP Randomize AEAD", Arrays.asList(1), Algorithm.AES128_YUBICO_OTP,
                                               Arrays.asList(Capability.CREATE_OTP_AEAD, Capability.RANDOMIZE_OTP_AEAD), nonceId, keyBytes);
        try {
            OtpAeadKey key = new OtpAeadKey(id);

            byte[] aead = key.randomizeOtpAed(session);
            assertEquals(36, aead.length);

            TestVector v = getTestVectors().get(3);
            byte[] aead2 = key.createOtpAed(session, v.key, v.privateId);

            assertFalse(Arrays.equals(aead, aead2));

        } finally {
            YHObject.deleteObject(session, id, ObjectType.TYPE_OTP_AEAD_KEY);
        }


    }

    @Test
    public void testDecryptInvalidOtp() throws Exception {

        short keyId = OtpAeadKey.generateOtpAeadKey(session, (short) 0, "Test OTP invalid", Arrays.asList(1), Algorithm.AES128_YUBICO_OTP,
                                                    Arrays.asList(Capability.RANDOMIZE_OTP_AEAD, Capability.DECRYPT_OTP), 0x12345678);
        try {
            OtpAeadKey key = new OtpAeadKey(keyId);

            byte[] aead = key.randomizeOtpAed(session);

            byte[] random = new byte[16];
            new SecureRandom().nextBytes(random);
            boolean exceptionThrown = false;
            try {
                key.decryptOtp(session, aead, random);
            } catch (YHDeviceException e) {
                exceptionThrown = true;
                assertEquals(YHError.INVALID_OTP, e.getYhError());
            }
            assertTrue(exceptionThrown);

            random = Arrays.copyOf(random, 15);
            exceptionThrown = false;
            try {
                key.decryptOtp(session, aead, random);
            } catch (IllegalArgumentException e) {
                exceptionThrown = true;
            }
            assertTrue(exceptionThrown);
        } finally {
            YHObject.deleteObject(session, keyId, ObjectType.TYPE_OTP_AEAD_KEY);
        }
    }


    @Test
    public void testOtpTestVectors() throws Exception {
        short key1Id = 0x100;
        short key2Id = 0x200;
        short key3Id = 0x300;

        try {

            OtpAeadKey.generateOtpAeadKey(session, key1Id, "Test OTP TestVectors", Arrays.asList(1), Algorithm.AES128_YUBICO_OTP,
                                          Arrays.asList(Capability.CREATE_OTP_AEAD, Capability.REWRAP_FROM_OTP_AEAD_KEY,
                                                        Capability.DECRYPT_OTP), 0x12345678);
            OtpAeadKey key1 = new OtpAeadKey(key1Id);


            OtpAeadKey.generateOtpAeadKey(session, key2Id, "Test OTP TestVectors", Arrays.asList(1), Algorithm.AES192_YUBICO_OTP,
                                          Arrays.asList(Capability.REWRAP_FROM_OTP_AEAD_KEY, Capability.REWRAP_TO_OTP_AEAD_KEY,
                                                        Capability.DECRYPT_OTP), 0x87654321);
            OtpAeadKey key2 = new OtpAeadKey(key2Id);

            byte[] key3data = new byte[32];
            new SecureRandom().nextBytes(key3data);
            byte[] key3NonceId = {0x00, 0x00, 0x00, 0x01};
            OtpAeadKey.importOtpAeadKey(session, key3Id, "Test OTP TestVectors", Arrays.asList(1), Algorithm.AES256_YUBICO_OTP,
                                        Arrays.asList(Capability.DECRYPT_OTP, Capability.CREATE_OTP_AEAD,
                                                      Capability.REWRAP_TO_OTP_AEAD_KEY), key3NonceId, key3data);
            OtpAeadKey key3 = new OtpAeadKey(key3Id);


            for (TestVector v : getTestVectors()) {
                byte[] aead1 = key1.createOtpAed(session, v.key, v.privateId);
                byte[] aead2 = OtpAeadKey.rewrapOtpAead(session, key1.getId(), key2.getId(), aead1);
                assertFalse(Arrays.equals(aead1, aead2));


                byte[] aead3 = OtpAeadKey.rewrapOtpAead(session, key2.getId(), key3.getId(), aead2);
                assertFalse(Arrays.equals(aead1, aead3));
                assertFalse(Arrays.equals(aead2, aead3));
                assertFalse(Arrays.equals(aead1, key3.createOtpAed(session, v.key, v.privateId)));

                for (int i = 0; i < v.otps.size(); i++) {
                    String otpHex = encodedStringToHex(v.otps.get(i));
                    byte[] otpBin = Hex.decode(otpHex);
                    assertEquals(v.otpsData.get(i), key1.decryptOtp(session, aead1, otpBin));
                    assertEquals(v.otpsData.get(i), key2.decryptOtp(session, aead2, otpBin));
                    assertEquals(v.otpsData.get(i), key3.decryptOtp(session, aead3, otpBin));
                }

            }
        } finally {
            try {
                YHObject.deleteObject(session, key1Id, ObjectType.TYPE_OTP_AEAD_KEY);
            } catch (YHDeviceException e) {
                if (!e.getYhError().equals(YHError.OBJECT_NOT_FOUND)) {
                    throw e;
                }
            }

            try {
                YHObject.deleteObject(session, key2Id, ObjectType.TYPE_OTP_AEAD_KEY);
            } catch (YHDeviceException e) {
                if (!e.getYhError().equals(YHError.OBJECT_NOT_FOUND)) {
                    throw e;
                }
            }

            try {
                YHObject.deleteObject(session, key3Id, ObjectType.TYPE_OTP_AEAD_KEY);
            } catch (YHDeviceException e) {
                if (!e.getYhError().equals(YHError.OBJECT_NOT_FOUND)) {
                    throw e;
                }
            }

        }


    }


    private String encodedStringToHex(@Nonnull String string) {
        List from = Arrays.asList('c', 'b', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'n', 'r', 't', 'u', 'v');
        List to = Arrays.asList('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f');

        char[] newString = string.toCharArray();
        for (int i = 0; i < newString.length; i++) {
            newString[i] = (char) to.get(from.indexOf(newString[i]));
        }
        return new String(newString);
    }

    private List<TestVector> getTestVectors() {
        List<TestVector> testVectors = new ArrayList<TestVector>();
        byte[] key1 = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
        byte[] id1 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        testVectors.add(new TestVector(key1, id1,
                                       Arrays.asList("dvgtiblfkbgturecfllberrvkinnctnn", "rnibcnfhdninbrdebccrndfhjgnhftee",
                                                     "iikkijbdknrrdhfdrjltvgrbkkjblcbh"),
                                       Arrays.asList(new YubicoOtpData((short) 1, (byte) 1, (byte) 1, (short) 1),
                                                     new YubicoOtpData((short) 1, (byte) 2, (byte) 1, (short) 1),
                                                     new YubicoOtpData((short) 0xfff, (byte) 1, (byte) 1, (short) 1))
        ));

        byte[] key2 =
                {(byte) 0x88, (byte) 0x88, (byte) 0x88, (byte) 0x88, (byte) 0x88, (byte) 0x88, (byte) 0x88, (byte) 0x88, (byte) 0x88, (byte) 0x88,
                 (byte) 0x88, (byte) 0x88, (byte) 0x88, (byte) 0x88, (byte) 0x88, (byte) 0x88};
        byte[] id2 = {(byte) 0x88, (byte) 0x88, (byte) 0x88, (byte) 0x88, (byte) 0x88, (byte) 0x88};
        testVectors.add(new TestVector(key2, id2,
                                       Arrays.asList("dcihgvrhjeucvrinhdfddbjhfjftjdei"),
                                       Arrays.asList(new YubicoOtpData((short) 0x8888, (byte) 0x88, (byte) 0x88, (short) 0x8888))
        ));

        byte[] key3 = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        byte[] id3 = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        testVectors.add(new TestVector(key3, id3,
                                       Arrays.asList("kkkncjnvcnenkjvjgncjihljiibgbhbh"),
                                       Arrays.asList(new YubicoOtpData((short) 0, (byte) 0, (byte) 0, (short) 0))
        ));

        byte[] key4 =
                {(byte) 0xc4, (byte) 0x42, (byte) 0x28, (byte) 0x90, (byte) 0x65, (byte) 0x30, (byte) 0x76, (byte) 0xcd, (byte) 0xe7, (byte) 0x3d,
                 (byte) 0x44, (byte) 0x9b, (byte) 0x19, (byte) 0x1b, (byte) 0x41, (byte) 0x6a};
        byte[] id4 = {(byte) 0x33, (byte) 0xc6, (byte) 0x9e, (byte) 0x7f, (byte) 0x24, (byte) 0x9e};
        testVectors.add(new TestVector(key4, id4,
                                       Arrays.asList("iucvrkjiegbhidrcicvlgrcgkgurhjnj"),
                                       Arrays.asList(new YubicoOtpData((short) 1, (byte) 0, (byte) 0x24, (short) 0x13a7))

        ));

        return testVectors;
    }

    private class TestVector {
        private byte[] key;
        private byte[] privateId;
        List<String> otps;
        List<YubicoOtpData> otpsData;

        public TestVector(byte[] key, byte[] privateId, List<String> otps, List<YubicoOtpData> otpsData) {
            this.key = key;
            this.privateId = privateId;
            this.otps = otps;
            this.otpsData = otpsData;
        }
    }


}
