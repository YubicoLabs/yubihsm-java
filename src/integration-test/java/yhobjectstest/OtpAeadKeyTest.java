/*
 * Copyright 2019 Yubico AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package yhobjectstest;

import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.exceptions.YHDeviceException;
import com.yubico.hsm.yhconcepts.*;
import com.yubico.hsm.yhdata.YHObjectInfo;
import com.yubico.hsm.yhdata.YubicoOtpData;
import com.yubico.hsm.yhobjects.OtpAeadKey;
import com.yubico.hsm.yhobjects.YHObject;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.annotation.Nonnull;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;

import static org.junit.Assert.*;

@Slf4j
public class OtpAeadKeyTest {

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
        if(session != null) {
            session.closeSession();
            yubihsm.close();
        }
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
            final YHObjectInfo key = YHObject.getObjectInfo(session, id, Type.TYPE_OTP_AEAD_KEY);
            assertEquals(id, key.getId());
            assertEquals(Type.TYPE_OTP_AEAD_KEY, key.getType());
            assertEquals(domains, key.getDomains());
            assertEquals(keyAlgorithm, key.getAlgorithm());
            assertEquals(Origin.YH_ORIGIN_GENERATED, key.getOrigin());
            assertEquals(label, key.getLabel());
            assertEquals(capabilities.size(), key.getCapabilities().size());
            assertTrue(key.getCapabilities().containsAll(capabilities));
            assertEquals(0, key.getDelegatedCapabilities().size());
        } finally {
            YHObject.delete(session, id, Type.TYPE_OTP_AEAD_KEY);
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
            final YHObjectInfo key = YHObject.getObjectInfo(session, id, Type.TYPE_OTP_AEAD_KEY);
            assertEquals(id, key.getId());
            assertEquals(Type.TYPE_OTP_AEAD_KEY, key.getType());
            assertEquals(domains, key.getDomains());
            assertEquals(keyAlgorithm, key.getAlgorithm());
            assertEquals(Origin.YH_ORIGIN_IMPORTED, key.getOrigin());
            assertEquals(label, key.getLabel());
            assertEquals(capabilities.size(), key.getCapabilities().size());
            assertTrue(key.getCapabilities().containsAll(capabilities));
            assertEquals(0, key.getDelegatedCapabilities().size());
        } finally {
            YHObject.delete(session, id, Type.TYPE_OTP_AEAD_KEY);
        }
    }

    @Test
    public void testRandomizeOtpAead() throws Exception {
        log.info("TEST START: testRandomizeOtpAead()");
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
            YHObject.delete(session, id, Type.TYPE_OTP_AEAD_KEY);
        }
        log.info("TEST END: testRandomizeOtpAead()");
    }

    @Test
    public void testDecryptInvalidOtp() throws Exception {
        log.info("TEST START: testDecryptInvalidOtp()");

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
            YHObject.delete(session, keyId, Type.TYPE_OTP_AEAD_KEY);
        }
        log.info("TEST END: testDecryptInvalidOtp()");
    }


    @Test
    public void testKnownOtpTestVectors() throws Exception {
        log.info("TEST START: testKnownOtpTestVectors()");

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

                for (String otp : v.otps.keySet()) {
                    String otpHex = encodedStringToHex(otp);
                    byte[] otpBin = Hex.decode(otpHex);
                    assertEquals(v.otps.get(otp), key1.decryptOtp(session, aead1, otpBin));
                    assertEquals(v.otps.get(otp), key2.decryptOtp(session, aead2, otpBin));
                    assertEquals(v.otps.get(otp), key3.decryptOtp(session, aead3, otpBin));
                }
            }
        } finally {
            YHObject.delete(session, key1Id, Type.TYPE_OTP_AEAD_KEY);
            YHObject.delete(session, key2Id, Type.TYPE_OTP_AEAD_KEY);
            YHObject.delete(session, key3Id, Type.TYPE_OTP_AEAD_KEY);
        }
        log.info("TEST END: testKnownOtpTestVectors()");
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

        byte[] v1Key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
        byte[] v1PrivateId = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        Map<String, YubicoOtpData> otps = new HashMap<String, YubicoOtpData>();
        otps.put("dvgtiblfkbgturecfllberrvkinnctnn", new YubicoOtpData((short) 1, (byte) 1, (byte) 1, (short) 1));
        otps.put("rnibcnfhdninbrdebccrndfhjgnhftee", new YubicoOtpData((short) 1, (byte) 2, (byte) 1, (short) 1));
        otps.put("iikkijbdknrrdhfdrjltvgrbkkjblcbh", new YubicoOtpData((short) 0xfff, (byte) 1, (byte) 1, (short) 1));
        testVectors.add(new TestVector(v1Key, v1PrivateId, otps));

        byte[] v2Key = {(byte) 0x88, (byte) 0x88, (byte) 0x88, (byte) 0x88, (byte) 0x88, (byte) 0x88, (byte) 0x88, (byte) 0x88, (byte) 0x88,
                        (byte) 0x88, (byte) 0x88, (byte) 0x88, (byte) 0x88, (byte) 0x88, (byte) 0x88, (byte) 0x88};
        byte[] v2PrivateId = {(byte) 0x88, (byte) 0x88, (byte) 0x88, (byte) 0x88, (byte) 0x88, (byte) 0x88};
        otps = new HashMap<String, YubicoOtpData>();
        otps.put("dcihgvrhjeucvrinhdfddbjhfjftjdei", new YubicoOtpData((short) 0x8888, (byte) 0x88, (byte) 0x88, (short) 0x8888));
        testVectors.add(new TestVector(v2Key, v2PrivateId, otps));

        byte[] v3Key = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        byte[] v3PrivateId = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        otps = new HashMap<String, YubicoOtpData>();
        otps.put("kkkncjnvcnenkjvjgncjihljiibgbhbh", new YubicoOtpData((short) 0, (byte) 0, (byte) 0, (short) 0));
        testVectors.add(new TestVector(v3Key, v3PrivateId, otps));

        byte[] v4Key =
                {(byte) 0xc4, (byte) 0x42, (byte) 0x28, (byte) 0x90, (byte) 0x65, (byte) 0x30, (byte) 0x76, (byte) 0xcd, (byte) 0xe7, (byte) 0x3d,
                 (byte) 0x44, (byte) 0x9b, (byte) 0x19, (byte) 0x1b, (byte) 0x41, (byte) 0x6a};
        byte[] v4PrivateID = {(byte) 0x33, (byte) 0xc6, (byte) 0x9e, (byte) 0x7f, (byte) 0x24, (byte) 0x9e};
        otps = new HashMap<String, YubicoOtpData>();
        otps.put("iucvrkjiegbhidrcicvlgrcgkgurhjnj", new YubicoOtpData((short) 1, (byte) 0, (byte) 0x24, (short) 0x13a7));
        testVectors.add(new TestVector(v4Key, v4PrivateID, otps));

        return testVectors;
    }

    private class TestVector {
        private byte[] key;
        private byte[] privateId;
        Map<String, YubicoOtpData> otps;

        public TestVector(byte[] key, byte[] privateId, Map<String, YubicoOtpData> otps) {
            this.key = key;
            this.privateId = privateId;
            this.otps = otps;
        }
    }


}
