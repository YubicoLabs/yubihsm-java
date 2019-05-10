import AsymmetricKeyTest.AsymmetricKeyTestHelper;
import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.exceptions.UnsupportedAlgorithmException;
import com.yubico.hsm.exceptions.YHDeviceException;
import com.yubico.hsm.yhconcepts.*;
import com.yubico.hsm.yhdata.WrapData;
import com.yubico.hsm.yhobjects.Opaque;
import com.yubico.hsm.yhobjects.WrapKey;
import com.yubico.hsm.yhobjects.YHObject;
import com.yubico.hsm.yhobjects.YHObjectInfo;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Random;
import java.util.logging.Logger;

import static org.junit.Assert.*;

public class WrapKeyTest {
    Logger log = Logger.getLogger(WrapKeyTest.class.getName());

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
    public void testGenerateWrapKey() throws Exception {
        log.info("TEST START: testGenerateWrapKey()");
        generateWrapKey(Algorithm.AES128_CCM_WRAP, 16);
        generateWrapKey(Algorithm.AES192_CCM_WRAP, 24);
        generateWrapKey(Algorithm.AES256_CCM_WRAP, 32);
        log.info("TEST END: testGenerateWrapKey()");
    }

    private void generateWrapKey(Algorithm keyAlgorithm, int keyLength) throws Exception {
        log.info("Test generating wrap key with algorithm " + keyAlgorithm.getName());
        List domains = Arrays.asList(2, 5, 8);
        List capabilities = Arrays.asList(Capability.EXPORT_WRAPPED, Capability.IMPORT_WRAPPED);
        String label = "test_wrap_key";

        short id = WrapKey.generateWrapKey(session, (short) 0, label, domains, keyAlgorithm, capabilities, capabilities);

        try {
            final YHObjectInfo wrapkey = YHObject.getObjectInfo(session, id, Type.TYPE_WRAP_KEY);
            assertEquals(id, wrapkey.getId());
            assertEquals(Type.TYPE_WRAP_KEY, wrapkey.getType());
            assertEquals(keyLength + 8, wrapkey.getObjectSize());
            assertEquals(domains, wrapkey.getDomains());
            assertEquals(keyAlgorithm, wrapkey.getAlgorithm());
            assertEquals(Origin.YH_ORIGIN_GENERATED, wrapkey.getOrigin());
            assertEquals(label, wrapkey.getLabel());
            assertEquals(capabilities.size(), wrapkey.getCapabilities().size());
            assertTrue(wrapkey.getCapabilities().containsAll(capabilities));
            assertEquals(capabilities.size(), wrapkey.getDelegatedCapabilities().size());
            assertTrue(wrapkey.getDelegatedCapabilities().containsAll(capabilities));
        } finally {
            YHObject.delete(session, id, Type.TYPE_WRAP_KEY);
        }
    }

    @Test
    public void testImportWrapKey() throws Exception {
        log.info("TEST START: testImportWrapKey()");
        importWrapKey(Algorithm.AES128_CCM_WRAP, 16);
        importWrapKey(Algorithm.AES192_CCM_WRAP, 24);
        importWrapKey(Algorithm.AES256_CCM_WRAP, 32);
        log.info("TEST END: testImportWrapKey()");
    }

    private void importWrapKey(Algorithm keyAlgorithm, int keyLength) throws Exception {
        log.info("Test importing " + keyLength + " bytes long wrap key with algorithm " + keyAlgorithm.getName());
        byte[] data = new byte[keyLength];
        new SecureRandom().nextBytes(data);

        List domains = Arrays.asList(2, 5, 8);
        List capabilities = Arrays.asList(Capability.EXPORT_WRAPPED, Capability.IMPORT_WRAPPED);
        String label = "test_wrap_key";
        short id = (short) 0x1234;

        WrapKey.importWrapKey(session, id, label, domains, keyAlgorithm, capabilities, capabilities, data);

        try {
            final YHObjectInfo wrapkey = YHObject.getObjectInfo(session, id, Type.TYPE_WRAP_KEY);
            assertEquals(id, wrapkey.getId());
            assertEquals(Type.TYPE_WRAP_KEY, wrapkey.getType());
            assertEquals(keyLength + 8, wrapkey.getObjectSize());
            assertEquals(domains, wrapkey.getDomains());
            assertEquals(keyAlgorithm, wrapkey.getAlgorithm());
            assertEquals(Origin.YH_ORIGIN_IMPORTED, wrapkey.getOrigin());
            assertEquals(label, wrapkey.getLabel());
            assertEquals(capabilities.size(), wrapkey.getCapabilities().size());
            assertTrue(wrapkey.getCapabilities().containsAll(capabilities));
            assertEquals(capabilities.size(), wrapkey.getDelegatedCapabilities().size());
            assertTrue(wrapkey.getDelegatedCapabilities().containsAll(capabilities));
        } finally {
            YHObject.delete(session, id, Type.TYPE_WRAP_KEY);
        }
    }

    @Test
    public void testInvalidWrapKey() throws Exception {
        log.info("TEST START: testInvalidWrapKey()");
        byte[] data = new byte[32];
        new SecureRandom().nextBytes(data);

        log.info("Test importing wrap key with wrong key length");
        boolean exceptionThrown = false;
        try {
            WrapKey.importWrapKey(session, (short) 0, "", Arrays.asList(2, 5, 8), Algorithm.AES192_CCM_WRAP, null, null, data);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue(exceptionThrown);

        log.info("Test importing wrap key with non-wrap key algorithm");
        exceptionThrown = false;
        try {
            WrapKey.importWrapKey(session, (short) 0, "", Arrays.asList(2, 5, 8), Algorithm.RSA_2048, null, null, data);
        } catch (UnsupportedAlgorithmException e) {
            exceptionThrown = true;
        }
        assertTrue(exceptionThrown);

        log.info("Test importing null wrap key");
        exceptionThrown = false;
        try {
            WrapKey.importWrapKey(session, (short) 0, "", Arrays.asList(2, 5, 8), Algorithm.AES192_CCM_WRAP, null, null, null);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue(exceptionThrown);

        log.info("TEST START: testInvalidWrapKey()");
    }

    @Test
    public void testDataWrap() throws Exception {
        log.info("TEST START: testDataWrap()");
        dataWrapDifferentLengths(Algorithm.AES128_CCM_WRAP);
        dataWrapDifferentLengths(Algorithm.AES192_CCM_WRAP);
        dataWrapDifferentLengths(Algorithm.AES256_CCM_WRAP);
        log.info("TEST END: testDataWrap()");
    }

    private void dataWrapDifferentLengths(Algorithm algorithm) throws Exception {
        short id = WrapKey.generateWrapKey(session, (short) 0, "test_wrap_key", Arrays.asList(2, 5, 8), algorithm,
                                           Arrays.asList(Capability.WRAP_DATA, Capability.UNWRAP_DATA), null);
        try {
            WrapKey wrapKey = new WrapKey(id);

            log.info("Test wrapping normal length data with wrap key of algorithm " + algorithm.getName());
            dataWrap(wrapKey, "Hello world!".getBytes(), true);

            log.info("Test wrapping null data with wrap key of algorithm " + algorithm.getName());
            dataWrap(wrapKey, null, false);

            log.info("Test wrapping empty data with wrap key of algorithm " + algorithm.getName());
            dataWrap(wrapKey, new byte[0], false);

            log.info("Test wrapping 1 byte long data with wrap key of algorithm " + algorithm.getName());
            byte[] data = new byte[1];
            new Random().nextBytes(data);
            dataWrap(wrapKey, data, true);

            log.info("Test wrapping too long data with wrap key of algorithm " + algorithm.getName());
            data = new byte[2048];
            new Random().nextBytes(data);
            dataWrap(wrapKey, data, false);

            unwrapInvalidData(wrapKey, algorithm.getName());
        } finally {
            YHObject.delete(session, id, Type.TYPE_WRAP_KEY);
        }
    }

    private void dataWrap(WrapKey key, byte[] data, boolean success) throws Exception {

        if (success) {
            WrapData wd = key.wrapData(session, data);
            assertNotNull(wd);
            assertNotNull(wd.getNonce());
            assertEquals(WrapData.NONCE_LENGTH, wd.getNonce().length);
            assertNotNull(wd.getWrappedData());
            assertTrue(wd.getWrappedData().length > 0);
            assertNotEquals(data, wd.getWrappedData());
            assertNotNull(wd.getMac());
            assertEquals(WrapData.MAC_LENGTH, wd.getMac().length);

            byte[] unwrapped = key.unwrapData(session, wd);
            assertArrayEquals(data, unwrapped);
        } else {
            boolean exceptionThrown = false;
            try {
                key.wrapData(session, data);
            } catch (IllegalArgumentException | IndexOutOfBoundsException e) {
                exceptionThrown = true;
            }
            assertTrue(exceptionThrown);
        }
    }

    private void unwrapInvalidData(WrapKey wrapKey, String keyAlgorithm) throws Exception {
        byte[] nonce = new byte[13];
        new Random().nextBytes(nonce);
        byte[] mac = new byte[16];
        new Random().nextBytes(mac);

        log.info("Test unwrapping null data using wrap key of algorithm " + keyAlgorithm);
        boolean exceptionThrown = false;
        try {
            wrapKey.unwrapData(session, null);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue(exceptionThrown);

        log.info("Test unwrapping data with null nonce using wrap key of algorithm " + keyAlgorithm);
        unwrapInvalidData(wrapKey, null, "wrapped data".getBytes(), mac);

        log.info("Test unwrapping data with empty nonce using wrap key of algorithm " + keyAlgorithm);
        unwrapInvalidData(wrapKey, new byte[0], "wrapped data".getBytes(), mac);

        log.info("Test unwrapping data with a too long nonce using wrap key of algorithm " + keyAlgorithm);
        unwrapInvalidData(wrapKey, "Nonce that is longer than 13 bytes".getBytes(), "wrapped data".getBytes(), mac);

        log.info("Test unwrapping data with a too short nonce using wrap key of algorithm " + keyAlgorithm);
        unwrapInvalidData(wrapKey, "nonce".getBytes(), "wrapped data".getBytes(), mac);

        log.info("Test unwrapping data with null MAC using wrap key of algorithm " + keyAlgorithm);
        unwrapInvalidData(wrapKey, nonce, "wrapped data".getBytes(), null);

        log.info("Test unwrapping data with empty MAC using wrap key of algorithm " + keyAlgorithm);
        unwrapInvalidData(wrapKey, nonce, "wrapped data".getBytes(), new byte[0]);

        log.info("Test unwrapping data with too long MAC using wrap key of algorithm " + keyAlgorithm);
        unwrapInvalidData(wrapKey, nonce, "wrapped data".getBytes(), "Mac that is longer than 16 bytes".getBytes());

        log.info("Test unwrapping data with too short MAC using wrap key of algorithm " + keyAlgorithm);
        unwrapInvalidData(wrapKey, nonce, "wrapped data".getBytes(), "mac".getBytes());

        log.info("Test unwrapping data with null wrappedData using wrap key of algorithm " + keyAlgorithm);
        unwrapInvalidData(wrapKey, nonce, null, mac);

        log.info("Test unwrapping data with empty wrappedData using wrap key of algorithm " + keyAlgorithm);
        unwrapInvalidData(wrapKey, nonce, new byte[0], mac);
    }

    private void unwrapInvalidData(WrapKey wrapKey, byte[] nonce, byte[] wrappedData, byte[] mac) throws Exception {
        boolean exceptionThrown = false;
        try {
            wrapKey.unwrapData(session, new WrapData(nonce, wrappedData, mac));
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue(exceptionThrown);
    }

    @Test
    public void testObjectWrap() throws Exception {
        log.info("TEST START: testObjectWrap()");
        X509Certificate testCert = AsymmetricKeyTestHelper.getTestCertificate();
        short id = Opaque.importOpaque(session, (short) 0, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.EXPORTABLE_UNDER_WRAP),
                                       Algorithm.OPAQUE_DATA, testCert.getEncoded());
        try {
            objectWrap(Algorithm.AES128_CCM_WRAP, id, testCert);
            objectWrap(Algorithm.AES192_CCM_WRAP, id, testCert);
            objectWrap(Algorithm.AES256_CCM_WRAP, id, testCert);
        } finally {
            try {
                YHObject.delete(session, id, Type.TYPE_OPAQUE);
            } catch (YHDeviceException e) {
            }
        }

        log.info("TEST END: testObjectWrap()");
    }

    private void objectWrap(Algorithm algorithm, short certId, X509Certificate cert) throws Exception {
        log.info("Test wrapping certificate with ID 0x" + Integer.toHexString(certId) + " using wrap key of algorithm " + algorithm.getName());
        short id = WrapKey.generateWrapKey(session, (short) 0, "", Arrays.asList(2, 5, 8), algorithm,
                                           Arrays.asList(Capability.IMPORT_WRAPPED, Capability.EXPORT_WRAPPED),
                                           Arrays.asList(Capability.EXPORTABLE_UNDER_WRAP));
        try {
            WrapKey wrapKey = new WrapKey(id);
            certWrap(wrapKey, certId, cert);
            nonExistingObjectWrap(wrapKey, certId, algorithm.getName());
        } finally {
            YHObject.delete(session, id, Type.TYPE_WRAP_KEY);
        }
    }

    private void certWrap(WrapKey wrapKey, short certId, X509Certificate cert) throws Exception {
        // Export certificate under wrap
        WrapData exportedCert = wrapKey.exportWrapped(session, certId, Type.TYPE_OPAQUE);

        // Delete it from the HSM and make sure that it is no longer there
        YHObject.delete(session, certId, Type.TYPE_OPAQUE);
        HashMap filters = new HashMap();
        filters.put(ListObjectsFilter.ID, certId);
        filters.put(ListObjectsFilter.TYPE, Type.TYPE_OPAQUE);
        List<YHObjectInfo> objects = YHObject.getObjectList(session, filters);
        assertEquals(0, objects.size());

        // Import the certificate under wrap
        YHObject importedCert = wrapKey.importWrapped(session, exportedCert.getNonce(), exportedCert.getWrappedData());

        // Verify that the certificate exists
        objects = YHObject.getObjectList(session, filters);
        assertEquals(1, objects.size());

        // Verify that it is the same certificate as the test certificate
        Opaque opaque = new Opaque(certId, Algorithm.OPAQUE_DATA);
        byte[] certBytes = opaque.getOpaque(session);
        ByteArrayInputStream in = new ByteArrayInputStream(certBytes);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate certInHsm = (X509Certificate) cf.generateCertificate(in);
        assertEquals(cert, certInHsm);
    }

    private void nonExistingObjectWrap(WrapKey wrapKey, short certId, String wrapKeyAlgorithm) throws Exception {
        log.info("Test wrapping a non existing object using wrap key of algorithm " + wrapKeyAlgorithm);
        HashMap filters = new HashMap();
        filters.put(ListObjectsFilter.ID, certId);
        filters.put(ListObjectsFilter.TYPE, Type.TYPE_ASYMMETRIC_KEY);
        List<YHObjectInfo> objects = YHObject.getObjectList(session, filters);
        assertEquals(0, objects.size());

        boolean exceptionThrown = false;
        try {
            wrapKey.exportWrapped(session, certId, Type.TYPE_ASYMMETRIC_KEY);
        } catch (YHDeviceException e) {
            exceptionThrown = true;
            assertEquals(YHError.OBJECT_NOT_FOUND, e.getYhError());
        }
        assertTrue(exceptionThrown);
    }
}
