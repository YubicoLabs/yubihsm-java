import AsymmetricKeyTest.AsymmetricKeyTestHelper;
import com.yubico.YHSession;
import com.yubico.YubiHsm;
import com.yubico.backend.Backend;
import com.yubico.backend.HttpBackend;
import com.yubico.exceptions.*;
import com.yubico.objects.WrapData;
import com.yubico.objects.yhconcepts.Algorithm;
import com.yubico.objects.yhconcepts.Capability;
import com.yubico.objects.yhconcepts.ObjectOrigin;
import com.yubico.objects.yhconcepts.ObjectType;
import com.yubico.objects.yhobjects.Opaque;
import com.yubico.objects.yhobjects.WrapKey;
import com.yubico.objects.yhobjects.YHObject;
import com.yubico.objects.yhobjects.YHObjectInfo;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.net.MalformedURLException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.logging.Logger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class WrapKeyTest {
    Logger log = Logger.getLogger(WrapKeyTest.class.getName());

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
    public void testGenerateWrapKey() throws Exception {
        log.info("TEST START: testGenerateWrapKey()");
        generateWrapKey(Algorithm.AES128_CCM_WRAP, 16);
        generateWrapKey(Algorithm.AES192_CCM_WRAP, 24);
        generateWrapKey(Algorithm.AES256_CCM_WRAP, 32);
        log.info("TEST END: testGenerateWrapKey()");
    }

    private void generateWrapKey(Algorithm keyAlgorithm, int keyLength) throws Exception {
        List domains = Arrays.asList(2, 5, 8);
        List capabilities = Arrays.asList(Capability.EXPORT_WRAPPED, Capability.IMPORT_WRAPPED);
        String label = "test_wrap_key";

        short id = WrapKey.generateWrapKey(session, (short) 0, label, domains, keyAlgorithm, capabilities, capabilities);

        try {
            final YHObjectInfo wrapkey = YHObject.getObjectInfo(session, id, ObjectType.TYPE_WRAP_KEY);
            assertEquals(id, wrapkey.getId());
            assertEquals(ObjectType.TYPE_WRAP_KEY, wrapkey.getType());
            assertEquals(keyLength + 8, wrapkey.getObjectSize());
            assertEquals(domains, wrapkey.getDomains());
            assertEquals(keyAlgorithm, wrapkey.getAlgorithm());
            assertEquals(ObjectOrigin.YH_ORIGIN_GENERATED, wrapkey.getOrigin());
            assertEquals(label, wrapkey.getLabel());
            assertEquals(capabilities.size(), wrapkey.getCapabilities().size());
            assertTrue(wrapkey.getCapabilities().containsAll(capabilities));
            assertEquals(capabilities.size(), wrapkey.getDelegatedCapabilities().size());
            assertTrue(wrapkey.getDelegatedCapabilities().containsAll(capabilities));
        } finally {
            YHObject.deleteObject(session, id, ObjectType.TYPE_WRAP_KEY);
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
        byte[] data = new byte[keyLength];
        new SecureRandom().nextBytes(data);

        List domains = Arrays.asList(2, 5, 8);
        List capabilities = Arrays.asList(Capability.EXPORT_WRAPPED, Capability.IMPORT_WRAPPED);
        String label = "test_wrap_key";
        short id = (short) 0x1234;

        WrapKey.importWrapKey(session, id, label, domains, keyAlgorithm, capabilities, capabilities, data);

        try {
            final YHObjectInfo wrapkey = YHObject.getObjectInfo(session, id, ObjectType.TYPE_WRAP_KEY);
            assertEquals(id, wrapkey.getId());
            assertEquals(ObjectType.TYPE_WRAP_KEY, wrapkey.getType());
            assertEquals(keyLength + 8, wrapkey.getObjectSize());
            assertEquals(domains, wrapkey.getDomains());
            assertEquals(keyAlgorithm, wrapkey.getAlgorithm());
            assertEquals(ObjectOrigin.YH_ORIGIN_IMPORTED, wrapkey.getOrigin());
            assertEquals(label, wrapkey.getLabel());
            assertEquals(capabilities.size(), wrapkey.getCapabilities().size());
            assertTrue(wrapkey.getCapabilities().containsAll(capabilities));
            assertEquals(capabilities.size(), wrapkey.getDelegatedCapabilities().size());
            assertTrue(wrapkey.getDelegatedCapabilities().containsAll(capabilities));
        } finally {
            YHObject.deleteObject(session, id, ObjectType.TYPE_WRAP_KEY);
        }
    }

    @Test
    public void testInvalidWrapKey() throws Exception {
        log.info("TEST START: testInvalidWrapKey()");
        byte[] data = new byte[32];
        new SecureRandom().nextBytes(data);

        boolean exceptionThrown = false;
        try {
            WrapKey.importWrapKey(session, (short) 0, "", Arrays.asList(2, 5, 8), Algorithm.AES192_CCM_WRAP, null, null, data);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue(exceptionThrown);

        exceptionThrown = false;
        try {
            WrapKey.importWrapKey(session, (short) 0, "", Arrays.asList(2, 5, 8), Algorithm.RSA_2048, null, null, data);
        } catch (UnsupportedAlgorithmException e) {
            exceptionThrown = true;
        }
        assertTrue(exceptionThrown);
        log.info("TEST START: testInvalidWrapKey()");
    }

    @Test
    public void testDataWrap() throws Exception {
        log.info("TEST START: testDataWrap()");
        dataWrap(Algorithm.AES128_CCM_WRAP);
        dataWrap(Algorithm.AES192_CCM_WRAP);
        dataWrap(Algorithm.AES256_CCM_WRAP);
        log.info("TEST END: testDataWrap()");
    }

    private void dataWrap(Algorithm algorithm) throws Exception {
        String data = "Hello world!";

        short id = WrapKey.generateWrapKey(session, (short) 0, "test_wrap_key", Arrays.asList(2, 5, 8), algorithm,
                                           Arrays.asList(Capability.WRAP_DATA, Capability.UNWRAP_DATA), null);

        try {
            WrapKey key = new WrapKey(id);
            WrapData wd = key.wrapData(session, data.getBytes());

            byte[] unwrapped = key.unwrapData(session, wd);
            assertEquals(data, new String(unwrapped));

        } finally {
            YHObject.deleteObject(session, id, ObjectType.TYPE_WRAP_KEY);
        }
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
                YHObject.deleteObject(session, id, ObjectType.TYPE_OPAQUE);
            } catch (YHDeviceException e) {
            }
        }

        log.info("TEST END: testObjectWrap()");
    }

    private void objectWrap(Algorithm algorithm, short certId, X509Certificate cert) throws Exception {
        short id = WrapKey.generateWrapKey(session, (short) 0, "", Arrays.asList(2, 5, 8), algorithm,
                                           Arrays.asList(Capability.IMPORT_WRAPPED, Capability.EXPORT_WRAPPED),
                                           Arrays.asList(Capability.EXPORTABLE_UNDER_WRAP));
        try {
            // Export certificate under wrap
            WrapKey key = new WrapKey(id);
            WrapData exportedCert = key.exportWrapped(session, certId, ObjectType.TYPE_OPAQUE);

            // Delete it from the HSM and make sure that it is no longer there
            YHObject.deleteObject(session, certId, ObjectType.TYPE_OPAQUE);
            HashMap filters = new HashMap();
            filters.put(YHObject.ListFilter.ID, certId);
            filters.put(YHObject.ListFilter.TYPE, ObjectType.TYPE_OPAQUE);
            List<YHObjectInfo> objects = YHObject.getObjectList(session, filters);
            assertEquals(0, objects.size());

            // Import the certificate under wrap
            YHObject importedCert = key.importWrapped(session, exportedCert.getNonce(), exportedCert.getWrappedData());

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

        } finally {
            YHObject.deleteObject(session, id, ObjectType.TYPE_WRAP_KEY);
        }
    }
}
