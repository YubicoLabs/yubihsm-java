import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.exceptions.YHDeviceException;
import com.yubico.hsm.yhconcepts.*;
import com.yubico.hsm.yhobjects.Opaque;
import com.yubico.hsm.yhobjects.YHObject;
import com.yubico.hsm.yhobjects.YHObjectInfo;
import org.bouncycastle.util.encoders.Base64;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.logging.Logger;

import static org.junit.Assert.*;

public class OpaqueTest {
    Logger log = Logger.getLogger(OpaqueTest.class.getName());

    private final String testCertificate = "-----BEGIN CERTIFICATE-----\n" +
                                           "MIIDMzCCAhugAwIBAgIIV9+4OgOubr4wDQYJKoZIhvcNAQELBQAwGzEZMBcGA1UE\n" +
                                           "AwwQTmV3TWFuYWdlbWVudEtleTAeFw0xODEyMTMwOTQ1MjVaFw0xODEyMjIxMDEw\n" +
                                           "MTlaMBcxFTATBgNVBAMMDHl1Ymljb19hZG1pbjCCASIwDQYJKoZIhvcNAQEBBQAD\n" +
                                           "ggEPADCCAQoCggEBAL2WcfkFWwrBO5ylKVdGMGmGBmiP6neQk8OHhZsTicxry6hw\n" +
                                           "GJoivGrI6KuBj919+MWcXbgs5lYW1gV+YduUOGPj0JoGMHsZWDzkRo1iF1I0B9Nf\n" +
                                           "tRhgkd0eSuhzoi1ainZ5MKvR0Tj5J6nnzs/Oy9W9EguUdNjh+LLGuvbJCuDhXYCU\n" +
                                           "bgGWhNg+bpKtn4bFpOJatJVseXXQdRdJtzdKSFou2xtQPSJqE1+WurxJ1/Qx0ZaA\n" +
                                           "wPywaAEkUbMRaPFsO2171ZflT01J+S4IO1BpHad6J47LAOWgKODcxdI231WymelB\n" +
                                           "Qp719v/Bbry5L4/KBj6SWKlKvt7SfOnfxkC4r1ECAwEAAaN/MH0wDAYDVR0TAQH/\n" +
                                           "BAIwADAfBgNVHSMEGDAWgBRn/G1+IF6vtGM40OvlGxTHnRCUWDAdBgNVHSUEFjAU\n" +
                                           "BggrBgEFBQcDAgYIKwYBBQUHAwQwHQYDVR0OBBYEFHrLsuB8yPWS4LeMQs0UjYCT\n" +
                                           "O1v+MA4GA1UdDwEB/wQEAwIF4DANBgkqhkiG9w0BAQsFAAOCAQEAs3c3gPCCC33E\n" +
                                           "I7lQEp/hrA0bu9K6VCa9NrzSXP8DFXn4hgM487678yhh7PlQ9T60VVnxVpuJgs8M\n" +
                                           "3PRiVvzY11ABjdnjjDMss5jNC3dOi7MLIT6xxDh5U/1XulEmUoqP7RkXCcmDKg+8\n" +
                                           "Vd7TnsmlutTmwKRiLOa8zl/o3aJoeCqg+FdNC3hRZuR3w5mG5IlaZ+VLwY7tjdov\n" +
                                           "12mcMSxsC1JG0aUXv+RdBUtNG1JXFBYA43FBwMNjZPsiYXYgN0T24zGW6OQnTbB3\n" +
                                           "kw4LNCS2l7cuEDiHwFmxVyCSInUSzcbfryltKCzzqWOCSPuKxwZzhHuRQ1tyy+MB\n" +
                                           "SKlmUkdizg==\n" +
                                           "-----END CERTIFICATE-----";

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
    public void testImportOpaque() throws Exception {
        log.info("TEST START: testImportOpaque()");

        final List domains = Arrays.asList(2, 5, 8);
        final List capabilities = Arrays.asList(Capability.GENERATE_HMAC_KEY, Capability.SIGN_PKCS);
        final String label = "imported_opaque";

        byte[] opaqueData = new byte[1024];
        new Random().nextBytes(opaqueData);
        final short id = Opaque.importOpaque(session, (short) 0, label, domains, capabilities, Algorithm.OPAQUE_DATA, opaqueData);

        try {
            // Verify object properties
            final YHObjectInfo opaqueObj = YHObject.getObjectInfo(session, id, Type.TYPE_OPAQUE);
            assertNotEquals(0, opaqueObj.getId());
            assertEquals(id, opaqueObj.getId());
            assertEquals(Type.TYPE_OPAQUE, opaqueObj.getType());
            assertEquals(domains, opaqueObj.getDomains());
            assertEquals(Algorithm.OPAQUE_DATA, opaqueObj.getAlgorithm());
            assertEquals(Origin.YH_ORIGIN_IMPORTED, opaqueObj.getOrigin());
            assertEquals(label, opaqueObj.getLabel());
            assertEquals(capabilities.size(), opaqueObj.getCapabilities().size());
            assertTrue(opaqueObj.getCapabilities().containsAll(capabilities));
            assertEquals(0, opaqueObj.getDelegatedCapabilities().size());

            Opaque opaque = new Opaque(id, Algorithm.OPAQUE_DATA);
            byte[] returnedOpaqueData = opaque.getOpaque(session);
            assertArrayEquals(opaqueData, returnedOpaqueData);
        } finally {
            // Delete opaque object
            YHObject.delete(session, id, Type.TYPE_OPAQUE);
            try {
                YHObject.getObjectInfo(session, id, Type.TYPE_OPAQUE);
            } catch (YHDeviceException e1) {
                assertEquals(YHError.OBJECT_NOT_FOUND, e1.getYhError());
            }
        }

        log.info("TEST END: testImportOpaque()");
    }

    @Test
    public void testImportCertificate() throws Exception {
        log.info("TEST START: testImportCertificate()");

        final List domains = Arrays.asList(2, 5, 8);
        final String label = "imported_cert";
        X509Certificate cert = getTestCertificate();

        final short id = Opaque.importCertificate(session, (short) 0, label, domains, cert);

        try {
            // Verify object properties
            final YHObjectInfo opaqueObj = YHObject.getObjectInfo(session, id, Type.TYPE_OPAQUE);
            assertNotEquals(0, opaqueObj.getId());
            assertEquals(id, opaqueObj.getId());
            assertEquals(Type.TYPE_OPAQUE, opaqueObj.getType());
            assertEquals(domains, opaqueObj.getDomains());
            assertEquals(Algorithm.OPAQUE_X509_CERTIFICATE, opaqueObj.getAlgorithm());
            assertEquals(Origin.YH_ORIGIN_IMPORTED, opaqueObj.getOrigin());
            assertEquals(label, opaqueObj.getLabel());
            assertEquals(0, opaqueObj.getCapabilities().size());
            assertEquals(0, opaqueObj.getDelegatedCapabilities().size());

            Opaque opaque = new Opaque(id, Algorithm.OPAQUE_X509_CERTIFICATE);
            X509Certificate returnedCert = opaque.getCertificate(session);
            assertEquals(cert, returnedCert);
        } finally {
            // Delete opaque object
            YHObject.delete(session, id, Type.TYPE_OPAQUE);
            try {
                YHObject.getObjectInfo(session, id, Type.TYPE_OPAQUE);
            } catch (YHDeviceException e1) {
                assertEquals(YHError.OBJECT_NOT_FOUND, e1.getYhError());
            }
        }

        log.info("TEST END: testImportCertificate()");
    }

    @Test
    public void testImportOpaqueCertificate() throws Exception {
        log.info("TEST START: testImportOpaqueCertificate()");

        X509Certificate testCert = getTestCertificate();
        short id =
                Opaque.importOpaque(session, (short) 0, "", Arrays.asList(2, 5, 8), null, Algorithm.OPAQUE_X509_CERTIFICATE, testCert.getEncoded());
        try {
            Opaque opaque = new Opaque(id, Algorithm.OPAQUE_X509_CERTIFICATE);
            X509Certificate returnedCert = opaque.getCertificate(session);
            assertEquals(testCert, returnedCert);
        } finally {
            // Delete opaque object
            YHObject.delete(session, id, Type.TYPE_OPAQUE);
        }

        log.info("TEST END: testImportOpaqueCertificate()");
    }

    @Test
    public void testImportOpaqueCertificateWithWrongAlgorithm() throws Exception {
        log.info("TEST START: testImportOpaqueCertificate()");

        X509Certificate testCert = getTestCertificate();
        short id = Opaque.importOpaque(session, (short) 0, "", Arrays.asList(2, 5, 8), null, Algorithm.OPAQUE_DATA, testCert.getEncoded());
        try {
            Opaque opaque = new Opaque(id, Algorithm.OPAQUE_DATA);
            boolean exceptionThrown = false;
            try {
                opaque.getCertificate(session);
            } catch (UnsupportedOperationException e) {
                exceptionThrown = true;
            }
            assertTrue("Succeeded in returning the opaque ", exceptionThrown);
        } finally {
            // Delete opaque object
            YHObject.delete(session, id, Type.TYPE_OPAQUE);
        }

        log.info("TEST END: testImportOpaqueCertificate()");
    }

    @Test
    public void testImportInvalidOpaque() throws Exception {
        log.info("TEST START: testImportInvalidOpaque()");

        boolean exceptionThrown = false;
        try {
            Opaque.importOpaque(session, (short) 0, "", Arrays.asList(2, 5, 8), null, Algorithm.OPAQUE_DATA, new byte[0]);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue("Succeeded in importing an empty byte array as an opaque object", exceptionThrown);

        byte[] opaqueData = new byte[1970];
        new Random().nextBytes(opaqueData);
        exceptionThrown = false;
        try {
            Opaque.importOpaque(session, (short) 0, "", Arrays.asList(2, 5, 8), null, Algorithm.OPAQUE_DATA, opaqueData);
        } catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue("Succeeded in importing an opaque object that is too large", exceptionThrown);

        log.info("TEST START: testImportInvalidOpaque()");
    }

    private X509Certificate getTestCertificate() throws CertificateException {
        String certStr = testCertificate.replace("-----BEGIN CERTIFICATE-----\n", "");
        certStr = certStr.replace("-----END CERTIFICATE-----", "");
        byte[] encoded = Base64.decode(certStr);
        ByteArrayInputStream in = new ByteArrayInputStream(encoded);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(in);
    }
}
