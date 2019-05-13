package yhobjectstest.asymmetrickeystest;

import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.yhconcepts.Algorithm;
import com.yubico.hsm.yhconcepts.Capability;
import com.yubico.hsm.yhobjects.AsymmetricKey;
import com.yubico.hsm.yhobjects.Opaque;
import com.yubico.hsm.yhobjects.YHObject;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.logging.Logger;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class EcSignCertificateTest {
    Logger log = Logger.getLogger(EcSignCertificateTest.class.getName());

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
    public void testSigningAttestationCertificate() throws Exception {
        log.info("TEST START: testSigningAttestationCertificate()");
        short attestingKeyid = 0x5678;
        short attestedKeyid = 0x0123;
        try {
            KeyPair attestingKeypair = AsymmetricKeyTestHelper.importEcKey(session, attestingKeyid, "", Arrays.asList(2, 5, 8),
                                                                           Arrays.asList(Capability.SIGN_ATTESTATION_CERTIFICATE), Algorithm.EC_P224,
                                                                           "secp224r1", 28);
            AsymmetricKey attestingKey = new AsymmetricKey(attestingKeyid, Algorithm.EC_P224);

            AsymmetricKey.generateAsymmetricKey(session, attestedKeyid, "", Arrays.asList(2, 5, 8), Algorithm.EC_P224,
                                                Arrays.asList(Capability.SIGN_ECDSA));

            boolean exceptionThrown = false;
            try {
                attestingKey.signAttestationCertificate(session, attestedKeyid);
            } catch (UnsupportedOperationException e) {
                exceptionThrown = true;
            }
            assertTrue(exceptionThrown);

            Opaque.importCertificate(session, attestingKeyid, "", Arrays.asList(2, 5, 8), AsymmetricKeyTestHelper.getTestCertificate());
            X509Certificate attestationCert = attestingKey.signAttestationCertificate(session, attestedKeyid);

            try {
                attestationCert.verify(attestingKeypair.getPublic());
            } catch (Exception e) {
                fail("Attestation certificate was not valid");
            }

        } finally {
            YHObject.delete(session, attestedKeyid, AsymmetricKey.TYPE);
            YHObject.delete(session, attestingKeyid, AsymmetricKey.TYPE);
            YHObject.delete(session, attestingKeyid, Opaque.TYPE);
        }
        log.info("TEST END: testSigningAttestationCertificate()");
    }
}
