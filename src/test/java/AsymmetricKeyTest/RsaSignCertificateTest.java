package AsymmetricKeyTest;

import com.yubico.YHSession;
import com.yubico.YubiHsm;
import com.yubico.backend.Backend;
import com.yubico.backend.HttpBackend;
import com.yubico.exceptions.*;
import com.yubico.objects.yhconcepts.Algorithm;
import com.yubico.objects.yhconcepts.Capability;
import com.yubico.objects.yhconcepts.ObjectType;
import com.yubico.objects.yhobjects.*;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.net.MalformedURLException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.logging.Logger;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class RsaSignCertificateTest {
    Logger logger = Logger.getLogger(RsaSignCertificateTest.class.getName());

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
    public void testSigningAttestationCertificate()
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, UnsupportedAlgorithmException, CertificateException, InvalidKeySpecException {
        short attestingKeyid = 0x5678;
        short attestedKeyid = 0x0123;
        try {

            PublicKey pubKey = AsymmetricKeyTestHelper.importRsaKey(session, attestingKeyid, "", Arrays.asList(2, 5, 8),
                                                                    Arrays.asList(Capability.SIGN_ATTESTATION_CERTIFICATE),
                                                                    Algorithm.RSA_2048, 2048, 128);
            AsymmetricKey attestingKey = new AsymmetricKey(attestingKeyid, Algorithm.RSA_2048);


            YHObjectInfo genKeyInfo = AsymmetricKeyRsa.getObjectInfoForNewKey(attestedKeyid, "", Arrays.asList(2, 5, 8), Algorithm.RSA_2048,
                                                                              Arrays.asList(Capability.SIGN_PKCS));
            AsymmetricKey.generateAsymmetricKey(session, genKeyInfo);


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
                attestationCert.verify(pubKey);
            } catch (Exception e) {
                fail("Attestation certificate was not valid");
            }

        } finally {
            try {
                YHObject.deleteObject(session, attestingKeyid, ObjectType.TYPE_ASYMMETRIC_KEY);
            } catch (YHDeviceException e) {
                if (!e.getErrorCode().equals(YHError.OBJECT_NOT_FOUND)) {
                    throw e;
                }
            }

            try {
                YHObject.deleteObject(session, attestedKeyid, ObjectType.TYPE_ASYMMETRIC_KEY);
            } catch (YHDeviceException e) {
                if (!e.getErrorCode().equals(YHError.OBJECT_NOT_FOUND)) {
                    throw e;
                }
            }

            try {
                YHObject.deleteObject(session, attestingKeyid, ObjectType.TYPE_OPAQUE);
            } catch (YHDeviceException e) {
                if (!e.getErrorCode().equals(YHError.OBJECT_NOT_FOUND)) {
                    throw e;
                }
            }
        }
    }
}
