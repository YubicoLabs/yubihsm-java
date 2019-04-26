package AsymmetricKeyTest;

import com.yubico.YHSession;
import com.yubico.YubiHsm;
import com.yubico.backend.Backend;
import com.yubico.backend.HttpBackend;
import com.yubico.exceptions.YHDeviceException;
import com.yubico.exceptions.YHError;
import com.yubico.objects.yhconcepts.Algorithm;
import com.yubico.objects.yhconcepts.Capability;
import com.yubico.objects.yhconcepts.ObjectType;
import com.yubico.objects.yhobjects.AsymmetricKeyRsa;
import com.yubico.objects.yhobjects.YHObject;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.Random;
import java.util.logging.Logger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class RsaSignTest {
    Logger log = Logger.getLogger(RsaSignTest.class.getName());

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
    public void testSignDataWithInsufficientPermissions() throws Exception {
        log.info("TEST START: testSignDataWithInsufficientPermissions()");

        short id = 0x1234;
        PublicKey pubKey = AsymmetricKeyTestHelper.importRsaKey(session, id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.SIGN_PKCS),
                                                                Algorithm.RSA_2048, 2048, 128);
        try {
            final AsymmetricKeyRsa key = new AsymmetricKeyRsa(id, Algorithm.RSA_2048);

            boolean exceptionThrown = false;
            try {
                signPss(pubKey, key, Algorithm.RSA_MGF1_SHA256, "SHA256withRSA/PSS", "SHA-256", (short) 32, new byte[0]);
            } catch (YHDeviceException e) {
                exceptionThrown = true;
                assertEquals("Device returned incorrect error", YHError.INSUFFICIENT_PERMISSIONS, e.getYhError());
            }
            assertTrue("Succeeded to sign in spite of insufficient permissions", exceptionThrown);

        } finally {
            YHObject.deleteObject(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
        }

        log.info("TEST END: testSignDataWithInsufficientPermissions()");
    }

    @Test
    public void testSignData() throws Exception {
        log.info("TEST START: testSignData()");

        signPkcs1Test(Algorithm.RSA_2048, 2048, 128);
        signPkcs1Test(Algorithm.RSA_3072, 3072, 192);
        signPkcs1Test(Algorithm.RSA_4096, 4096, 256);

        signPssTest(Algorithm.RSA_2048, 2048, 128);
        signPssTest(Algorithm.RSA_3072, 3072, 192);
        signPssTest(Algorithm.RSA_4096, 4096, 256);

        log.info("TEST END: testSignData()");
    }

    // ---------------------------------------------------------------------------------

    private void signPkcs1Test(Algorithm keyAlgorithm, int keysize, int componentLength) throws Exception {
        short id = 0x1234;
        PublicKey pubKey = AsymmetricKeyTestHelper.importRsaKey(session, id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.SIGN_PKCS),
                                                                keyAlgorithm, keysize, componentLength);
        try {
            AsymmetricKeyRsa key = new AsymmetricKeyRsa(id, keyAlgorithm);

            byte[] data = new byte[0];
            signPkcs1(pubKey, key, Algorithm.RSA_PKCS1_SHA1, "SHA1withRSA", data);
            signPkcs1(pubKey, key, Algorithm.RSA_PKCS1_SHA256, "SHA256withRSA", data);
            signPkcs1(pubKey, key, Algorithm.RSA_PKCS1_SHA384, "SHA384withRSA", data);
            signPkcs1(pubKey, key, Algorithm.RSA_PKCS1_SHA512, "SHA512withRSA", data);

            data = "This is a signing test data".getBytes();
            signPkcs1(pubKey, key, Algorithm.RSA_PKCS1_SHA1, "SHA1withRSA", data);
            signPkcs1(pubKey, key, Algorithm.RSA_PKCS1_SHA256, "SHA256withRSA", data);
            signPkcs1(pubKey, key, Algorithm.RSA_PKCS1_SHA384, "SHA384withRSA", data);
            signPkcs1(pubKey, key, Algorithm.RSA_PKCS1_SHA512, "SHA512withRSA", data);

            data = new byte[2048];
            new Random().nextBytes(data);
            signPkcs1(pubKey, key, Algorithm.RSA_PKCS1_SHA1, "SHA1withRSA", data);
            signPkcs1(pubKey, key, Algorithm.RSA_PKCS1_SHA256, "SHA256withRSA", data);
            signPkcs1(pubKey, key, Algorithm.RSA_PKCS1_SHA384, "SHA384withRSA", data);
            signPkcs1(pubKey, key, Algorithm.RSA_PKCS1_SHA512, "SHA512withRSA", data);
        } finally {
            YHObject.deleteObject(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
        }
    }

    private void signPkcs1(PublicKey pubKey, AsymmetricKeyRsa key, Algorithm hashAlgorithm, String signatureAlgorithm, byte[] data) throws Exception {
        log.info("Test signing " + data.length + " bytes with RSA key of algorithm " + key.getKeyAlgorithm().getName() + " using RSA-PKCS#1v1.5");
        byte[] signature = key.signPkcs1(session, data, hashAlgorithm);

        Signature sig = Signature.getInstance(signatureAlgorithm);
        sig.initVerify(pubKey);
        sig.update(data);
        assertTrue(sig.verify(signature));
    }

    private void signPssTest(Algorithm keyAlgorithm, int keysize, int componentLength) throws Exception {
        short id = 0x1234;
        PublicKey pubKey = AsymmetricKeyTestHelper.importRsaKey(session, id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.SIGN_PSS),
                                                                keyAlgorithm, keysize, componentLength);

        try {
            AsymmetricKeyRsa key = new AsymmetricKeyRsa(id, keyAlgorithm);

            byte[] data = new byte[0];
            signPss(pubKey, key, Algorithm.RSA_MGF1_SHA1, "SHA1withRSA/PSS", "SHA-1", (short) 32, data);
            signPss(pubKey, key, Algorithm.RSA_MGF1_SHA256, "SHA256withRSA/PSS", "SHA-256", (short) 32, data);
            signPss(pubKey, key, Algorithm.RSA_MGF1_SHA384, "SHA384withRSA/PSS", "SHA-384", (short) 32, data);
            signPss(pubKey, key, Algorithm.RSA_MGF1_SHA512, "SHA512withRSA/PSS", "SHA-512", (short) 32, data);

            data = "This is a signing test data".getBytes();
            signPss(pubKey, key, Algorithm.RSA_MGF1_SHA1, "SHA1withRSA/PSS", "SHA-1", (short) 32, data);
            signPss(pubKey, key, Algorithm.RSA_MGF1_SHA256, "SHA256withRSA/PSS", "SHA-256", (short) 32, data);
            signPss(pubKey, key, Algorithm.RSA_MGF1_SHA384, "SHA384withRSA/PSS", "SHA-384", (short) 32, data);
            signPss(pubKey, key, Algorithm.RSA_MGF1_SHA512, "SHA512withRSA/PSS", "SHA-512", (short) 32, data);

            data = new byte[2048];
            new Random().nextBytes(data);
            signPss(pubKey, key, Algorithm.RSA_MGF1_SHA1, "SHA1withRSA/PSS", "SHA-1", (short) 32, data);
            signPss(pubKey, key, Algorithm.RSA_MGF1_SHA256, "SHA256withRSA/PSS", "SHA-256", (short) 32, data);
            signPss(pubKey, key, Algorithm.RSA_MGF1_SHA384, "SHA384withRSA/PSS", "SHA-384", (short) 32, data);
            signPss(pubKey, key, Algorithm.RSA_MGF1_SHA512, "SHA512withRSA/PSS", "SHA-512", (short) 32, data);
        } finally {
            YHObject.deleteObject(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
        }
    }

    private void signPss(PublicKey pubKey, AsymmetricKeyRsa key, Algorithm signAlgorithm, String signAlgorithmStr, String hashAlgorithm,
                         short saltLength, byte[] data) throws Exception {
        log.info("Test signing " + data.length + " bytes with RSA key of algorithm " + key.getKeyAlgorithm().getName() + " using RSA-PSS");
        byte[] signature = key.signPss(session, signAlgorithm, saltLength, data);

        Security.addProvider(new BouncyCastleProvider());
        Signature sig = Signature.getInstance(signAlgorithmStr, "BC");
        MGF1ParameterSpec mgf1Param = new MGF1ParameterSpec(hashAlgorithm);
        PSSParameterSpec pssParam = new PSSParameterSpec(hashAlgorithm, "MGF1", mgf1Param, saltLength, 1);
        sig.setParameter(pssParam);
        sig.initVerify(pubKey);
        sig.update(data);
        assertTrue(sig.verify(signature));
    }

}
