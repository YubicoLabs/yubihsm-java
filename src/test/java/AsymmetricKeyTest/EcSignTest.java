package AsymmetricKeyTest;

import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.exceptions.YHDeviceException;
import com.yubico.hsm.yhconcepts.Algorithm;
import com.yubico.hsm.yhconcepts.Capability;
import com.yubico.hsm.yhconcepts.Type;
import com.yubico.hsm.yhconcepts.YHError;
import com.yubico.hsm.yhobjects.AsymmetricKeyEc;
import com.yubico.hsm.yhobjects.YHObject;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.util.Arrays;
import java.util.Random;
import java.util.logging.Logger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class EcSignTest {
    Logger log = Logger.getLogger(EcSignTest.class.getName());

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
        final short id = 0x1234;
        KeyPair keypair = AsymmetricKeyTestHelper.importEcKey(session, id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.DERIVE_ECDH),
                                                              Algorithm.EC_P224, "secp224r1", 28);
        try {
            final AsymmetricKeyEc key = new AsymmetricKeyEc(id, Algorithm.EC_P224);

            boolean exceptionThrown = false;
            try {
                signEcdsa(keypair.getPublic(), key, Algorithm.EC_ECDSA_SHA256, "SHA256withECDSA", new byte[0]);
            } catch (YHDeviceException e) {
                exceptionThrown = true;
                assertEquals("Device returned incorrect error", YHError.INSUFFICIENT_PERMISSIONS, e.getYhError());
            }
            assertTrue("Succeeded to sign in spite of insufficient permissions", exceptionThrown);

        } finally {
            YHObject.delete(session, id, Type.TYPE_ASYMMETRIC_KEY);
        }
        log.info("TEST END: testSignDataWithInsufficientPermissions()");
    }

    @Test
    public void testSignData() throws Exception {
        log.info("TEST START: testSignData()");

        signEcdsaTest(Algorithm.EC_P224, "secp224r1", 28);
        signEcdsaTest(Algorithm.EC_P256, "secp256r1", 32);
        signEcdsaTest(Algorithm.EC_P384, "secp384r1", 48);
        signEcdsaTest(Algorithm.EC_P521, "secp521r1", 66);
        signEcdsaTest(Algorithm.EC_K256, "secp256k1", 32);

        signEcdsaBrainpoolTest(Algorithm.EC_BP256, "brainpoolP256r1", 32);
        signEcdsaBrainpoolTest(Algorithm.EC_BP384, "brainpoolP384r1", 48);
        signEcdsaBrainpoolTest(Algorithm.EC_BP512, "brainpoolP512r1", 64);

        log.info("TEST END: testSignData()");
    }


    private void signEcdsaTest(Algorithm keyAlgorithm, String curve, int componentLength) throws Exception {
        final short id = 0x1234;
        KeyPair keypair = AsymmetricKeyTestHelper.importEcKey(session, id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.SIGN_ECDSA),
                                                              keyAlgorithm, curve, componentLength);
        PublicKey publicKey = keypair.getPublic();
        try {
            final AsymmetricKeyEc key = new AsymmetricKeyEc(id, keyAlgorithm);

            byte[] data = new byte[0];
            signEcdsa(publicKey, key, Algorithm.EC_ECDSA_SHA1, "SHA1withECDSA", data);
            signEcdsa(publicKey, key, Algorithm.EC_ECDSA_SHA256, "SHA256withECDSA", data);
            signEcdsa(publicKey, key, Algorithm.EC_ECDSA_SHA384, "SHA384withECDSA", data);
            signEcdsa(publicKey, key, Algorithm.EC_ECDSA_SHA512, "SHA512withECDSA", data);

            data = "This is a signing test data".getBytes();
            signEcdsa(publicKey, key, Algorithm.EC_ECDSA_SHA1, "SHA1withECDSA", data);
            signEcdsa(publicKey, key, Algorithm.EC_ECDSA_SHA256, "SHA256withECDSA", data);
            signEcdsa(publicKey, key, Algorithm.EC_ECDSA_SHA384, "SHA384withECDSA", data);
            signEcdsa(publicKey, key, Algorithm.EC_ECDSA_SHA512, "SHA512withECDSA", data);

            data = new byte[2048];
            new Random().nextBytes(data);
            signEcdsa(publicKey, key, Algorithm.EC_ECDSA_SHA1, "SHA1withECDSA", data);
            signEcdsa(publicKey, key, Algorithm.EC_ECDSA_SHA256, "SHA256withECDSA", data);
            signEcdsa(publicKey, key, Algorithm.EC_ECDSA_SHA384, "SHA384withECDSA", data);
            signEcdsa(publicKey, key, Algorithm.EC_ECDSA_SHA512, "SHA512withECDSA", data);

        } finally {
            YHObject.delete(session, id, Type.TYPE_ASYMMETRIC_KEY);
        }
    }

    private void signEcdsa(PublicKey pubKey, AsymmetricKeyEc key, Algorithm signAlgorithm, String signAlgorithmStr, byte[] data) throws Exception {
        log.info("Test performing ECDSA signing on data of length " + data.length + " with EC key of algorithm " + key.getKeyAlgorithm().getName() +
                 " using algorithm " + signAlgorithm.getName());

        byte[] signature = key.signEcdsa(session, data, signAlgorithm);

        Signature sig = Signature.getInstance(signAlgorithmStr);
        sig.initVerify(pubKey);
        sig.update(data);
        assertTrue(sig.verify(signature));
    }

    private void signEcdsaBrainpoolTest(Algorithm keyAlgorithm, String curve, int componentLength) throws Exception {
        final short id = 0x1234;
        KeyPair keyPair =
                AsymmetricKeyTestHelper.importEcBrainpoolKey(session, id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.SIGN_ECDSA),
                                                             keyAlgorithm, curve, componentLength);
        PublicKey publicKey = keyPair.getPublic();
        try {
            final AsymmetricKeyEc key = new AsymmetricKeyEc(id, keyAlgorithm);

            signEcdsaBrainpool(publicKey, key, Algorithm.EC_ECDSA_SHA1, "SHA1withECDSA");
            signEcdsaBrainpool(publicKey, key, Algorithm.EC_ECDSA_SHA256, "SHA256withECDSA");
            signEcdsaBrainpool(publicKey, key, Algorithm.EC_ECDSA_SHA384, "SHA384withECDSA");
            signEcdsaBrainpool(publicKey, key, Algorithm.EC_ECDSA_SHA512, "SHA512withECDSA");

        } finally {
            YHObject.delete(session, id, Type.TYPE_ASYMMETRIC_KEY);
        }
    }

    private void signEcdsaBrainpool(PublicKey pubKey, AsymmetricKeyEc key, Algorithm signAlgorithm, String signAlgorithmStr) throws Exception {
        log.info("Test performing ECDSA signing with EC key of algorithm " + key.getKeyAlgorithm().getName() + " using algorithm " +
                 signAlgorithm.getName());
        final byte[] data = "This is a signing test data".getBytes();
        final byte[] signature = key.signEcdsa(session, data, signAlgorithm);

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Signature sig = Signature.getInstance(signAlgorithmStr, "BC");
        sig.initVerify(pubKey);
        sig.update(data);
        assertTrue(sig.verify(signature));
    }
}
