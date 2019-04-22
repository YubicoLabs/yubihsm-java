package AsymmetricKeyTest;

import com.yubico.YHSession;
import com.yubico.YubiHsm;
import com.yubico.backend.Backend;
import com.yubico.backend.HttpBackend;
import com.yubico.exceptions.*;
import com.yubico.objects.yhconcepts.Algorithm;
import com.yubico.objects.yhconcepts.Capability;
import com.yubico.objects.yhconcepts.ObjectType;
import com.yubico.objects.yhobjects.AsymmetricKeyEc;
import com.yubico.objects.yhobjects.YHObject;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.net.MalformedURLException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.logging.Logger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class EcSignTest {
    Logger logger = Logger.getLogger(EcSignTest.class.getName());

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
    public void testSignDataWithInsufficientPermissions()
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, SignatureException, UnsupportedAlgorithmException {
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
                assertEquals("Device returned incorrect error", YHError.INSUFFICIENT_PERMISSIONS, e.getErrorCode());
            }
            assertTrue("Succeeded to sign in spite of insufficient permissions", exceptionThrown);

        } finally {
            YHObject.deleteObject(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
        }
    }

    @Test
    public void testSignData()
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, SignatureException, NoSuchProviderException, UnsupportedAlgorithmException {
        logger.info("TEST START: testSignData()");

        signEcdsaTest(Algorithm.EC_P224, "secp224r1", 28);
        signEcdsaTest(Algorithm.EC_P256, "secp256r1", 32);
        signEcdsaTest(Algorithm.EC_P384, "secp384r1", 48);
        signEcdsaTest(Algorithm.EC_P521, "secp521r1", 66);
        signEcdsaTest(Algorithm.EC_K256, "secp256k1", 32);

        signEcdsaBrainpoolTest(Algorithm.EC_BP256, "brainpoolP256r1", 32);
        signEcdsaBrainpoolTest(Algorithm.EC_BP384, "brainpoolP384r1", 48);
        signEcdsaBrainpoolTest(Algorithm.EC_BP512, "brainpoolP512r1", 64);

        logger.info("TEST END: testSignData()");
    }


    private void signEcdsaTest(Algorithm keyAlgorithm, String curve, int componentLength)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, SignatureException, UnsupportedAlgorithmException {
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

        } finally {
            YHObject.deleteObject(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
        }
    }

    private void signEcdsa(PublicKey pubKey, AsymmetricKeyEc key, Algorithm signAlgorithm, String signAlgorithmStr, byte[] data)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, SignatureException {

        byte[] signature = key.signEcdsa(session, data, signAlgorithm);

        Signature sig = Signature.getInstance(signAlgorithmStr);
        sig.initVerify(pubKey);
        sig.update(data);
        assertTrue(sig.verify(signature));
    }

    private void signEcdsaBrainpoolTest(Algorithm keyAlgorithm, String curve, int componentLength)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, SignatureException, NoSuchProviderException, UnsupportedAlgorithmException {
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
            YHObject.deleteObject(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
        }
    }

    private void signEcdsaBrainpool(PublicKey pubKey, AsymmetricKeyEc key, Algorithm signAlgorithm, String signAlgorithmStr)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, SignatureException, NoSuchProviderException {
        final byte[] data = "This is a signing test data".getBytes();
        final byte[] signature = key.signEcdsa(session, data, signAlgorithm);

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Signature sig = Signature.getInstance(signAlgorithmStr, "BC");
        sig.initVerify(pubKey);
        sig.update(data);
        assertTrue(sig.verify(signature));
    }
}
