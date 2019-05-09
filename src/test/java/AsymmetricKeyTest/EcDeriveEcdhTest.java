package AsymmetricKeyTest;

import com.yubico.YHSession;
import com.yubico.YubiHsm;
import com.yubico.backend.Backend;
import com.yubico.backend.HttpBackend;
import com.yubico.internal.util.Utils;
import com.yubico.objects.yhconcepts.Algorithm;
import com.yubico.objects.yhconcepts.Capability;
import com.yubico.objects.yhobjects.AsymmetricKey;
import com.yubico.objects.yhobjects.AsymmetricKeyEc;
import com.yubico.objects.yhobjects.YHObject;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.KeyAgreement;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.util.Arrays;
import java.util.logging.Logger;

import static org.junit.Assert.assertArrayEquals;

public class EcDeriveEcdhTest {
    Logger log = Logger.getLogger(EcDeriveEcdhTest.class.getName());

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
    public void testDeriveEcdh() throws Exception {
        log.info("TEST START: testDeriveEcdh()");
        deriveEcdh(Algorithm.EC_P224, "secp224r1", 28, false);
        deriveEcdh(Algorithm.EC_P256, "secp256r1", 32, false);
        deriveEcdh(Algorithm.EC_P384, "secp384r1", 48, false);
        deriveEcdh(Algorithm.EC_P521, "secp521r1", 66, false);
        deriveEcdh(Algorithm.EC_K256, "secp256k1", 32, false);
        deriveEcdh(Algorithm.EC_BP256, "brainpoolP256r1", 32, true);
        deriveEcdh(Algorithm.EC_BP384, "brainpoolP384r1", 48, true);
        deriveEcdh(Algorithm.EC_BP512, "brainpoolP512r1", 64, true);
        log.info("TEST END: testDeriveEcdh()");
    }

    private void deriveEcdh(Algorithm algorithm, String curve, int componentLength, boolean brainpool) throws Exception {
        KeyPair keypair1 = generateEcKeyPair(curve, brainpool);
        KeyPair keypair2 = generateEcKeyPair(curve, brainpool);

        ECPrivateKey privkey = (ECPrivateKey) keypair1.getPrivate();
        short keyid = AsymmetricKeyEc.importKey(session, (short) 0, "", Arrays.asList(1), algorithm, Arrays.asList(Capability.DERIVE_ECDH),
                                                Utils.getUnsignedByteArrayFromBigInteger(privkey.getS(), componentLength));
        try {
            byte[] secretKey = getVerificationSecretKey(keypair1.getPrivate(), keypair2.getPublic(), brainpool);

            AsymmetricKeyEc key = new AsymmetricKeyEc(keyid, algorithm);
            byte[] ecdh = key.deriveEcdh(session, getUncompressedEcPublicKey(keypair2.getPublic(), componentLength));
            assertArrayEquals(secretKey, ecdh);

            ecdh = key.deriveEcdh(session, (ECPublicKey) keypair2.getPublic());
            assertArrayEquals(secretKey, ecdh);
        } finally {
            YHObject.delete(session, keyid, AsymmetricKey.TYPE);
        }
    }

    private byte[] getVerificationSecretKey(PrivateKey privkey, PublicKey pubkey, boolean brainpool) throws Exception {
        KeyAgreement keyAgreement;
        if (brainpool) {
            keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
        } else {
            keyAgreement = KeyAgreement.getInstance("ECDH");
        }
        keyAgreement.init(privkey);
        keyAgreement.doPhase(pubkey, true);
        return keyAgreement.generateSecret();
    }

    private KeyPair generateEcKeyPair(String curve, boolean brainpool) throws Exception {
        KeyPairGenerator generator;
        if (brainpool) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            generator = KeyPairGenerator.getInstance("EC", "BC");
        } else {
            generator = KeyPairGenerator.getInstance("EC");
        }
        generator.initialize(new ECGenParameterSpec(curve));
        return generator.generateKeyPair();
    }

    private byte[] getUncompressedEcPublicKey(PublicKey publicKey, int length) {
        ECPublicKey pubkey = (ECPublicKey) publicKey;
        ECPoint point = pubkey.getW();
        byte[] x = Utils.getUnsignedByteArrayFromBigInteger(point.getAffineX(), length);
        byte[] y = Utils.getUnsignedByteArrayFromBigInteger(point.getAffineY(), length);
        ByteBuffer bb = ByteBuffer.allocate(1 + x.length + y.length);
        bb.put((byte) 0x04).put(x).put(y);
        return bb.array();
    }
}
