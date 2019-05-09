package AsymmetricKeyTest;

import com.yubico.YHSession;
import com.yubico.YubiHsm;
import com.yubico.backend.Backend;
import com.yubico.backend.HttpBackend;
import com.yubico.objects.yhconcepts.Algorithm;
import com.yubico.objects.yhconcepts.Capability;
import com.yubico.objects.yhconcepts.ObjectType;
import com.yubico.objects.yhobjects.AsymmetricKeyEc;
import com.yubico.objects.yhobjects.YHObject;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.logging.Logger;

import static org.junit.Assert.assertEquals;

public class EcPublicKeyTest {
    Logger log = Logger.getLogger(EcPublicKeyTest.class.getName());

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
    public void testPublicKey() throws Exception {
        log.info("TEST START: testPublicKey()");
        getEcPublicKeyTest(Algorithm.EC_P224, "secp224r1", 28, false);
        getEcPublicKeyTest(Algorithm.EC_P256, "secp256r1", 32, false);
        getEcPublicKeyTest(Algorithm.EC_P384, "secp384r1", 48, false);
        getEcPublicKeyTest(Algorithm.EC_P521, "secp521r1", 66, false);
        getEcPublicKeyTest(Algorithm.EC_K256, "secp256k1", 32, false);
        getEcPublicKeyTest(Algorithm.EC_BP256, "brainpoolP256r1", 32, true);
        getEcPublicKeyTest(Algorithm.EC_BP384, "brainpoolP384r1", 48, true);
        getEcPublicKeyTest(Algorithm.EC_BP512, "brainpoolP512r1", 64, true);
        log.info("TEST END: testPublicKey()");
    }


    private void getEcPublicKeyTest(Algorithm algorithm, String curve, int componentLength, boolean brainpool) throws Exception {
        log.info("Test retrieving the public key of an EC key with algorithm " + algorithm.getName());
        final short id = 0x1234;
        KeyPair keypair;
        if (brainpool) {
            keypair = AsymmetricKeyTestHelper.importEcBrainpoolKey(session, id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.SIGN_ECDSA),
                                                                   algorithm, curve, componentLength);
        } else {
            keypair = AsymmetricKeyTestHelper.importEcKey(session, id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.SIGN_ECDSA), algorithm,
                                                          curve, componentLength);
        }

        try {
            final AsymmetricKeyEc key = new AsymmetricKeyEc(id, algorithm);
            PublicKey returnedPubKey = key.getEcPublicKey(session);
            assertEquals(keypair.getPublic(), returnedPubKey);
        } finally {
            YHObject.delete(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
        }
    }
}
